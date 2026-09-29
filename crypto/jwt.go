package crypto

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
)

type internalJWT struct {
	signer types.Signer
	cfg    types.JWTConfig
}

func (j *internalJWT) sign(subject string, custom behemoth.M) (string, error) {
	now := time.Now()

	claims := types.Claims{
		Issuer:    j.cfg.Issuer,
		Audience:  j.cfg.Audience[types.JWTInternal],
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: now.Add(j.cfg.TTL[types.JWTInternal]),
		Custom:    custom,
	}

	claimsB64, _, err := marshalB64(claims)
	if err != nil {
		return "", newJWTError("JWT.Sign", "claims_marshal_err", err)
	}

	// Fetch the signing key once for this entire operation;
	// see SigningKey doc for why two separate Sign() calls here would be racy against a
	// hot key rotation landing between them.
	signingKey, err := j.signer.PrepareSigning()
	if err != nil {
		return "", err
	}

	headerB64, _, err := marshalB64(jwtHeader{Alg: "HS256", Typ: "JWT", Kid: strconv.Itoa(signingKey.Version())})
	if err != nil {
		return "", newJWTError("JWT.Sign", "header_marshal_failed", err)
	}

	signingInput := headerB64 + "." + claimsB64
	signed := signingKey.Sign([]byte(signingInput))
	return signingInput + "." + b64(signed), nil
}

func (j *internalJWT) verify(token string) (*types.Claims, error) {
	const op = "JWT.Verify.Internal"

	parts := splitJWT(token)
	if parts == nil {
		return nil, newJWTError(op, "malformed_token", nil)
	}

	headerB, err := b64Decode(parts.header)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	var h jwtHeader
	if err := json.Unmarshal(headerB, &h); err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	// Algorithm pinning, made structural
	// this is the only algorithm internalJWT ever attempts.
	if h.Alg != "HS256" {
		return nil, newJWTError(op, "algorithm_mismatch", nil)
	}
	keyVersion, err := strconv.Atoi(h.Kid)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	sigBytes, err := b64Decode(parts.signature)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	signingInput := parts.header + "." + parts.claims
	ok, err := j.signer.(*HMACSigner).Verify([]byte(signingInput), sigBytes, keyVersion)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, newJWTError(op, "invalid_signature", nil)
	}

	claimsB, err := b64Decode(parts.claims)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}
	var claims types.Claims
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	if err := validateRegisteredClaims(op, &claims, j.cfg.Issuer, j.cfg.Audience[types.JWTInternal]); err != nil {
		return nil, err
	}
	return &claims, nil

}

func validateRegisteredClaims(op string, c *types.Claims, expectedIssuer, expectedAudience string) error {
	now := time.Now()
	switch {
	case now.After(c.ExpiresAt):
		return newJWTError(op, "token_expired", nil)
	case !c.NotBefore.IsZero() && now.Before(c.NotBefore):
		return newJWTError(op, "token_not_yet_valid", nil)
	case expectedIssuer != "" && c.Issuer != expectedIssuer:
		return newJWTError(op, "issuer_mismatch", nil)
	case expectedAudience != "" && c.Audience != expectedAudience:
		return newJWTError(op, "audience_mismatch", nil)
	default:
		return nil
	}

}

type externalJWT struct {
	store types.JWKSStore
	enc   types.Encryptor
	cfg   types.JWTConfig
}

func (j *externalJWT) sign(ctx context.Context, subject string, custom behemoth.M) (string, error) {
	const op = "JWT.Sign.External"
	kp, err := j.store.Current(ctx)
	if err != nil {
		return "", err
	}
	privBytes, err := j.enc.Decrypt(kp.EncryptedPrivateKey, kp.PrivateKeyVersion)
	if err != nil {
		return "", err
	}
	priv := ed25519.PrivateKey(privBytes)
	now := time.Now()
	claims := types.Claims{
		Issuer:   j.cfg.Issuer,
		Audience: j.cfg.Audience[types.JWTExternal],
		Subject:  subject, IssuedAt: now,
		ExpiresAt: now.Add(j.cfg.TTL[types.JWTExternal]),
		Custom:    custom,
	}
	headerB64, _, err := marshalB64(jwtHeader{Alg: "EdDSA", Typ: "JWT", Kid: kp.ID})
	if err != nil {
		return "", newJWTError(op, "header_marshal_failed", err)
	}
	claimsB64, _, err := marshalB64(claims)
	if err != nil {
		return "", newJWTError(op, "claims_marshal_failed", err)
	}

	signingInput := headerB64 + "." + claimsB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64(sig), nil
}

func (j *externalJWT) verify(ctx context.Context, token string) (*types.Claims, error) {
	const op = "JWT.Verify.External"

	parts := splitJWT(token)
	if parts == nil {
		return nil, newJWTError(op, "malformed_token", nil)
	}
	headerB, err := b64Decode(parts.header)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(headerB, &h); err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}
	if h.Alg != "EdDSA" { // pinned — externalJWT structurally never attempts any other algorithm
		return nil, newJWTError(op, "algorithm_mismatch", nil)
	}

	kp, err := j.store.ByKid(ctx, h.Kid) // works for the current key AND a recently-rotated-out one still verifying old tokens
	if err != nil {
		return nil, err
	}

	sigBytes, err := b64Decode(parts.signature)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}
	signingInput := []byte(parts.header + "." + parts.claims)
	if !ed25519.Verify(kp.PublicKey, signingInput, sigBytes) {
		return nil, newJWTError(op, "invalid_signature", nil)
	}
	claimsB, err := b64Decode(parts.claims)
	if err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}
	var claims types.Claims
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		return nil, newJWTError(op, "malformed_token", err)
	}

	if err := validateRegisteredClaims(op, &claims, j.cfg.Issuer, j.cfg.Audience[types.JWTExternal]); err != nil {
		return nil, err
	}
	return &claims, nil
}

type JWTProviderImpl struct {
	internal *internalJWT
	external *externalJWT // not required
	cfg      types.JWTConfig
}

func NewJWTProvider(signer types.Signer, store types.JWKSStore, enc types.Encryptor, cfg types.JWTConfig) *JWTProviderImpl {
	if cfg.JWKSPath == "" {
		cfg.JWKSPath = "/.well-known/jwks.json"
	}
	p := &JWTProviderImpl{internal: &internalJWT{signer: signer, cfg: cfg}, cfg: cfg}
	if store != nil {
		p.external = &externalJWT{store: store, enc: enc, cfg: cfg}
	}
	return p
}

func (p *JWTProviderImpl) Sign(ctx context.Context, kind types.JWTKind, subject string, custom behemoth.M) (string, error) {
	switch kind {
	case types.JWTInternal:
		return p.internal.sign(subject, custom)
	case types.JWTExternal:
		if p.external == nil {
			return "", newJWTError("JWT.Sign", "external_jwt_not_configured", nil)
		}
		return p.external.sign(ctx, subject, custom)
	default:
		return "", newJWTError("JWT.Sign", "unknown_jwt_kind", nil)
	}
}

func (p *JWTProviderImpl) Verify(ctx context.Context, kind types.JWTKind, token string) (*types.Claims, error) {
	switch kind {
	case types.JWTInternal:
		return p.internal.verify(token)
	case types.JWTExternal:
		if p.external == nil {
			return nil, newJWTError("JWT.Verify", "external_jwt_not_configured", nil)
		}
		return p.external.verify(ctx, token)
	default:
		return nil, newJWTError("JWT.Verify", "unknown_jwt_kind", nil)
	}
}

func (p *JWTProviderImpl) HandleJWKS(rctx *types.RequestContext) error {
	pairs, err := p.external.store.All(rctx.Ctx)
	if err != nil {
		return err
	}

	keys := make([]jwkJSON, 0, len(pairs))
	for _, kp := range pairs {
		keys = append(keys, jwkJSON{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   b64(kp.PublicKey),
			Use: "sig",
			Kid: kp.ID,
			Alg: "EdDSA",
		})
	}

	return rctx.Response.JSON(http.StatusOK, behemoth.M{"keys": keys})
}

// Routes exposes the JWKS endpoint as a Route. Returns nil when external
// JWT isn't configured
func (p *JWTProviderImpl) Routes() []types.Route {
	if p.external == nil {
		return nil
	}
	return []types.Route{
		{Method: http.MethodGet, Path: p.cfg.JWKSPath, Handler: p.HandleJWKS},
	}
}
