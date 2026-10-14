package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/golang-jwt/jwt/v5"
)

// Tokens are encoded, parsed and their registered claims checked with
// golang-jwt, so that they are standard JWTs (RFC 7519): NumericDate dates,
// and an audience that may be a string or an array. The algorithm is never
// the token's choice: an internal token is HS256, and an external one is
// signed with the algorithm of the key its kid names. A token whose header
// names another is refused before its signature is looked at.

// externalAlgs are the algorithms an external key may sign with:
// asymmetric ones only, so that a public key is never used as an HMAC
// secret. The derived keys are EdDSA. The others are for a key set held by a
// KMS (ADR-0002).
var externalAlgs = []string{"EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// wireClaims is a token's payload as it is parsed and checked.
type wireClaims struct {
	jwt.RegisteredClaims
	SessionID string     `json:"sid,omitempty"`
	Custom    behemoth.M `json:"custom,omitempty"`
}

// payload returns the claims of a new token as they are signed. A map, and
// not wireClaims, because golang-jwt writes a single audience as an array
// unless a package-wide setting says otherwise.
func payload(op string, kind types.JWTKind, cfg types.JWTConfig, req types.JWTRequest) (jwt.MapClaims, error) {
	if req.Subject == "" {
		return nil, behemotherr.NewInvalidInputError(op, "subject", "a token needs a subject", nil)
	}
	audience := req.Audience
	allowed := cfg.Audiences[kind]
	switch {
	case audience == "" && len(allowed) > 0:
		audience = allowed[0]
	case audience != "" && !slices.Contains(allowed, audience):
		return nil, behemotherr.NewInvalidInputError(op, "audience", "audience is not allowed", nil)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": cfg.Issuer,
		"sub": req.Subject,
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(cfg.TTL[kind])),
		"jti": rand.Text(),
	}
	if audience != "" {
		claims["aud"] = audience
	}
	if req.SessionID != "" {
		claims["sid"] = req.SessionID
	}
	if len(req.Custom) > 0 {
		claims["custom"] = req.Custom
	}
	return claims, nil
}

// parsed is a token read without its signature checked yet.
type parsed struct {
	alg           string
	kid           string
	signingString string
	signature     []byte
	claims        *wireClaims
}

// parse reads token without verifying anything.
func parse(op, token string) (*parsed, error) {
	p := jwt.NewParser()
	claims := &wireClaims{}
	tok, parts, err := p.ParseUnverified(token, claims)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTAlgorithmMismatch, err) // an algorithm golang-jwt does not know
		}
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTMalformed, err)
	}
	signature, err := p.DecodeSegment(parts[2])
	if err != nil {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTMalformed, err)
	}
	alg, _ := tok.Header["alg"].(string)
	kid, _ := tok.Header["kid"].(string)
	return &parsed{alg: alg, kid: kid, signingString: parts[0] + "." + parts[1], signature: signature, claims: claims}, nil
}

// signWith encodes claims with a header naming alg and kid, and signs it
// with sign.
func signWith(op, alg, kid string, claims jwt.MapClaims, sign func([]byte) ([]byte, error)) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", behemotherr.NewSecurityError(op, behemotherr.ErrorCodeJWTSigningFailed, fmt.Errorf("unknown algorithm %q", alg))
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	signingString, err := token.SigningString()
	if err != nil {
		return "", behemotherr.NewSecurityError(op, behemotherr.ErrorCodeJWTEncodingFailed, err)
	}
	signature, err := sign([]byte(signingString))
	if err != nil {
		return "", behemotherr.NewSecurityError(op, behemotherr.ErrorCodeJWTSigningFailed, err)
	}
	return signingString + "." + b64(signature), nil
}

// validate checks the registered claims of a token whose signature is
// valid, and returns them as types.Claims.
func validate(op string, c *wireClaims, issuer string, audiences []string) (*types.Claims, error) {
	opts := []jwt.ParserOption{jwt.WithExpirationRequired()}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if len(audiences) > 0 {
		opts = append(opts, jwt.WithAudience(audiences...))
	}
	if err := jwt.NewValidator(opts...).Validate(c); err != nil {
		code := behemotherr.ErrorCodeJWTInvalidClaims
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			code = behemotherr.ErrorCodeTokenExpired
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			code = behemotherr.ErrorCodeJWTNotYetValid
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			code = behemotherr.ErrorCodeJWTIssuerMismatch
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			code = behemotherr.ErrorCodeJWTAudienceMismatch
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			code = behemotherr.ErrorCodeJWTMissingClaim
		}
		return nil, behemotherr.NewJWTError(op, code, err)
	}

	out := &types.Claims{Issuer: c.Issuer, Subject: c.Subject, SessionID: c.SessionID, ID: c.ID, Custom: c.Custom}
	// Claims holds one audience: the first configured one the token names.
	if len(c.Audience) > 0 {
		out.Audience = c.Audience[0]
		for _, a := range audiences {
			if slices.Contains(c.Audience, a) {
				out.Audience = a
				break
			}
		}
	}
	for _, d := range []struct {
		from *jwt.NumericDate
		into *time.Time
	}{{c.ExpiresAt, &out.ExpiresAt}, {c.IssuedAt, &out.IssuedAt}, {c.NotBefore, &out.NotBefore}} {
		if d.from != nil {
			*d.into = d.from.Time
		}
	}
	return out, nil
}

// internalJWT is an HS256 token signed with the key manager's key of
// purpose jwt_sign. Its kid is the key's version, so a token signed before
// a rotation still verifies.
type internalJWT struct {
	signer types.Signer
	cfg    types.JWTConfig
}

func (j *internalJWT) sign(req types.JWTRequest) (string, error) {
	const op = "JWT.Sign.Internal"
	claims, err := payload(op, types.JWTInternal, j.cfg, req)
	if err != nil {
		return "", err
	}
	// One snapshot of the key for the whole token: the kid and the
	// signature have to name the same version, and a rotation can land
	// between two calls to the signer.
	signingKey, err := j.signer.PrepareSigning()
	if err != nil {
		return "", err
	}
	return signWith(op, jwt.SigningMethodHS256.Alg(), strconv.Itoa(signingKey.Version()), claims,
		func(b []byte) ([]byte, error) { return signingKey.Sign(b), nil })
}

func (j *internalJWT) verify(token string) (*types.Claims, error) {
	const op = "JWT.Verify.Internal"
	p, err := parse(op, token)
	if err != nil {
		return nil, err
	}
	if p.alg != jwt.SigningMethodHS256.Alg() {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTAlgorithmMismatch, nil)
	}
	version, err := strconv.Atoi(p.kid)
	if err != nil {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTMalformed, err)
	}
	// The signer checks the HMAC in constant time, with the key of the
	// token's version.
	ok, err := j.signer.Verify([]byte(p.signingString), p.signature, version)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTInvalidSignature, nil)
	}
	return validate(op, p.claims, j.cfg.Issuer, j.cfg.Audiences[types.JWTInternal])
}

// externalJWT is signed with the current key of an ExternalKeySet, for
// other services to verify with the published keys. Its kid is the key's.
type externalJWT struct {
	keys types.ExternalKeySet
	cfg  types.JWTConfig
}

func (j *externalJWT) sign(ctx context.Context, req types.JWTRequest) (string, error) {
	const op = "JWT.Sign.External"
	claims, err := payload(op, types.JWTExternal, j.cfg, req)
	if err != nil {
		return "", err
	}
	key, err := j.keys.CurrentKey(ctx)
	if err != nil {
		return "", err
	}
	return signWith(op, key.Algorithm(), key.KID(), claims,
		func(b []byte) ([]byte, error) { return key.Sign(ctx, b) })
}

func (j *externalJWT) verify(ctx context.Context, token string) (*types.Claims, error) {
	const op = "JWT.Verify.External"
	p, err := parse(op, token)
	if err != nil {
		return nil, err
	}
	// An algorithm no external key may have is refused before the key set
	// is asked: none, and the HMAC ones.
	if !slices.Contains(externalAlgs, p.alg) {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTAlgorithmMismatch, nil)
	}
	// The current key and the ones rotated out, which still verify the
	// tokens they signed until those expire.
	key, err := j.keys.PublicKey(ctx, p.kid)
	if err != nil {
		return nil, err
	}
	if p.alg != key.Algorithm {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTAlgorithmMismatch, nil)
	}
	if err := jwt.GetSigningMethod(key.Algorithm).Verify(p.signingString, p.signature, key.Key); err != nil {
		return nil, behemotherr.NewJWTError(op, behemotherr.ErrorCodeJWTInvalidSignature, err)
	}
	return validate(op, p.claims, j.cfg.Issuer, j.cfg.Audiences[types.JWTExternal])
}

type JWTProviderImpl struct {
	internal *internalJWT
	external *externalJWT // not required
	cfg      types.JWTConfig
}

// NewJWTProvider returns the provider of both kinds of JWT. Internal tokens
// are signed by signer, external ones by keys. A nil keys leaves external
// tokens off: Sign and Verify of JWTExternal are then configuration errors,
// and Routes publishes nothing.
func NewJWTProvider(signer types.Signer, keys types.ExternalKeySet, cfg types.JWTConfig) *JWTProviderImpl {
	if cfg.JWKSPath == "" {
		cfg.JWKSPath = "/.well-known/jwks.json"
	}
	p := &JWTProviderImpl{internal: &internalJWT{signer: signer, cfg: cfg}, cfg: cfg}
	if keys != nil {
		p.external = &externalJWT{keys: keys, cfg: cfg}
	}
	return p
}

// Sign implements [types.JWTProvider]. A request without a subject, or for
// an audience the kind does not list, is a validation error.
func (p *JWTProviderImpl) Sign(ctx context.Context, kind types.JWTKind, req types.JWTRequest) (string, error) {
	switch kind {
	case types.JWTInternal:
		return p.internal.sign(req)
	case types.JWTExternal:
		if p.external == nil {
			return "", behemotherr.NewConfigurationErrorCode("JWT.Sign", behemotherr.ErrorCodeJWTExternalNotConfigured, "external JWTs need a key set")
		}
		return p.external.sign(ctx, req)
	default:
		return "", behemotherr.NewConfigurationErrorCode("JWT.Sign", behemotherr.ErrorCodeJWTUnknownKind, "unknown JWT kind")
	}
}

// Verify implements [types.JWTProvider]. A refused token is a CategoryToken
// error, with one of the codes of errors/jwt.go.
func (p *JWTProviderImpl) Verify(ctx context.Context, kind types.JWTKind, token string) (*types.Claims, error) {
	switch kind {
	case types.JWTInternal:
		return p.internal.verify(token)
	case types.JWTExternal:
		if p.external == nil {
			return nil, behemotherr.NewConfigurationErrorCode("JWT.Verify", behemotherr.ErrorCodeJWTExternalNotConfigured, "external JWTs need a key set")
		}
		return p.external.verify(ctx, token)
	default:
		return nil, behemotherr.NewConfigurationErrorCode("JWT.Verify", behemotherr.ErrorCodeJWTUnknownKind, "unknown JWT kind")
	}
}

// jwksMaxAge is how long a verifier may cache the key set. A key published
// for a new secret version is found within it.
const jwksMaxAge = 5 * time.Minute

// HandleJWKS answers with the published keys as a JWK set (RFC 7517), public
// halves only.
//
// Not built: EC and RSA keys, which a key set held by a KMS may have
// (ADR-0002). A key of another type than Ed25519 is an error.
func (p *JWTProviderImpl) HandleJWKS(rctx *types.RequestContext) error {
	published, err := p.external.keys.PublicKeys(rctx.Ctx)
	if err != nil {
		return err
	}
	keys := make([]jwkJSON, 0, len(published))
	for _, k := range published {
		pub, ok := k.Key.(ed25519.PublicKey)
		if !ok {
			return behemotherr.NewSecurityError("JWT.HandleJWKS", behemotherr.ErrorCodeJWKSReadFailed, fmt.Errorf("key %q: %T is not published", k.KID, k.Key))
		}
		keys = append(keys, jwkJSON{Kty: "OKP", Crv: "Ed25519", X: b64(pub), Use: "sig", Kid: k.KID, Alg: k.Algorithm})
	}
	rctx.Response.SetHeader("Cache-Control", fmt.Sprintf("public, max-age=%d", int(jwksMaxAge/time.Second)))
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
