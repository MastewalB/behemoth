package crypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/golang-jwt/jwt/v5"
)

// Tokens are encoded, parsed and their registered claims checked with
// golang-jwt, so that they are standard JWTs (RFC 7519): NumericDate dates,
// and an audience that may be a string or an array. The algorithm is never
// the token's choice: an internal token is HS256, and an external one is
// signed with the algorithm of the key its kid names. A token whose header
// names another is refused before its signature is looked at.

// asymmetricAlgs are the algorithms a key of a KeySet may sign with:
// asymmetric ones only, so that a public key is never used as an HMAC
// secret. They are the algorithms of the key types the JWK codec knows. The
// derived keys are EdDSA; the others are for a key set held by a KMS
// (ADR-0002) and for other issuers' keys (ADR-0003).
var asymmetricAlgs = []string{"EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// wireClaims is a token's payload as it is parsed and checked.
type wireClaims struct {
	jwt.RegisteredClaims
	SessionID string     `json:"sid,omitempty"`
	Custom    behemoth.M `json:"custom,omitempty"`
}

// payload returns the claims of a new token as they are signed. A map, and
// not wireClaims, because golang-jwt writes a single audience as an array
// unless a package-wide setting says otherwise.
func payload(op string, kind JWTKind, cfg JWTConfig, req JWTRequest) (jwt.MapClaims, error) {
	if req.Subject == "" {
		return nil, errs.NewInvalidInputError(op, "subject", "a token needs a subject", nil)
	}
	audience := req.Audience
	allowed := cfg.Audiences[kind]
	switch {
	case audience == "" && len(allowed) > 0:
		audience = allowed[0]
	case audience != "" && !slices.Contains(allowed, audience):
		return nil, errs.NewInvalidInputError(op, "audience", "audience is not allowed", nil)
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
	payload       []byte // the claims as they were signed, decoded from base64url
}

// parse reads token without verifying anything, and decodes its claims
// into claims. A header with "crit" is refused: no extension is understood
// here, and RFC 7515 section 4.1.11 then fails the token.
func parse(op, token string, claims jwt.Claims) (*parsed, error) {
	p := jwt.NewParser()
	tok, parts, err := p.ParseUnverified(token, claims)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			return nil, errs.NewJWTError(op, errs.CodeJWTAlgorithmMismatch, err) // an algorithm golang-jwt does not know
		}
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, err)
	}
	if _, ok := tok.Header["crit"]; ok {
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, errors.New("the header names critical extensions"))
	}
	signature, err := p.DecodeSegment(parts[2])
	if err != nil {
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, err)
	}
	payload, err := p.DecodeSegment(parts[1])
	if err != nil {
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, err)
	}
	alg, _ := tok.Header["alg"].(string)
	kid, _ := tok.Header["kid"].(string)
	return &parsed{alg: alg, kid: kid, signingString: parts[0] + "." + parts[1], signature: signature, payload: payload}, nil
}

// signWith encodes claims with a header naming alg and kid, and signs it
// with sign.
func signWith(op, alg, kid string, claims jwt.MapClaims, sign func([]byte) ([]byte, error)) (string, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", errs.NewSecurityError(op, errs.CodeJWTSigningFailed, fmt.Errorf("unknown algorithm %q", alg))
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	signingString, err := token.SigningString()
	if err != nil {
		return "", errs.NewSecurityError(op, errs.CodeJWTEncodingFailed, err)
	}
	signature, err := sign([]byte(signingString))
	if err != nil {
		return "", errs.NewSecurityError(op, errs.CodeJWTSigningFailed, err)
	}
	return signingString + "." + b64(signature), nil
}

// validate checks the registered claims of an internal token whose
// signature is valid, and returns them as Claims.
func validate(op string, c *wireClaims, issuer string, audiences []string) (*Claims, error) {
	opts := []jwt.ParserOption{jwt.WithExpirationRequired()}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if len(audiences) > 0 {
		opts = append(opts, jwt.WithAudience(audiences...))
	}
	if err := checkClaims(op, jwt.NewValidator(opts...), c); err != nil {
		return nil, err
	}
	return claimsOf(c, audiences), nil
}

// checkClaims runs v over claims, and turns its error into a refused token
// with the code of the check that failed.
func checkClaims(op string, v *jwt.Validator, claims jwt.Claims) error {
	err := v.Validate(claims)
	if err == nil {
		return nil
	}
	code := errs.CodeJWTInvalidClaims
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		code = errs.CodeTokenExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		code = errs.CodeJWTNotYetValid
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		code = errs.CodeJWTIssuerMismatch
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		code = errs.CodeJWTAudienceMismatch
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		code = errs.CodeJWTMissingClaim
	}
	return errs.NewJWTError(op, code, err)
}

// claimsOf returns the claims of a checked token as Claims.
func claimsOf(c *wireClaims, audiences []string) *Claims {
	out := &Claims{Issuer: c.Issuer, Subject: c.Subject, SessionID: c.SessionID, ID: c.ID, Custom: c.Custom}
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
	return out
}

// internalJWT is an HS256 token signed with the key manager's key of
// purpose jwt_sign. Its kid is the key's version, so a token signed before
// a rotation still verifies.
type internalJWT struct {
	signer Signer
	cfg    JWTConfig
}

func (j *internalJWT) sign(req JWTRequest) (string, error) {
	const op = "JWT.Sign.Internal"
	claims, err := payload(op, JWTInternal, j.cfg, req)
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

func (j *internalJWT) verify(token string) (*Claims, error) {
	const op = "JWT.Verify.Internal"
	var c wireClaims
	p, err := parse(op, token, &c)
	if err != nil {
		return nil, err
	}
	if p.alg != jwt.SigningMethodHS256.Alg() {
		return nil, errs.NewJWTError(op, errs.CodeJWTAlgorithmMismatch, nil)
	}
	version, err := strconv.Atoi(p.kid)
	if err != nil {
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, err)
	}
	// The signer checks the HMAC in constant time, with the key of the
	// token's version.
	ok, err := j.signer.Verify([]byte(p.signingString), p.signature, version)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errs.NewJWTError(op, errs.CodeJWTInvalidSignature, nil)
	}
	return validate(op, &c, j.cfg.Issuer, j.cfg.Audiences[JWTInternal])
}

// externalJWT is signed with the current key of an ExternalKeySet, for
// other services to verify with the published keys. Its kid is the key's.
type externalJWT struct {
	keys ExternalKeySet
	cfg  JWTConfig
}

func (j *externalJWT) sign(ctx context.Context, req JWTRequest) (string, error) {
	const op = "JWT.Sign.External"
	claims, err := payload(op, JWTExternal, j.cfg, req)
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

// verify checks an external token with VerifyJWT, the verification another
// service runs with the published keys: the key set holds the current key
// and the ones rotated out, which still verify the tokens they signed until
// those expire. An algorithm no key may have, none and the HMAC ones among
// them, is refused before the key set is asked.
func (j *externalJWT) verify(ctx context.Context, token string) (*Claims, error) {
	const op = "JWT.Verify.External"
	audiences := j.cfg.Audiences[JWTExternal]
	verified, err := VerifyJWT(ctx, token, j.keys, VerifyOptions{Issuers: []string{j.cfg.Issuer}, Audiences: audiences})
	if err != nil {
		return nil, err
	}
	var c wireClaims
	if err := verified.Claims(&c); err != nil {
		return nil, errs.NewJWTError(op, errs.CodeJWTMalformed, err)
	}
	return claimsOf(&c, audiences), nil
}

type JWTProviderImpl struct {
	internal *internalJWT
	external *externalJWT // not required
	cfg      JWTConfig
}

// NewJWTProvider returns the provider of both kinds of JWT. Internal tokens
// are signed by signer, external ones by keys. A nil keys leaves external
// tokens off: Sign and Verify of JWTExternal are then configuration errors.
func NewJWTProvider(signer Signer, keys ExternalKeySet, cfg JWTConfig) *JWTProviderImpl {
	p := &JWTProviderImpl{internal: &internalJWT{signer: signer, cfg: cfg}, cfg: cfg}
	if keys != nil {
		p.external = &externalJWT{keys: keys, cfg: cfg}
	}
	return p
}

// Sign implements [JWTProvider]. A request without a subject, or for
// an audience the kind does not list, is a validation error.
func (p *JWTProviderImpl) Sign(ctx context.Context, kind JWTKind, req JWTRequest) (string, error) {
	switch kind {
	case JWTInternal:
		return p.internal.sign(req)
	case JWTExternal:
		if p.external == nil {
			return "", errs.NewConfigurationErrorCode("JWT.Sign", errs.CodeJWTExternalNotConfigured, "external JWTs need a key set")
		}
		return p.external.sign(ctx, req)
	default:
		return "", errs.NewConfigurationErrorCode("JWT.Sign", errs.CodeJWTUnknownKind, "unknown JWT kind")
	}
}

// Verify implements [JWTProvider]. A refused token is a CategoryToken
// error, with one of the codes of errors/jwt.go.
func (p *JWTProviderImpl) Verify(ctx context.Context, kind JWTKind, token string) (*Claims, error) {
	switch kind {
	case JWTInternal:
		return p.internal.verify(token)
	case JWTExternal:
		if p.external == nil {
			return nil, errs.NewConfigurationErrorCode("JWT.Verify", errs.CodeJWTExternalNotConfigured, "external JWTs need a key set")
		}
		return p.external.verify(ctx, token)
	default:
		return nil, errs.NewConfigurationErrorCode("JWT.Verify", errs.CodeJWTUnknownKind, "unknown JWT kind")
	}
}
