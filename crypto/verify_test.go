package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticKeys is a KeySet with fixed keys. err, when set, is the error of
// every call: a set that can't get its keys.
type staticKeys struct {
	keys []types.PublishedKey
	err  error
}

func (s *staticKeys) PublicKey(_ context.Context, kid string) (types.PublishedKey, error) {
	if s.err != nil {
		return types.PublishedKey{}, s.err
	}
	for _, k := range s.keys {
		if k.KID == kid {
			return k, nil
		}
	}
	return types.PublishedKey{}, behemotherr.NewJWTError("staticKeys", behemotherr.ErrorCodeJWTUnknownKey, nil)
}

func (s *staticKeys) PublicKeys(context.Context) ([]types.PublishedKey, error) {
	return s.keys, s.err
}

const (
	verifyIssuer   = "https://id.example.com"
	verifyAudience = "https://api.example.com"
)

// verifyFixture is an issuer's keys, and a key set of their public halves.
type verifyFixture struct {
	rsa     any
	ec256   *ecdsa.PrivateKey
	ec384   *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	keys    *staticKeys
	options crypto.VerifyOptions
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	rsaKey := newRSAKey(t, 2048)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f := &verifyFixture{rsa: rsaKey, ec256: newECKey(t, elliptic.P256()), ec384: newECKey(t, elliptic.P384()), ed: ed}
	f.keys = &staticKeys{keys: []types.PublishedKey{
		{KID: "rsa", Key: &rsaKey.PublicKey}, // names no algorithm: any of RSA's
		{KID: "ec", Algorithm: "ES256", Key: &f.ec256.PublicKey},
		{KID: "ed", Algorithm: "EdDSA", Key: ed.Public()},
		// Two keys of different types under one kid (RFC 7517, section 4.5).
		{KID: "shared", Algorithm: "PS256", Key: &rsaKey.PublicKey},
		{KID: "shared", Algorithm: "ES384", Key: &f.ec384.PublicKey},
	}}
	f.options = crypto.VerifyOptions{Issuers: []string{verifyIssuer}, Audiences: []string{verifyAudience}}
	return f
}

func validClaims(change ...func(jwt.MapClaims)) jwt.MapClaims {
	now := time.Now()
	c := jwt.MapClaims{
		"iss": verifyIssuer, "aud": verifyAudience, "sub": "user-1", "jti": "token-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "email": "ada@example.com",
	}
	for _, fn := range change {
		fn(c)
	}
	return c
}

func tokenWith(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func refused(t *testing.T, err error, code string, msgAndArgs ...any) {
	t.Helper()
	require.Error(t, err, msgAndArgs...)
	var domain *behemotherr.DomainError
	require.True(t, errors.As(err, &domain), "a DomainError: %v", err)
	assert.Equal(t, behemotherr.CategoryToken, domain.Category, msgAndArgs...)
	assert.Equal(t, code, domain.Code, msgAndArgs...)
}

// A token of every key type is accepted, with its registered claims and
// the others to decode. A key that names no algorithm takes any its type
// signs with.
func TestVerifyJWTAcceptsEveryKeyType(t *testing.T) {
	f := newVerifyFixture(t)
	ctx := context.Background()
	cases := []struct {
		method jwt.SigningMethod
		key    any
		kid    string
	}{
		{jwt.SigningMethodRS256, f.rsa, "rsa"},
		{jwt.SigningMethodPS512, f.rsa, "rsa"},
		{jwt.SigningMethodES256, f.ec256, "ec"},
		{jwt.SigningMethodEdDSA, f.ed, "ed"},
		{jwt.SigningMethodPS256, f.rsa, "shared"},
		{jwt.SigningMethodES384, f.ec384, "shared"},
	}
	for _, c := range cases {
		claims := validClaims()
		verified, err := crypto.VerifyJWT(ctx, tokenWith(t, c.method, c.key, c.kid, claims), f.keys, f.options)
		require.NoError(t, err, "%s with %s", c.method.Alg(), c.kid)
		assert.Equal(t, c.kid, verified.KID)
		assert.Equal(t, c.method.Alg(), verified.Algorithm)
		assert.Equal(t, verifyIssuer, verified.Issuer)
		assert.Equal(t, "user-1", verified.Subject)
		assert.Equal(t, []string{verifyAudience}, verified.Audience)
		assert.Equal(t, "token-1", verified.ID)
		assert.Equal(t, claims["exp"], verified.ExpiresAt.Unix())
		assert.Equal(t, claims["iat"], verified.IssuedAt.Unix())
		assert.True(t, verified.NotBefore.IsZero())

		var custom struct {
			Email string `json:"email"`
		}
		require.NoError(t, verified.Claims(&custom))
		assert.Equal(t, "ada@example.com", custom.Email)
	}
}

// The algorithm comes from the caller's list and the key, never from the
// header alone.
func TestVerifyJWTPinsTheAlgorithm(t *testing.T) {
	f := newVerifyFixture(t)
	ctx := context.Background()
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	cases := map[string]string{
		"none":                          unsigned,
		"HS256 under an RSA key":        tokenWith(t, jwt.SigningMethodHS256, []byte("a guessed secret"), "rsa", validClaims()),
		"ES256 under an Ed25519 key":    tokenWith(t, jwt.SigningMethodES256, f.ec256, "ed", validClaims()),
		"RS256 under an EC key":         tokenWith(t, jwt.SigningMethodRS256, f.rsa, "ec", validClaims()),
		"ES512 under the shared kid":    tokenWith(t, jwt.SigningMethodES512, newECKey(t, elliptic.P521()), "shared", validClaims()),
		"an algorithm golang-jwt lacks": fakeHeader(t, `{"alg":"XYZ","kid":"rsa"}`),
		"ES384 under a key for ES256":   tokenWith(t, jwt.SigningMethodES384, f.ec384, "ec", validClaims()),
	}
	for name, token := range cases {
		_, err := crypto.VerifyJWT(ctx, token, f.keys, f.options)
		refused(t, err, behemotherr.ErrorCodeJWTAlgorithmMismatch, name)
	}

	onlyRSA := f.options
	onlyRSA.Algorithms = []string{"RS256"}
	_, err = crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodEdDSA, f.ed, "ed", validClaims()), f.keys, onlyRSA)
	refused(t, err, behemotherr.ErrorCodeJWTAlgorithmMismatch, "an algorithm the caller does not list")
	_, err = crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodRS256, f.rsa, "rsa", validClaims()), f.keys, onlyRSA)
	assert.NoError(t, err)
}

// fakeHeader returns a token with header as it is, valid claims, and a
// signature of no key.
func fakeHeader(t *testing.T, header string) string {
	t.Helper()
	claims, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims()).SigningString()
	require.NoError(t, err)
	return b64url([]byte(header)) + "." + strings.SplitN(claims, ".", 2)[1] + "." + b64url([]byte("signature"))
}

// A signature of another key, or over other claims, is refused.
func TestVerifyJWTChecksTheSignature(t *testing.T) {
	f := newVerifyFixture(t)
	ctx := context.Background()
	_, err := crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodRS256, newRSAKey(t, 2048), "rsa", validClaims()), f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTInvalidSignature, "signed by another key")

	token := tokenWith(t, jwt.SigningMethodES256, f.ec256, "ec", validClaims())
	parts := strings.Split(token, ".")
	other := strings.Split(tokenWith(t, jwt.SigningMethodES256, f.ec256, "ec", validClaims(func(c jwt.MapClaims) { c["sub"] = "admin" })), ".")
	_, err = crypto.VerifyJWT(ctx, parts[0]+"."+other[1]+"."+parts[2], f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTInvalidSignature, "claims that were not signed")
}

// The registered claims are checked once the signature is.
func TestVerifyJWTChecksTheClaims(t *testing.T) {
	f := newVerifyFixture(t)
	ctx := context.Background()
	now := time.Now()
	sign := func(change func(jwt.MapClaims)) string {
		return tokenWith(t, jwt.SigningMethodEdDSA, f.ed, "ed", validClaims(change))
	}
	cases := map[string]struct {
		token string
		code  string
	}{
		"another issuer":         {sign(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" }), behemotherr.ErrorCodeJWTIssuerMismatch},
		"no issuer":              {sign(func(c jwt.MapClaims) { delete(c, "iss") }), behemotherr.ErrorCodeJWTIssuerMismatch},
		"another audience":       {sign(func(c jwt.MapClaims) { c["aud"] = "https://billing.example.com" }), behemotherr.ErrorCodeJWTAudienceMismatch},
		"no audience":            {sign(func(c jwt.MapClaims) { delete(c, "aud") }), behemotherr.ErrorCodeJWTMissingClaim},
		"expired":                {sign(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Second).Unix() }), behemotherr.ErrorCodeTokenExpired},
		"no expiry":              {sign(func(c jwt.MapClaims) { delete(c, "exp") }), behemotherr.ErrorCodeJWTMissingClaim},
		"not valid yet":          {sign(func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Minute).Unix() }), behemotherr.ErrorCodeJWTNotYetValid},
		"a subject of numbers":   {sign(func(c jwt.MapClaims) { c["sub"] = 42 }), behemotherr.ErrorCodeJWTInvalidClaims},
		"an id of numbers":       {sign(func(c jwt.MapClaims) { c["jti"] = 42 }), behemotherr.ErrorCodeJWTInvalidClaims},
		"an expiry that is text": {sign(func(c jwt.MapClaims) { c["exp"] = "tomorrow" }), behemotherr.ErrorCodeJWTInvalidClaims},
	}
	for name, c := range cases {
		_, err := crypto.VerifyJWT(ctx, c.token, f.keys, f.options)
		refused(t, err, c.code, name)
	}

	google := f.options
	google.Issuers = []string{"https://accounts.google.com", "accounts.google.com"}
	_, err := crypto.VerifyJWT(ctx, sign(func(c jwt.MapClaims) { c["iss"] = "accounts.google.com" }), f.keys, google)
	assert.NoError(t, err, "one of several issuers")

	several := sign(func(c jwt.MapClaims) { c["aud"] = []string{"https://billing.example.com", verifyAudience} })
	verified, err := crypto.VerifyJWT(ctx, several, f.keys, f.options)
	require.NoError(t, err, "aud holds the caller among others")
	assert.Len(t, verified.Audience, 2)

	issuedLater := sign(func(c jwt.MapClaims) {
		c["iat"] = now.Add(10 * time.Minute).Unix()
		c["exp"] = now.Add(20 * time.Minute).Unix()
	})
	_, err = crypto.VerifyJWT(ctx, issuedLater, f.keys, f.options)
	assert.NoError(t, err, "iat is not checked unless asked")
	checked := f.options
	checked.CheckIssuedAt = true
	_, err = crypto.VerifyJWT(ctx, issuedLater, f.keys, checked)
	refused(t, err, behemotherr.ErrorCodeJWTInvalidClaims, "an iat in the future")

	justExpired := sign(func(c jwt.MapClaims) { c["exp"] = now.Add(-30 * time.Second).Unix() })
	lenient := f.options
	lenient.Leeway = time.Minute
	_, err = crypto.VerifyJWT(ctx, justExpired, f.keys, lenient)
	assert.NoError(t, err, "within the leeway")

	clock := f.options
	clock.Now = func() time.Time { return now.Add(time.Hour) }
	_, err = crypto.VerifyJWT(ctx, sign(func(jwt.MapClaims) {}), f.keys, clock)
	refused(t, err, behemotherr.ErrorCodeTokenExpired, "the caller's clock")
}

// A token names its key. One that names none is checked against every key
// that fits it, when the caller allows it.
func TestVerifyJWTFindsTheKey(t *testing.T) {
	f := newVerifyFixture(t)
	ctx := context.Background()
	_, err := crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodEdDSA, f.ed, "nope", validClaims()), f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTUnknownKey, "a kid the set lacks")

	withoutKID := tokenWith(t, jwt.SigningMethodRS256, f.rsa, "", validClaims())
	_, err = crypto.VerifyJWT(ctx, withoutKID, f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTUnknownKey, "no kid")

	allow := f.options
	allow.AllowMissingKID = true
	verified, err := crypto.VerifyJWT(ctx, withoutKID, f.keys, allow)
	require.NoError(t, err, "every RSA key is tried")
	assert.Empty(t, verified.KID)
	_, err = crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodES512, newECKey(t, elliptic.P521()), "", validClaims()), f.keys, allow)
	refused(t, err, behemotherr.ErrorCodeJWTUnknownKey, "no key fits")
	_, err = crypto.VerifyJWT(ctx, tokenWith(t, jwt.SigningMethodRS256, newRSAKey(t, 2048), "", validClaims()), f.keys, allow)
	refused(t, err, behemotherr.ErrorCodeJWTInvalidSignature, "no key that fits signed it")

	_, err = crypto.VerifyJWT(ctx, fakeHeader(t, `{"alg":"EdDSA","kid":"ed","crit":["exp"]}`), f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTMalformed, "a critical extension")
	_, err = crypto.VerifyJWT(ctx, "not.a.token", f.keys, f.options)
	refused(t, err, behemotherr.ErrorCodeJWTMalformed)
}

// A key set that can't get its keys fails as the system does, and the
// token is not refused.
func TestVerifyJWTKeySetFailure(t *testing.T) {
	f := newVerifyFixture(t)
	down := &staticKeys{err: errors.New("the issuer is down")}
	for _, opts := range []crypto.VerifyOptions{f.options, {Issuers: f.options.Issuers, Audiences: f.options.Audiences, AllowMissingKID: true}} {
		for _, kid := range []string{"ed", ""} {
			_, err := crypto.VerifyJWT(context.Background(), tokenWith(t, jwt.SigningMethodEdDSA, f.ed, kid, validClaims()), down, opts)
			if kid == "" && !opts.AllowMissingKID {
				continue
			}
			require.Error(t, err)
			assert.False(t, behemotherr.Is(err, behemotherr.CategoryToken), "kid %q: %v", kid, err)
			assert.ErrorContains(t, err, "the issuer is down")
		}
	}
}

// Options that can't keep a token from another issuer, another service or
// a symmetric algorithm out are a configuration error.
func TestVerifyJWTOptions(t *testing.T) {
	f := newVerifyFixture(t)
	token := tokenWith(t, jwt.SigningMethodEdDSA, f.ed, "ed", validClaims())
	cases := map[string]func(*crypto.VerifyOptions){
		"no issuer":         func(o *crypto.VerifyOptions) { o.Issuers = nil },
		"an empty issuer":   func(o *crypto.VerifyOptions) { o.Issuers = []string{""} },
		"no audience":       func(o *crypto.VerifyOptions) { o.Audiences = nil },
		"an empty audience": func(o *crypto.VerifyOptions) { o.Audiences = []string{verifyAudience, ""} },
		"HS256":             func(o *crypto.VerifyOptions) { o.Algorithms = []string{"EdDSA", "HS256"} },
		"none":              func(o *crypto.VerifyOptions) { o.Algorithms = []string{"none"} },
		"a negative leeway": func(o *crypto.VerifyOptions) { o.Leeway = -time.Second },
	}
	for name, change := range cases {
		opts := f.options
		change(&opts)
		_, err := crypto.VerifyJWT(context.Background(), token, f.keys, opts)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%s: %v", name, err)
	}
	_, err := crypto.VerifyJWT(context.Background(), token, nil, f.options)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "no key set: %v", err)
}
