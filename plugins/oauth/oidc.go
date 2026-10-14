package oauth

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// How long a discovery document and a key set are used before they are
// fetched again. An ID token signed with a key the set does not have makes
// the provider fetch the set again, at most once per keyRefetchInterval, so
// a rotation is picked up before keysTTL is over.
const (
	discoveryTTL       = 24 * time.Hour
	keysTTL            = time.Hour
	keyRefetchInterval = time.Minute
)

// idTokenLeeway is the clock skew allowed on an ID token's exp and iat.
const idTokenLeeway = time.Minute

// minRSAKeyBits is the smallest RSA key an ID token may be signed with.
const minRSAKeyBits = 2048

// signingAlgs are the algorithms an ID token may be signed with: RSA and
// ECDSA. "none" and the HMAC algorithms are not among them: an HMAC token
// would be checked with a public key as its secret.
var signingAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// errKeysUnavailable marks a failure to get the provider's keys, which is a
// failure of the system and not a token to refuse.
var errKeysUnavailable = errors.New("the provider's keys could not be fetched")

// discoveryDocument is what the plugin reads of an issuer's
// /.well-known/openid-configuration (OpenID Connect Discovery 1.0, section
// 3, and RFC 9207, section 3).
type discoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
	IssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// jsonWebKey is one key of a JWK set (RFC 7517), with the members of RSA and
// EC public keys (RFC 7518, section 6).
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// publicKey is a usable key of the provider's set.
type publicKey struct {
	kid string
	alg string // the JWK's "alg"; empty when the key does not name one
	key any    // *rsa.PublicKey or *ecdsa.PublicKey
}

// oidcProvider is the built-in OpenID Connect provider: the generic one, and
// Google. It reads the issuer's discovery document on first use, and checks
// every ID token against the issuer's keys.
type oidcProvider struct {
	id     string
	issuer string
	// issuers are the values an ID token's iss may have: the issuer, and
	// for Google also "accounts.google.com", which Google uses as well.
	issuers []string
	auth    clientAuth
	scopes  []string
	http    providerHTTP
	now     func() time.Time

	mu         sync.Mutex
	discovery  *discoveryDocument
	discovered time.Time
	keys       []publicKey
	keysAt     time.Time
}

func (p *oidcProvider) ID() string { return p.id }

// AuthorizationURL implements [Provider].
func (p *oidcProvider) AuthorizationURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	doc, err := p.document(ctx)
	if err != nil {
		return "", err
	}
	return withQuery(doc.AuthorizationEndpoint, url.Values{
		"response_type":         {"code"},
		"client_id":             {p.auth.clientID},
		"redirect_uri":          {req.RedirectURI},
		"scope":                 {strings.Join(p.scopes, " ")},
		"state":                 {req.State},
		"nonce":                 {req.Nonce},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {"S256"},
	})
}

// Exchange implements [Provider]. It redeems the code, checks the ID token,
// and reads the user's claims from it. When the ID token has no email and
// the issuer has a userinfo endpoint, the claims the token lacks come from
// there.
func (p *oidcProvider) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	doc, err := p.document(ctx)
	if err != nil {
		return nil, err
	}
	// RFC 9207: an authorization response that names its issuer has to name
	// this one, and an issuer that says it names itself has to.
	switch {
	case req.Issuer != "" && req.Issuer != doc.Issuer:
		return nil, fmt.Errorf("%w: the authorization response names the issuer %q", ErrExchangeRefused, req.Issuer)
	case req.Issuer == "" && doc.IssParameterSupported:
		return nil, fmt.Errorf("%w: the authorization response does not name its issuer", ErrExchangeRefused)
	}

	tokens, err := p.http.redeemCode(ctx, doc.TokenEndpoint, p.auth, authMethod(doc.AuthMethods, p.auth.secret != nil), req)
	if err != nil {
		return nil, err
	}
	if tokens.IDToken == "" {
		return nil, errors.New("token endpoint: the answer has no ID token")
	}
	claims, err := p.verifyIDToken(ctx, tokens.IDToken, req.Nonce)
	if err != nil {
		return nil, err
	}
	identity := identityFromClaims(claims)

	if identity.Email == "" && doc.UserinfoEndpoint != "" {
		var info map[string]any
		if _, err := p.http.getJSON(ctx, doc.UserinfoEndpoint, http.Header{"Authorization": {"Bearer " + tokens.AccessToken}}, &info); err != nil {
			return nil, fmt.Errorf("userinfo endpoint: %w", err)
		}
		// OpenID Connect Core 1.0, section 5.3.2: the sub of the userinfo
		// answer has to be the ID token's, or the answer is not about the
		// user who signed in.
		if sub, _ := info["sub"].(string); sub != identity.Subject {
			return nil, fmt.Errorf("%w: the userinfo answer is about another subject", ErrExchangeRefused)
		}
		identity = mergeIdentity(identity, identityFromClaims(info))
	}
	return &ExchangeResult{Identity: identity}, nil
}

// authMethod returns how to authenticate at the token endpoint: HTTP Basic
// when the issuer supports it or does not say (the default of OpenID
// Connect Discovery), the form when it supports only that, and the client
// id alone for a client without a secret.
func authMethod(supported []string, hasSecret bool) string {
	switch {
	case !hasSecret:
		return authNone
	case len(supported) == 0 || slices.Contains(supported, authSecretBasic):
		return authSecretBasic
	case slices.Contains(supported, authSecretPost):
		return authSecretPost
	}
	return authSecretBasic
}

// document returns the issuer's discovery document, fetching it when there
// is none or it is older than discoveryTTL.
func (p *oidcProvider) document(ctx context.Context) (*discoveryDocument, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discovery != nil && p.now().Sub(p.discovered) < discoveryTTL {
		return p.discovery, nil
	}
	var doc discoveryDocument
	if _, err := p.http.getJSON(ctx, strings.TrimRight(p.issuer, "/")+"/.well-known/openid-configuration", nil, &doc); err != nil {
		return nil, fmt.Errorf("discovery of %s: %w", p.issuer, err)
	}
	// OpenID Connect Discovery 1.0, section 4.3: a document that names
	// another issuer is not this issuer's.
	if doc.Issuer != p.issuer {
		return nil, fmt.Errorf("discovery of %s: the document names the issuer %q", p.issuer, doc.Issuer)
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI,
	} {
		if err := checkEndpoint(endpoint); err != nil {
			return nil, fmt.Errorf("discovery of %s: %s: %w", p.issuer, name, err)
		}
	}
	if doc.UserinfoEndpoint != "" {
		if err := checkEndpoint(doc.UserinfoEndpoint); err != nil {
			return nil, fmt.Errorf("discovery of %s: userinfo_endpoint: %w", p.issuer, err)
		}
	}
	p.discovery, p.discovered = &doc, p.now()
	return p.discovery, nil
}

// verifyIDToken checks an ID token (OpenID Connect Core 1.0, section
// 3.1.3.7) and returns its claims: the signature with one of the issuer's
// keys, the issuer, the audience and the authorized party, the expiry and
// the issue time, the nonce, and a subject. A token that fails a check
// wraps ErrExchangeRefused. Keys that can't be fetched are a failure of the
// system.
func (p *oidcProvider) verifyIDToken(ctx context.Context, raw, nonce string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingAlgs),
		jwt.WithAudience(p.auth.clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(idTokenLeeway),
		jwt.WithTimeFunc(p.now),
	)
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return p.signingKey(ctx, kid, token.Method.Alg())
	})
	if err != nil {
		if errors.Is(err, errKeysUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: ID token: %w", ErrExchangeRefused, err)
	}

	refuse := func(why string) error { return fmt.Errorf("%w: ID token: %s", ErrExchangeRefused, why) }
	if iss, _ := claims["iss"].(string); !slices.Contains(p.issuers, iss) {
		return nil, refuse("another issuer")
	}
	audience, _ := claims.GetAudience()
	azp, hasAzp := claims["azp"].(string)
	if (len(audience) > 1 || hasAzp) && azp != p.auth.clientID {
		// A token for several audiences has to name this client as the
		// party it was issued to.
		return nil, refuse("issued to another party")
	}
	if got, _ := claims["nonce"].(string); got == "" || got != nonce {
		return nil, refuse("another nonce")
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, refuse("no subject")
	}
	return claims, nil
}

// signingKey returns the issuer's key for an ID token's kid and alg. It
// fetches the key set when it is older than keysTTL, or when it has no
// matching key and was not fetched in the last keyRefetchInterval.
func (p *oidcProvider) signingKey(ctx context.Context, kid, alg string) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys == nil || p.now().Sub(p.keysAt) >= keysTTL {
		if err := p.fetchKeys(ctx); err != nil {
			return nil, err
		}
	}
	if key, ok := matchKey(p.keys, kid, alg); ok {
		return key, nil
	}
	if p.now().Sub(p.keysAt) >= keyRefetchInterval {
		if err := p.fetchKeys(ctx); err != nil {
			return nil, err
		}
		if key, ok := matchKey(p.keys, kid, alg); ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("no key of the issuer matches kid %q and alg %q", kid, alg)
}

// fetchKeys replaces the key set with the one at the discovery document's
// jwks_uri. Keys the plugin can't use are left out. p.mu is held.
func (p *oidcProvider) fetchKeys(ctx context.Context) error {
	doc := p.discovery
	if doc == nil {
		return fmt.Errorf("%w: no discovery document", errKeysUnavailable)
	}
	var set struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if _, err := p.http.getJSON(ctx, doc.JWKSURI, nil, &set); err != nil {
		return fmt.Errorf("%w: %w", errKeysUnavailable, err)
	}
	keys := make([]publicKey, 0, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		key, err := jwk.publicKey()
		if err != nil {
			continue
		}
		keys = append(keys, publicKey{kid: jwk.Kid, alg: jwk.Alg, key: key})
	}
	p.keys, p.keysAt = keys, p.now()
	return nil
}

// matchKey finds the key for kid and alg. A token without a kid matches
// when exactly one key of the algorithm's type is in the set.
func matchKey(keys []publicKey, kid, alg string) (any, bool) {
	var found []any
	for _, k := range keys {
		if (kid != "" && k.kid != kid) || (k.alg != "" && k.alg != alg) || !keyFits(k.key, alg) {
			continue
		}
		found = append(found, k.key)
	}
	if len(found) == 1 || (kid != "" && len(found) > 0) {
		return found[0], true
	}
	return nil, false
}

// keyFits reports whether key is of the type alg signs with.
func keyFits(key any, alg string) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		return strings.HasPrefix(alg, "ES")
	}
	return false
}

// publicKey converts an RSA or EC key of a JWK set. Any other type, an RSA
// key under minRSAKeyBits, and a point that is not on its curve are errors.
func (k jsonWebKey) publicKey() (any, error) {
	decode := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")) }
	switch k.Kty {
	case "RSA":
		n, err := decode(k.N)
		if err != nil {
			return nil, err
		}
		e, err := decode(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("RSA key: bad exponent")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if key.N.BitLen() < minRSAKeyBits || key.E < 3 {
			return nil, errors.New("RSA key: too small")
		}
		return key, nil
	case "EC":
		var curve elliptic.Curve
		var check ecdh.Curve
		switch k.Crv {
		case "P-256":
			curve, check = elliptic.P256(), ecdh.P256()
		case "P-384":
			curve, check = elliptic.P384(), ecdh.P384()
		case "P-521":
			curve, check = elliptic.P521(), ecdh.P521()
		default:
			return nil, fmt.Errorf("EC key: curve %q", k.Crv)
		}
		x, errX := decode(k.X)
		y, errY := decode(k.Y)
		size := (curve.Params().BitSize + 7) / 8
		if errX != nil || errY != nil || len(x) > size || len(y) > size {
			return nil, errors.New("EC key: bad coordinates")
		}
		// The uncompressed point, which ecdh refuses when it is not on the
		// curve.
		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1+size-len(x):1+size], x)
		copy(point[1+2*size-len(y):], y)
		if _, err := check.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("EC key: %w", err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, fmt.Errorf("key type %q", k.Kty)
}

// identityFromClaims reads the standard claims of OpenID Connect Core 1.0,
// section 5.1. email_verified is true only as the boolean true or the
// string "true", which some providers send.
func identityFromClaims(claims map[string]any) Identity {
	str := func(key string) string { s, _ := claims[key].(string); return s }
	verified := false
	switch v := claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	return Identity{
		Subject:       str("sub"),
		Email:         str("email"),
		EmailVerified: verified,
		Name:          str("name"),
		GivenName:     str("given_name"),
		FamilyName:    str("family_name"),
		Picture:       str("picture"),
	}
}

// mergeIdentity fills what base lacks from more. The email and its
// verification come together, from the one that has the email.
func mergeIdentity(base, more Identity) Identity {
	if base.Email == "" {
		base.Email, base.EmailVerified = more.Email, more.EmailVerified
	}
	for _, field := range []struct{ into, from *string }{
		{&base.Name, &more.Name}, {&base.GivenName, &more.GivenName},
		{&base.FamilyName, &more.FamilyName}, {&base.Picture, &more.Picture},
	} {
		if *field.into == "" {
			*field.into = *field.from
		}
	}
	return base
}
