package crypto_test

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwkSet encodes keys, each a map of JWK members, as a JWK set.
func jwkSet(t *testing.T, keys ...any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	return data
}

func rsaMembers(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "n": b64url(key.N.Bytes()), "e": b64url(big.NewInt(int64(key.E)).Bytes())}
}

func ecMembers(t *testing.T, kid, crv string, key *ecdsa.PublicKey) map[string]any {
	t.Helper()
	point, err := key.Bytes()
	require.NoError(t, err)
	size := (len(point) - 1) / 2
	return map[string]any{"kty": "EC", "kid": kid, "crv": crv, "x": b64url(point[1 : 1+size]), "y": b64url(point[1+size:])}
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return key
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

// with returns a copy of members with change applied.
func with(members map[string]any, change func(map[string]any)) map[string]any {
	out := make(map[string]any, len(members))
	for k, v := range members {
		out[k] = v
	}
	change(out)
	return out
}

// Every key type of the JWS signature algorithms is read, in the set's
// order, and verifies a token its private half signed. A key that names no
// algorithm gets the one its type allows; an RSA key has six and keeps none.
func TestParseJWKSetReadsEveryKeyType(t *testing.T) {
	rsaKey := newRSAKey(t, 2048)
	p256, p384, p521 := newECKey(t, elliptic.P256()), newECKey(t, elliptic.P384()), newECKey(t, elliptic.P521())
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keys, err := crypto.ParseJWKSet(jwkSet(t,
		with(rsaMembers("rsa-1", &rsaKey.PublicKey), func(m map[string]any) { m["alg"] = "PS384"; m["use"] = "sig" }),
		rsaMembers("rsa-2", &rsaKey.PublicKey),
		ecMembers(t, "p256", "P-256", &p256.PublicKey),
		ecMembers(t, "p384", "P-384", &p384.PublicKey),
		with(ecMembers(t, "p521", "P-521", &p521.PublicKey), func(m map[string]any) { m["key_ops"] = []string{"verify"} }),
		map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(edPub)},
	))
	require.NoError(t, err)
	require.Len(t, keys, 6)

	cases := []struct {
		kid, alg string
		private  any
		method   jwt.SigningMethod
	}{
		{"rsa-1", "PS384", rsaKey, jwt.SigningMethodPS384},
		{"rsa-2", "", rsaKey, jwt.SigningMethodRS256},
		{"p256", "ES256", p256, jwt.SigningMethodES256},
		{"p384", "ES384", p384, jwt.SigningMethodES384},
		{"p521", "ES512", p521, jwt.SigningMethodES512},
		{"", "EdDSA", edPriv, jwt.SigningMethodEdDSA},
	}
	for i, c := range cases {
		assert.Equal(t, c.kid, keys[i].KID, "the set's order")
		assert.Equal(t, c.alg, keys[i].Algorithm, c.kid)
		signature, err := c.method.Sign("header.payload", c.private)
		require.NoError(t, err)
		assert.NoError(t, c.method.Verify("header.payload", signature, keys[i].Key), "%s verifies what its private half signed", c.kid)
	}
}

// The examples of the RFCs: the set of RFC 7517, appendix A.1, whose EC key
// is for encryption, and the Ed25519 key of RFC 8037, appendix A, with the
// JWS it signed.
func TestParseJWKSetRFCExamples(t *testing.T) {
	keys, err := crypto.ParseJWKSet([]byte(`{"keys":[
		{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},
		{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}
	]}`))
	require.NoError(t, err)
	require.Len(t, keys, 1, "the encryption key is left out")
	assert.Equal(t, "2011-04-29", keys[0].KID)
	assert.Equal(t, "RS256", keys[0].Algorithm)
	rsaKey := keys[0].Key.(*rsa.PublicKey)
	assert.Equal(t, 2048, rsaKey.N.BitLen())
	assert.Equal(t, 65537, rsaKey.E)

	public := `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	private := `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	keys, err = crypto.ParseJWKSet([]byte(`{"keys":[` + private + `,` + public + `]}`))
	require.NoError(t, err)
	require.Len(t, keys, 1, "the key published with its private part is left out")
	assert.Equal(t, "EdDSA", keys[0].Algorithm)
	signature, err := base64.RawURLEncoding.DecodeString("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
	require.NoError(t, err)
	assert.NoError(t, jwt.SigningMethodEdDSA.Verify("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc", signature, keys[0].Key),
		"the JWS of RFC 8037, appendix A.4")
}

// A key that can't verify a signature is left out, and the set's other keys
// are kept.
func TestParseJWKSetLeavesOutUnusableKeys(t *testing.T) {
	good := rsaMembers("good", &newRSAKey(t, 2048).PublicKey)
	rsaKey := rsaMembers("rsa", &newRSAKey(t, 2048).PublicKey)
	ecKey := ecMembers(t, "ec", "P-256", &newECKey(t, elliptic.P256()).PublicKey)
	exponent := func(e []byte) map[string]any { return with(rsaKey, func(m map[string]any) { m["e"] = b64url(e) }) }

	cases := map[string]any{
		"a symmetric key":                  map[string]any{"kty": "oct", "k": b64url([]byte("shared"))},
		"an unknown key type":              map[string]any{"kty": "XYZ", "x": "AA"},
		"no key type":                      map[string]any{"n": good["n"], "e": good["e"]},
		"an encryption key":                with(rsaKey, func(m map[string]any) { m["use"] = "enc" }),
		"key_ops without verify":           with(rsaKey, func(m map[string]any) { m["key_ops"] = []string{"encrypt", "wrapKey"} }),
		"a private key":                    with(ecKey, func(m map[string]any) { m["d"] = b64url([]byte("private")) }),
		"an RSA key under 2048 bits":       rsaMembers("small", &newRSAKey(t, 1024).PublicKey),
		"an even exponent":                 exponent(big.NewInt(65536).Bytes()),
		"an exponent of 1":                 exponent([]byte{1}),
		"an exponent over 2^31-1":          exponent([]byte{0x80, 0, 0, 1}),
		"an exponent of five bytes":        exponent([]byte{1, 0, 0, 0, 1}),
		"no modulus":                       with(rsaKey, func(m map[string]any) { delete(m, "n") }),
		"an unknown curve":                 with(ecKey, func(m map[string]any) { m["crv"] = "P-192" }),
		"secp256k1":                        with(ecKey, func(m map[string]any) { m["crv"] = "secp256k1" }),
		"a point off its curve":            with(ecKey, func(m map[string]any) { m["y"] = m["x"] }),
		"a coordinate longer than a curve": with(ecKey, func(m map[string]any) { m["x"] = b64url(make([]byte, 33)) }),
		"no y":                             with(ecKey, func(m map[string]any) { delete(m, "y") }),
		"an Ed448 key":                     map[string]any{"kty": "OKP", "crv": "Ed448", "x": b64url(make([]byte, 57))},
		"an Ed25519 key of the wrong size": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AA"},
		"an RSA key for ES256":             with(rsaKey, func(m map[string]any) { m["alg"] = "ES256" }),
		"a P-256 key for ES384":            with(ecKey, func(m map[string]any) { m["alg"] = "ES384" }),
		"alg none":                         with(rsaKey, func(m map[string]any) { m["alg"] = "none" }),
		"alg HS256":                        with(rsaKey, func(m map[string]any) { m["alg"] = "HS256" }),
		"a member that is not base64url":   with(rsaKey, func(m map[string]any) { m["n"] = "not base64url!" }),
		"a member of the wrong type":       with(rsaKey, func(m map[string]any) { m["kid"] = 5 }),
		"a key that is not an object":      "a string",
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			keys, err := crypto.ParseJWKSet(jwkSet(t, key, good))
			require.NoError(t, err)
			require.Len(t, keys, 1)
			assert.Equal(t, "good", keys[0].KID)
		})
	}
}

// What is not a JSON object with a "keys" array is an error. An empty set is
// not.
func TestParseJWKSetRefusesWhatIsNotASet(t *testing.T) {
	for _, data := range []string{`not json`, `[]`, `{}`, `{"keys":null}`, `{"keys":{}}`, `{"keys":"a"}`, ``} {
		_, err := crypto.ParseJWKSet([]byte(data))
		assert.Error(t, err, "%q", data)
	}
	keys, err := crypto.ParseJWKSet([]byte(`{"keys":[]}`))
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// Two forms some issuers write are read: base64url with padding, and an EC
// coordinate without its leading zero bytes.
func TestParseJWKSetTolerance(t *testing.T) {
	rsaKey := newRSAKey(t, 2048)
	padded := rsaMembers("padded", &rsaKey.PublicKey)
	padded["n"] = base64.URLEncoding.EncodeToString(rsaKey.N.Bytes())
	require.True(t, strings.HasSuffix(padded["n"].(string), "="), "256 bytes need padding")

	// A key whose x starts with a zero byte, written without it.
	var ec *ecdsa.PrivateKey
	for range 10000 {
		if k := newECKey(t, elliptic.P256()); k.X.BitLen() <= 248 {
			ec = k
			break
		}
	}
	require.NotNil(t, ec)
	short := ecMembers(t, "short", "P-256", &ec.PublicKey)
	short["x"] = b64url(ec.X.Bytes())
	require.Less(t, len(ec.X.Bytes()), 32)

	keys, err := crypto.ParseJWKSet(jwkSet(t, padded, short))
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.True(t, rsaKey.PublicKey.Equal(keys[0].Key))
	assert.True(t, ec.PublicKey.Equal(keys[1].Key))
}

// A set MarshalJWKSet writes is read back to the same keys. Each key has
// its kid, its algorithm when it names one, and use "sig", and nothing
// private. EC coordinates have the curve's full size.
func TestMarshalJWKSet(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey := newRSAKey(t, 2048)
	keys := []types.PublishedKey{
		{KID: "1", Algorithm: "EdDSA", Key: edPub},
		{KID: "2", Algorithm: "ES256", Key: &newECKey(t, elliptic.P256()).PublicKey},
		{KID: "3", Algorithm: "ES384", Key: &newECKey(t, elliptic.P384()).PublicKey},
		{KID: "4", Algorithm: "ES512", Key: &newECKey(t, elliptic.P521()).PublicKey},
		{KID: "5", Algorithm: "RS256", Key: &rsaKey.PublicKey},
		{KID: "6", Key: &rsaKey.PublicKey},
	}
	data, err := crypto.MarshalJWKSet(keys)
	require.NoError(t, err)

	read, err := crypto.ParseJWKSet(data)
	require.NoError(t, err)
	require.Len(t, read, len(keys))
	for i, key := range keys {
		assert.Equal(t, key.KID, read[i].KID)
		assert.Equal(t, key.Algorithm, read[i].Algorithm)
		assert.True(t, key.Key.(interface {
			Equal(stdcrypto.PublicKey) bool
		}).Equal(read[i].Key), key.KID)
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &set))
	for _, k := range set.Keys {
		assert.Equal(t, "sig", k["use"])
		assert.NotContains(t, k, "d", "no private part")
	}
	assert.Equal(t, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(edPub), "kid": "1", "alg": "EdDSA", "use": "sig"}, set.Keys[0])
	for i, size := range map[int]int{1: 32, 2: 48, 3: 66} {
		for _, member := range []string{"x", "y"} {
			coordinate, err := base64.RawURLEncoding.DecodeString(set.Keys[i][member].(string))
			require.NoError(t, err)
			assert.Len(t, coordinate, size, "%s of key %s", member, set.Keys[i]["kid"])
		}
	}
	assert.Equal(t, "AQAB", set.Keys[4]["e"])
	assert.NotContains(t, set.Keys[5], "alg", "an RSA key that names no algorithm")
}

// What can't be published is refused, a private key among it, and the
// error names the key.
func TestMarshalJWKSetRefusesWhatItCantPublish(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey := newECKey(t, elliptic.P256())
	rsaKey := newRSAKey(t, 2048)
	cases := map[string]types.PublishedKey{
		"an Ed25519 private key":     {KID: "k", Algorithm: "EdDSA", Key: edPriv},
		"an EC private key":          {KID: "k", Algorithm: "ES256", Key: ecKey},
		"an RSA private key":         {KID: "k", Algorithm: "RS256", Key: rsaKey},
		"an RSA key under 2048 bits": {KID: "k", Algorithm: "RS256", Key: &newRSAKey(t, 1024).PublicKey},
		"a P-224 key":                {KID: "k", Key: &newECKey(t, elliptic.P224()).PublicKey},
		"an Ed25519 key for ES256":   {KID: "k", Algorithm: "ES256", Key: edPub},
		"a P-256 key for ES512":      {KID: "k", Algorithm: "ES512", Key: &ecKey.PublicKey},
		"an RSA key for EdDSA":       {KID: "k", Algorithm: "EdDSA", Key: &rsaKey.PublicKey},
		"an Ed25519 key too short":   {KID: "k", Key: edPub[:16]},
		"no key":                     {KID: "k"},
		"a nil RSA key":              {KID: "k", Key: (*rsa.PublicKey)(nil)},
		"a nil EC key":               {KID: "k", Key: (*ecdsa.PublicKey)(nil)},
		"something else":             {KID: "k", Key: "a string"},
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.MarshalJWKSet([]types.PublishedKey{{KID: "fine", Algorithm: "EdDSA", Key: edPub}, key})
			require.Error(t, err)
			assert.Contains(t, err.Error(), `key "k"`)
		})
	}
}
