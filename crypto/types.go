package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

func newJWTError(op, code string, cause error) error {
	return behemotherr.NewSecurityError(op, code, cause)
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`

	// Kid translates to two different types per kind, overloaded onto one
	// header field because JWT defines only one kid type:
	//   - JWTInternal: Kid == HKDF KeyManager key Version (an int, stringified).Rotation-compatible.
	//   - JWTExternal: Kid == Asymmetric JWKKeyPair.ID, an opaque UUID looked up via
	//     JWKSStore.ByKid.
	Kid string `json:"kid"` // KeyManager version (internal) or JWK key id (external), should be always present.
}

type jwtparts struct{ header, claims, signature string }

func splitJWT(token string) *jwtparts {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil
	}

	return &jwtparts{header: p[0], claims: p[1], signature: p[2]}
}

func b64(b []byte) string                { return base64.RawURLEncoding.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func marshalB64(v any) (string, []byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", nil, err
	}

	return b64(b), b, err
}
