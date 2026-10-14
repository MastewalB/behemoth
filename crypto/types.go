package crypto

import (
	"encoding/base64"
)

type jwkJSON struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
