package crypto

import (
	"crypto/hmac"
	"encoding/hex"
)

type hmacSecretHasher struct{ km KeyManager }

// NewSecretHasher returns an HMAC-SHA256 SecretHasher keyed by km's
// KeyPurposeTokenHash key. Hash returns the HMAC as 64 lowercase hex
// characters, and the version of the key; the same secret has the same hash
// under one version. Verify compares in constant time, and a version km does
// not hold is km's error.
func NewSecretHasher(km KeyManager) SecretHasher {
	return &hmacSecretHasher{km: km}
}

func (h *hmacSecretHasher) Hash(secret string) (string, int, error) {
	key, version, err := h.km.Current(KeyPurposeTokenHash)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hmacSHA256(key, []byte(secret))), version, nil
}

func (h *hmacSecretHasher) Verify(secret, hash string, keyVersion int) (bool, error) {
	key, err := h.km.GetByVersion(KeyPurposeTokenHash, keyVersion)
	if err != nil {
		return false, err // unknown version. treated as invalid
	}

	expected := hex.EncodeToString(hmacSHA256(key, []byte(secret)))
	return hmac.Equal([]byte(hash), []byte(expected)), nil
}
