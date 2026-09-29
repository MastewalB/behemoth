package crypto

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/MastewalB/behemoth/types"
)

type hmacSecretHasher struct{ km types.KeyManager }

func (h *hmacSecretHasher) Hash(secret string) (string, int, error) {
	key, version, err := h.km.Current(types.KeyPurposeTokenHash)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hmacSHA256(key, []byte(secret))), version, nil
}

func (h *hmacSecretHasher) Verify(secret, hash string, keyVersion int) (bool, error) {
	key, err := h.km.GetByVersion(types.KeyPurposeTokenHash, keyVersion)
	if err != nil {
		return false, err // unknown version. treated as invalid
	}

	expected := hex.EncodeToString(hmacSHA256(key, []byte(secret)))
	return hmac.Equal([]byte(hash), []byte(expected)), nil
}
