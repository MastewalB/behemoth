package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/MastewalB/behemoth/errs"
)

type DefaultRandomizer struct{}

func NewRandomizer() *DefaultRandomizer { return &DefaultRandomizer{} }

func (r *DefaultRandomizer) SecureRandomString(n int) (string, error) {
	b, err := r.SecureRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (r *DefaultRandomizer) SecureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, errs.NewSecurityError("Randomizer.SecureRandomString", "crypto_read_failure", err)
	}

	return b, nil
}
