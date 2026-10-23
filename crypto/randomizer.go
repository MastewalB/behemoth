package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/go-behemoth/behemoth/errs"
)

// DefaultRandomizer is the Randomizer Boot builds. Every byte it returns
// comes from crypto/rand.
type DefaultRandomizer struct{}

// NewRandomizer returns a DefaultRandomizer.
func NewRandomizer() *DefaultRandomizer { return &DefaultRandomizer{} }

// SecureRandomString returns n random bytes as unpadded base64url: a string
// of base64.RawURLEncoding.EncodedLen(n) characters, safe in a URL and a
// cookie. n is the number of random bytes, not of characters, and must be
// positive.
func (r *DefaultRandomizer) SecureRandomString(n int) (string, error) {
	b, err := r.SecureRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SecureRandomBytes returns n random bytes. n must be positive: a length of
// zero would be a secret with no entropy, and is an internal error. A failed
// read of crypto/rand is a security error, and no bytes are returned.
func (r *DefaultRandomizer) SecureRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errs.NewInternalError("Randomizer.SecureRandomBytes", fmt.Errorf("asked for %d random bytes", n))
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, errs.NewSecurityError("Randomizer.SecureRandomBytes", "crypto_read_failure", err)
	}

	return b, nil
}
