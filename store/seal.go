package store

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/types/cryptotypes"
)

// WithEncryptor encrypts at-rest secrets (OAuth tokens) with e. Without it
// the store refuses to write or read one, rather than storing it in the
// clear.
func WithEncryptor(e cryptotypes.Encryptor) Option { return func(s *Store) { s.encryptor = e } }

// A sealed value is "v<key version>:<base64 ciphertext>". The version
// travels with the ciphertext, so each secret column is decryptable on its
// own: columns of one row may be sealed under different key versions (an
// access token refreshed after a rotation, next to an older refresh token).
const sealPrefix = "v"

func (s *Store) seal(op, plaintext string) (string, error) {
	if s.encryptor == nil {
		return "", errs.NewConfigurationError(op, "storing a secret requires store.WithEncryptor", nil)
	}
	ciphertext, version, err := s.encryptor.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return sealPrefix + strconv.Itoa(version) + ":" + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (s *Store) open(op, sealed string) (string, error) {
	if s.encryptor == nil {
		return "", errs.NewConfigurationError(op, "reading a secret requires store.WithEncryptor", nil)
	}
	version, ciphertext, err := parseSealed(sealed)
	if err != nil {
		return "", errs.NewSecurityError(op, "invalid_sealed_value", err)
	}
	plaintext, err := s.encryptor.Decrypt(ciphertext, version)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Seal encrypts a secret the way the store seals an account's OAuth tokens
// and returns the sealed form described above. It is for a secret a plugin
// keeps outside the accounts table: a column of its own table, or a value in
// a token's metadata. Open reads it back. It is a configuration error when
// the store has no encryptor (WithEncryptor).
func (s *Store) Seal(plaintext string) (string, error) {
	return s.seal("Store.Seal", plaintext)
}

// Open returns the plaintext of a value Seal produced. A value that is not
// in the sealed form is a security error, and so is one the encryptor can't
// decrypt.
func (s *Store) Open(sealed string) (string, error) {
	return s.open("Store.Open", sealed)
}

func parseSealed(sealed string) (version int, ciphertext []byte, err error) {
	head, body, ok := strings.Cut(sealed, ":")
	if !ok || !strings.HasPrefix(head, sealPrefix) {
		return 0, nil, fmt.Errorf("not a sealed value")
	}
	if version, err = strconv.Atoi(strings.TrimPrefix(head, sealPrefix)); err != nil {
		return 0, nil, fmt.Errorf("sealed value key version: %w", err)
	}
	if ciphertext, err = base64.RawStdEncoding.DecodeString(body); err != nil {
		return 0, nil, fmt.Errorf("sealed value ciphertext: %w", err)
	}
	return version, ciphertext, nil
}

// SealedKeyVersion reports the key version a sealed value was encrypted
// under — what a re-encryption sweep after a key rotation selects on.
func SealedKeyVersion(sealed string) (int, error) {
	version, _, err := parseSealed(sealed)
	return version, err
}
