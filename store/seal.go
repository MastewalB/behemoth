package store

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/errs"
)

// WithEncryptor encrypts at-rest secrets (OAuth tokens) with e. Without it
// the store refuses to write or read one, rather than storing it in the
// clear.
func WithEncryptor(e crypto.Encryptor) Option { return func(s *Store) { s.encryptor = e } }

// A sealed value is "v<key version>:<base64 ciphertext>". The version
// travels with the ciphertext, so each secret column is decryptable on its
// own: columns of one row may be sealed under different key versions (an
// access token refreshed after a rotation, next to an older refresh token).
const sealPrefix = "v"

// SealBinding says what a sealed value is and what it belongs to. Seal binds
// the value to it, and Open opens the value only with the same binding, so a
// value copied into another user's row, or used as another kind of secret,
// does not open. Both fields are required.
//
// The binding is not stored with the value: the code that opens it names it
// again, from the row it read.
type SealBinding struct {
	// Purpose names what the value is, such as "accounts.access_token" or
	// "twofactor.totp_secret". A plugin starts its purposes with its name.
	Purpose string
	// Owner names what the value belongs to, such as the id of its account
	// or its user. It must not change for as long as the value is stored.
	Owner string
}

// sealLabel starts the associated data of every sealed value. It names the
// encoding, so that another one can't produce the same bytes.
const sealLabel = "behemoth.seal.v1"

// associatedData encodes b for the encryptor: the label, then each field
// with its length before it, so that two different bindings never give the
// same bytes ("a.b" + "c" and "a" + "b.c" differ).
func (b SealBinding) associatedData() []byte {
	data := make([]byte, 0, len(sealLabel)+8+len(b.Purpose)+len(b.Owner))
	data = append(data, sealLabel...)
	for _, field := range []string{b.Purpose, b.Owner} {
		data = binary.BigEndian.AppendUint32(data, uint32(len(field)))
		data = append(data, field...)
	}
	return data
}

func (b SealBinding) check(op string) error {
	if b.Purpose == "" || b.Owner == "" {
		return errs.NewInternalError(op, fmt.Errorf("a sealed value needs a purpose and an owner, got %+v", b))
	}
	return nil
}

func (s *Store) seal(op, plaintext string, binding SealBinding) (string, error) {
	if s.encryptor == nil {
		return "", errs.NewConfigurationError(op, "storing a secret requires store.WithEncryptor", nil)
	}
	if err := binding.check(op); err != nil {
		return "", err
	}
	ciphertext, version, err := s.encryptor.Encrypt([]byte(plaintext), binding.associatedData())
	if err != nil {
		return "", err
	}
	return sealPrefix + strconv.Itoa(version) + ":" + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (s *Store) open(op, sealed string, binding SealBinding) (string, error) {
	if s.encryptor == nil {
		return "", errs.NewConfigurationError(op, "reading a secret requires store.WithEncryptor", nil)
	}
	if err := binding.check(op); err != nil {
		return "", err
	}
	version, ciphertext, err := parseSealed(sealed)
	if err != nil {
		return "", errs.NewSecurityError(op, "invalid_sealed_value", err)
	}
	plaintext, err := s.encryptor.Decrypt(ciphertext, version, binding.associatedData())
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Seal encrypts a secret the way the store seals an account's OAuth tokens,
// bound to binding, and returns the sealed form described above. It is for
// a secret a plugin keeps outside the accounts table: a column of its own
// table, or a value in a token's metadata. Open reads it back with the same
// binding. It is a configuration error when the store has no encryptor
// (WithEncryptor), and an internal error when binding lacks a field.
func (s *Store) Seal(plaintext string, binding SealBinding) (string, error) {
	return s.seal("Store.Seal", plaintext, binding)
}

// Open returns the plaintext of a value Seal produced with binding. A value
// that is not in the sealed form is a security error with the code
// invalid_sealed_value. One the encryptor can't decrypt, because it was
// changed or sealed with another binding, is a security error with the code
// invalid_payload.
func (s *Store) Open(sealed string, binding SealBinding) (string, error) {
	return s.open("Store.Open", sealed, binding)
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
