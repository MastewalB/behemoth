package crypto_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixtures shared by the tests of the encryptor, the secret hasher, the
// signer, and the polling watcher. secretV1 and secretV2 are in
// jwt_test.go.
//
// The known answers in these tests were computed with Python's standard
// library (hmac, hashlib, an HKDF checked against RFC 5869 test case 3) and
// its cryptography package (AES-GCM), not with the code under test.

// rotatingSource is a WatchableSecretSource whose test rotates the secrets:
// Watch keeps the key manager's callback, and rotate calls it the way a
// watcher reports a change.
type rotatingSource struct {
	crypto.StaticSecretSource
	onUpdate func(secrets map[int]string, current int)
}

func (s *rotatingSource) Watch(_ context.Context, onUpdate func(map[int]string, int)) error {
	s.onUpdate = onUpdate
	return nil
}

func (s *rotatingSource) rotate(secrets map[int]string, current int) { s.onUpdate(secrets, current) }

// newKeys returns a key manager over secrets, current being the current
// version, and the source that rotates it.
func newKeys(t *testing.T, secrets map[int]string, current int) (*crypto.DefaultKeyManager, *rotatingSource) {
	t.Helper()
	src := &rotatingSource{StaticSecretSource: crypto.StaticSecretSource{Secrets: secrets, Current: current}}
	km, err := crypto.NewDefaultKeyManager(context.Background(), crypto.KeyManagerConfig{}, src, nil)
	require.NoError(t, err)
	return km, src
}

// rotateToV2 rotates a key manager built over secretV1 to secretV2, keeping
// version 1.
func rotateToV2(src *rotatingSource) {
	src.rotate(map[int]string{1: secretV1, 2: secretV2}, 2)
}

// fixedKeys is a KeyManager that returns one key for every purpose and
// version, or fails with err.
type fixedKeys struct {
	key []byte
	err error
}

func (k fixedKeys) Current(crypto.KeyPurpose) ([]byte, int, error)      { return k.key, 1, k.err }
func (k fixedKeys) GetByVersion(crypto.KeyPurpose, int) ([]byte, error) { return k.key, k.err }
func (k fixedKeys) CurrentVersion() int                                 { return 1 }
func (k fixedKeys) Versions() []int                                     { return []int{1} }
func (k fixedKeys) RemoveVersion(int) error                             { return nil }

// fixedRandom is a Randomizer that returns b, which must be as long as the
// caller asks for, or fails with err.
type fixedRandom struct {
	b   []byte
	err error
}

func (r fixedRandom) SecureRandomBytes(n int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	if n != len(r.b) {
		return nil, fmt.Errorf("asked for %d bytes, have %d", n, len(r.b))
	}
	return r.b, nil
}

func (r fixedRandom) SecureRandomString(int) (string, error) {
	return "", errors.New("not used")
}

// securityError asserts that err is a security error with code.
func securityError(t *testing.T, err error, code string, msgAndArgs ...any) {
	t.Helper()
	require.Error(t, err, msgAndArgs...)
	assert.True(t, errs.IsCategory(err, errs.CategorySecurity), "want a security error, got %v", err)
	assert.True(t, errs.IsCode(err, code), "want code %q, got %v", code, err)
}

// errKeys is the failure of a key manager.
var errKeys = errors.New("key manager down")
