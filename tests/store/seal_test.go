package store_test

import (
	"errors"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seal and Open are the store's sealing for a secret a plugin keeps outside
// the accounts table: the same form, key version included, and the same
// refusal without an encryptor.
func TestStoreSealAndOpen(t *testing.T) {
	st := store.New(nil, store.WithEncryptor(testCrypto(t).AtRest))
	binding := store.SealBinding{Purpose: "test.secret", Owner: "user-1"}

	sealed, err := st.Seal("s3cret-value", binding)
	require.NoError(t, err)
	assert.NotContains(t, sealed, "s3cret-value")
	version, err := store.SealedKeyVersion(sealed)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "the key version travels with the ciphertext")

	plaintext, err := st.Open(sealed, binding)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", plaintext)

	again, err := st.Seal("s3cret-value", binding)
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "sealing the same value twice gives two ciphertexts")

	_, err = st.Open("s3cret-value", binding)
	assert.True(t, errs.IsCode(err, "invalid_sealed_value"), "a value that is not sealed is refused: %v", err)

	bare := store.New(nil)
	_, err = bare.Seal("s3cret-value", binding)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "no encryptor: %v", err)
	_, err = bare.Open(sealed, binding)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "no encryptor: %v", err)
}

// A sealed value opens only with the binding it was sealed with: copied to
// another owner, or read as another kind of secret, it is refused as a
// changed ciphertext is. The fields are encoded with their lengths, so
// moving a character from one to the other is another binding too.
func TestSealIsBoundToItsOwnerAndPurpose(t *testing.T) {
	st := store.New(nil, store.WithEncryptor(testCrypto(t).AtRest))
	binding := store.SealBinding{Purpose: "twofactor.totp_secret", Owner: "user-1"}
	sealed, err := st.Seal("JBSWY3DPEHPK3PXP", binding)
	require.NoError(t, err)

	for name, other := range map[string]store.SealBinding{
		"another owner":                    {Purpose: "twofactor.totp_secret", Owner: "user-2"},
		"another purpose":                  {Purpose: "accounts.access_token", Owner: "user-1"},
		"a character moved between fields": {Purpose: "twofactor.totp_secretu", Owner: "ser-1"},
	} {
		_, err := st.Open(sealed, other)
		assert.True(t, errs.IsCode(err, "invalid_payload"), "%s: %v", name, err)
	}

	for name, incomplete := range map[string]store.SealBinding{
		"no purpose": {Owner: "user-1"},
		"no owner":   {Purpose: "twofactor.totp_secret"},
		"nothing":    {},
	} {
		_, err := st.Seal("x", incomplete)
		assert.True(t, errs.IsCategory(err, errs.CategoryInternal), "%s: Seal = %v", name, err)
		_, err = st.Open(sealed, incomplete)
		assert.True(t, errs.IsCategory(err, errs.CategoryInternal), "%s: Open = %v", name, err)
	}
}

// The sealed form of a known secret, nonce, value, and binding is the one
// computed with Python's cryptography package, with the binding encoded as
// "behemoth.seal.v1", then the purpose and the owner, each after its length
// as four big-endian bytes. A change to the encoding leaves every sealed
// value unreadable.
func TestSealKnownAnswer(t *testing.T) {
	suite := testCrypto(t)
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	st := store.New(nil, store.WithEncryptor(crypto.NewEncryptor(suite.Keys, fixedNonce(nonce))))
	binding := store.SealBinding{Purpose: "test.secret", Owner: "user-1"}

	sealed, err := st.Seal("s3cret-value", binding)
	require.NoError(t, err)
	assert.Equal(t, "v1:AAECAwQFBgcICQoLm73jUdIMVdlEsIv1jCb3UBaAQIKJEcglIHDiBw", sealed)

	opened, err := store.New(nil, store.WithEncryptor(suite.AtRest)).Open(sealed, binding)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", opened)
}

// fixedNonce is a Randomizer that returns the same bytes every time.
type fixedNonce []byte

func (n fixedNonce) SecureRandomBytes(size int) ([]byte, error) {
	if size != len(n) {
		return nil, errors.New("fixedNonce: unexpected size")
	}
	return n, nil
}

func (n fixedNonce) SecureRandomString(int) (string, error) {
	return "", errors.New("fixedNonce: not used")
}
