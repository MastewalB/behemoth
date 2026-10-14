package store_test

import (
	"testing"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seal and Open are the store's sealing for a secret a plugin keeps outside
// the accounts table: the same form, key version included, and the same
// refusal without an encryptor.
func TestStoreSealAndOpen(t *testing.T) {
	st := store.New(nil, store.WithEncryptor(testCrypto(t).AtRest))

	sealed, err := st.Seal("s3cret-value")
	require.NoError(t, err)
	assert.NotContains(t, sealed, "s3cret-value")
	version, err := store.SealedKeyVersion(sealed)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "the key version travels with the ciphertext")

	plaintext, err := st.Open(sealed)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", plaintext)

	again, err := st.Seal("s3cret-value")
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "sealing the same value twice gives two ciphertexts")

	_, err = st.Open("s3cret-value")
	assert.True(t, behemotherr.Is(err, behemotherr.CategorySecurity), "a value that is not sealed is refused: %v", err)

	bare := store.New(nil)
	_, err = bare.Seal("s3cret-value")
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "no encryptor: %v", err)
	_, err = bare.Open(sealed)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "no encryptor: %v", err)
}
