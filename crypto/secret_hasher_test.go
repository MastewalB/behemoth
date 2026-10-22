package crypto_test

import (
	"regexp"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hash of a secret is the HMAC-SHA256 of the secret under the key of
// purpose token_hash, as lowercase hex. A known secret gives the hash
// another implementation computes. A change to it makes every stored token,
// session, code, and recovery code fail to verify.
func TestSecretHasherKnownAnswer(t *testing.T) {
	assert.Equal(t, crypto.KeyPurpose("token_hash"), crypto.KeyPurposeTokenHash, "the purpose string never changes")
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	h := crypto.NewSecretHasher(km)

	hash, version, err := h.Hash("secret-token")
	require.NoError(t, err)
	assert.Equal(t, 1, version)
	assert.Equal(t, "4a6eb9973397ef311209ce964863ba41dc1f3cdc6912cff0727b33c1570ccc29", hash)

	again, _, err := h.Hash("secret-token")
	require.NoError(t, err)
	assert.Equal(t, hash, again, "the same secret has the same hash under one version")
	empty, _, err := h.Hash("")
	require.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}$`), empty, "an empty secret is hashed too")
}

// Verify accepts the secret a hash was made of, and nothing else: another
// secret, or a hash with one character changed, cut, or extended.
func TestSecretHasherVerify(t *testing.T) {
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	h := crypto.NewSecretHasher(km)
	hash, version, err := h.Hash("secret-token")
	require.NoError(t, err)

	ok, err := h.Verify("secret-token", hash, version)
	require.NoError(t, err)
	assert.True(t, ok)

	refused := map[string][2]string{
		"another secret":         {"secret-tokeN", hash},
		"an empty secret":        {"", hash},
		"the first hex changed":  {"secret-token", flipHex(hash, 0)},
		"the last hex changed":   {"secret-token", flipHex(hash, len(hash)-1)},
		"a cut hash":             {"secret-token", hash[:len(hash)-2]},
		"a longer hash":          {"secret-token", hash + "00"},
		"an empty hash":          {"secret-token", ""},
		"the hash as the secret": {hash, hash},
	}
	for name, c := range refused {
		ok, err := h.Verify(c[0], c[1], version)
		require.NoError(t, err, name)
		assert.False(t, ok, name)
	}
}

// A hash verifies with the version Hash returned, also after a rotation,
// and with no other. A version the key manager does not hold is the key
// manager's error, and no match.
func TestSecretHasherKeyVersions(t *testing.T) {
	km, src := newKeys(t, map[int]string{1: secretV1}, 1)
	h := crypto.NewSecretHasher(km)
	old, oldVersion, err := h.Hash("secret-token")
	require.NoError(t, err)

	rotateToV2(src)
	fresh, version, err := h.Hash("secret-token")
	require.NoError(t, err)
	assert.Equal(t, 2, version, "a new hash is made with the current key")
	assert.NotEqual(t, old, fresh, "each version has its own key")

	ok, err := h.Verify("secret-token", old, oldVersion)
	require.NoError(t, err)
	assert.True(t, ok, "a hash made before the rotation still verifies")
	ok, err = h.Verify("secret-token", old, 2)
	require.NoError(t, err)
	assert.False(t, ok, "with another version's key it does not")

	ok, err = h.Verify("secret-token", old, 9)
	securityError(t, err, "unknown_key_version")
	assert.False(t, ok)
}

// A key manager that fails makes Hash and Verify fail.
func TestSecretHasherKeyFailure(t *testing.T) {
	h := crypto.NewSecretHasher(fixedKeys{err: errKeys})
	hash, _, err := h.Hash("secret-token")
	assert.ErrorIs(t, err, errKeys)
	assert.Empty(t, hash)
	ok, err := h.Verify("secret-token", "00", 1)
	assert.ErrorIs(t, err, errKeys)
	assert.False(t, ok)
}

// flipHex returns hash with the hex digit at i replaced by another one.
func flipHex(hash string, i int) string {
	replacement := byte('0')
	if hash[i] == '0' {
		replacement = '1'
	}
	return hash[:i] + string(replacement) + hash[i+1:]
}
