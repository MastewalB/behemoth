package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2idHasher_HashAndVerify(t *testing.T) {
	cfg := KeyManagerConfig{}
	km, err := NewDefaultKeyManager(t.Context(), cfg, NewSecretSource(nil), tel)
	h := NewArgon2idHasher(nil, km) // uses DefaultParams

	password := "correct horse battery staple"
	hash, err := h.Hash(password)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"))

	ok, err := h.Verify(hash, password)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = h.Verify(hash, "wrong password")
	assert.NoError(t, err)
	assert.False(t, ok)

	ok, err = h.Verify("not-a-hash", password)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestArgon2idHasher_NeedsRehash(t *testing.T) {
	cfg := KeyManagerConfig{}
	km, err := NewDefaultKeyManager(t.Context(), cfg, NewSecretSource(nil), tel)
	strong := NewArgon2idHasher(&Params{
		Memory:      128 * 1024,
		Iterations:  4,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}, km)
	weak := NewArgon2idHasher(&Params{
		Memory:      32 * 1024,
		Iterations:  1,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}, km)

	hash, err := weak.Hash("secret")
	assert.NoError(t, err)

	assert.True(t, strong.NeedsRehash(hash), "weaker params should need rehash")
	assert.False(t, weak.NeedsRehash(hash), "same params should not need rehash")
}

func TestArgon2idHasher_DifferentSalts(t *testing.T) {
	cfg := KeyManagerConfig{}
	km, err := NewDefaultKeyManager(t.Context(), cfg, NewSecretSource(nil), tel)
	h := NewArgon2idHasher(nil, km)
	hash1, err := h.Hash("password")
	assert.NoError(t, err)
	hash2, err := h.Hash("password")
	assert.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "each hash must use a unique salt")
}
