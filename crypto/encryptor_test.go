package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The encryptor is AES-256-GCM under the key of purpose encrypt_at_rest,
// with the nonce before the sealed plaintext and the associated data
// authenticated by the tag. A known secret, nonce, plaintext, and associated
// data give the ciphertext another implementation computes. A change to any
// part of it leaves every value already sealed in a database unreadable.
func TestEncryptorKnownAnswer(t *testing.T) {
	assert.Equal(t, crypto.KeyPurpose("encrypt_at_rest"), crypto.KeyPurposeEncryptAtRest, "the purpose string never changes")
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	key, err := km.GetByVersion(crypto.KeyPurposeEncryptAtRest, 1)
	require.NoError(t, err)
	assert.Equal(t, "0407a4a013632c35680464638f1352b58f715bf8669864611f0230aa8fe12d8b", hex.EncodeToString(key),
		"HKDF-SHA256 of the secret, no salt, the purpose as the info: a 32-byte key, so AES-256")

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	enc := crypto.NewEncryptor(km, fixedRandom{b: nonce})
	ciphertext, version, err := enc.Encrypt([]byte("plaintext"), []byte("context"))
	require.NoError(t, err)
	assert.Equal(t, 1, version)
	assert.Equal(t, "000102030405060708090a0b"+"780b3f2449d5fbc81e"+"cb936fa736375336ebb98f6d9ecc7d31", hex.EncodeToString(ciphertext),
		"the nonce, the sealed plaintext, and the tag over it and the associated data")

	plaintext, err := enc.Decrypt(ciphertext, 1, []byte("context"))
	require.NoError(t, err)
	assert.Equal(t, "plaintext", string(plaintext))
}

// A plaintext of any length comes back from Decrypt. Each ciphertext is a
// fresh 12-byte nonce, the sealed plaintext, and a 16-byte tag, so the same
// plaintext never gives the same ciphertext twice.
func TestEncryptorRoundTrip(t *testing.T) {
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	enc := crypto.NewEncryptor(km, crypto.NewRandomizer())
	binary := make([]byte, 4096)
	_, err := rand.Read(binary)
	require.NoError(t, err)
	aad := []byte("accounts.access_token|a-1")

	for name, plaintext := range map[string][]byte{"empty": {}, "one byte": {'x'}, "text": []byte("otpauth secret"), "4 KiB of binary": binary} {
		t.Run(name, func(t *testing.T) {
			first, version, err := enc.Encrypt(plaintext, aad)
			require.NoError(t, err)
			assert.Equal(t, 1, version)
			assert.Len(t, first, 12+len(plaintext)+16)

			second, _, err := enc.Encrypt(plaintext, aad)
			require.NoError(t, err)
			assert.NotEqual(t, first[:12], second[:12], "each ciphertext has its own nonce")
			assert.NotEqual(t, first, second)

			for _, ciphertext := range [][]byte{first, second} {
				got, err := enc.Decrypt(ciphertext, version, aad)
				require.NoError(t, err)
				assert.Equal(t, string(plaintext), string(got))
			}
		})
	}
}

// A ciphertext that was changed, cut, or extended is refused, whichever
// byte was touched: the nonce, the sealed plaintext, or the tag. One shorter
// than a nonce is refused before it is opened.
func TestEncryptorRefusesAChangedCiphertext(t *testing.T) {
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	enc := crypto.NewEncryptor(km, crypto.NewRandomizer())
	aad := []byte("context")
	ciphertext, version, err := enc.Encrypt([]byte("plaintext"), aad)
	require.NoError(t, err)

	for i := range ciphertext {
		changed := bytes.Clone(ciphertext)
		changed[i] ^= 0x01
		_, err := enc.Decrypt(changed, version, aad)
		securityError(t, err, "invalid_payload", "byte %d changed", i)
	}
	for n := range len(ciphertext) {
		_, err := enc.Decrypt(ciphertext[:n], version, aad)
		if n < 12 {
			securityError(t, err, "short_cipher_length", "cut to %d bytes", n)
		} else {
			securityError(t, err, "invalid_payload", "cut to %d bytes", n)
		}
	}
	_, err = enc.Decrypt(append(bytes.Clone(ciphertext), 0), version, aad)
	securityError(t, err, "invalid_payload", "a byte added")
	_, err = enc.Decrypt(nil, version, aad)
	securityError(t, err, "short_cipher_length", "no ciphertext")
}

// A ciphertext opens with the version Encrypt returned, also after a
// rotation, and with no other. A version the key manager does not hold is
// the key manager's error.
func TestEncryptorKeyVersions(t *testing.T) {
	km, src := newKeys(t, map[int]string{1: secretV1}, 1)
	enc := crypto.NewEncryptor(km, crypto.NewRandomizer())
	old, oldVersion, err := enc.Encrypt([]byte("sealed before the rotation"), nil)
	require.NoError(t, err)
	require.Equal(t, 1, oldVersion)

	rotateToV2(src)
	fresh, version, err := enc.Encrypt([]byte("sealed after the rotation"), nil)
	require.NoError(t, err)
	assert.Equal(t, 2, version, "a new ciphertext is sealed under the current key")

	got, err := enc.Decrypt(old, oldVersion, nil)
	require.NoError(t, err)
	assert.Equal(t, "sealed before the rotation", string(got), "the old key still opens what it sealed")
	got, err = enc.Decrypt(fresh, 2, nil)
	require.NoError(t, err)
	assert.Equal(t, "sealed after the rotation", string(got))

	_, err = enc.Decrypt(old, 2, nil)
	securityError(t, err, "invalid_payload", "another version's key does not open it")
	_, err = enc.Decrypt(fresh, 1, nil)
	securityError(t, err, "invalid_payload")
	_, err = enc.Decrypt(old, 9, nil)
	securityError(t, err, "unknown_key_version")
}

// Encrypt returns nothing when it can't get a key or a nonce, and a key AES
// can't use is a security error on both sides.
func TestEncryptorFailures(t *testing.T) {
	nonce := make([]byte, 12)

	ciphertext, _, err := crypto.NewEncryptor(fixedKeys{err: errKeys}, fixedRandom{b: nonce}).Encrypt([]byte("x"), nil)
	assert.ErrorIs(t, err, errKeys)
	assert.Nil(t, ciphertext)
	_, err = crypto.NewEncryptor(fixedKeys{err: errKeys}, fixedRandom{b: nonce}).Decrypt(make([]byte, 40), 1, nil)
	assert.ErrorIs(t, err, errKeys)

	key := bytes.Repeat([]byte{1}, 32)
	ciphertext, _, err = crypto.NewEncryptor(fixedKeys{key: key}, fixedRandom{err: errKeys}).Encrypt([]byte("x"), nil)
	assert.ErrorIs(t, err, errKeys, "no nonce, no ciphertext")
	assert.Nil(t, ciphertext)

	short := crypto.NewEncryptor(fixedKeys{key: []byte("7 bytes")}, fixedRandom{b: nonce})
	_, _, err = short.Encrypt([]byte("x"), nil)
	securityError(t, err, "aes_gcm_error")
	_, err = short.Decrypt(make([]byte, 40), 1, nil)
	securityError(t, err, "aes_gcm_error")
}

// A ciphertext opens only with the associated data it was sealed with: any
// other, a changed byte of it, or none is refused like a changed
// ciphertext. No associated data and empty associated data are the same.
func TestEncryptorBindsTheAssociatedData(t *testing.T) {
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	enc := crypto.NewEncryptor(km, crypto.NewRandomizer())
	aad := []byte("twofactor.totp_secret|user-1")
	ciphertext, version, err := enc.Encrypt([]byte("JBSWY3DPEHPK3PXP"), aad)
	require.NoError(t, err)

	got, err := enc.Decrypt(ciphertext, version, bytes.Clone(aad))
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", string(got))

	for name, other := range map[string][]byte{
		"another owner":   []byte("twofactor.totp_secret|user-2"),
		"another purpose": []byte("accounts.access_token|user-1"),
		"cut":             aad[:len(aad)-1],
		"extended":        append(bytes.Clone(aad), '0'),
		"none":            nil,
	} {
		_, err := enc.Decrypt(ciphertext, version, other)
		securityError(t, err, "invalid_payload", name)
	}
	for i := range aad {
		changed := bytes.Clone(aad)
		changed[i] ^= 0x01
		_, err := enc.Decrypt(ciphertext, version, changed)
		securityError(t, err, "invalid_payload", "byte %d of the associated data changed", i)
	}

	unbound, _, err := enc.Encrypt([]byte("x"), nil)
	require.NoError(t, err)
	got, err = enc.Decrypt(unbound, version, []byte{})
	require.NoError(t, err)
	assert.Equal(t, "x", string(got))
	got, err = enc.Decrypt(unbound, version, []byte("user"))
	securityError(t, err, "invalid_payload")
}
