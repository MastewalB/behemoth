package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A signature is the HMAC-SHA256 of the payload under the key of the
// signer's purpose. A known secret and payload give the signature another
// implementation computes, for both signers Boot builds. A change to it
// makes every internal JWT fail to verify, and any value signed with the
// cookie signer.
func TestSignerKnownAnswer(t *testing.T) {
	assert.Equal(t, crypto.KeyPurpose("cookie_sign"), crypto.KeyPurposeCookieSign, "the purpose string never changes")
	assert.Equal(t, crypto.KeyPurpose("jwt_sign"), crypto.KeyPurposeJWTSign, "the purpose string never changes")
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)

	for purpose, want := range map[crypto.KeyPurpose]string{
		crypto.KeyPurposeCookieSign: "33cee5affd8facaa35187f16abd5e07855b35d052d6293e9bbb684ca975e75e5",
		crypto.KeyPurposeJWTSign:    "3b343e293909b29ae3b01f0f9ed082f50ab22dccde44f9b4583867d60a062f80",
	} {
		signature, version, err := crypto.NewSigner(km, purpose).Sign([]byte("payload"))
		require.NoError(t, err)
		assert.Equal(t, 1, version)
		assert.Equal(t, want, hex.EncodeToString(signature), purpose)
	}
}

// Verify accepts the signature Sign made of the payload, and nothing else:
// another payload, a signature with any byte changed, cut, or extended, or
// the signature the signer of another purpose made.
func TestSignerVerify(t *testing.T) {
	km, _ := newKeys(t, map[int]string{1: secretV1}, 1)
	cookies := crypto.NewSigner(km, crypto.KeyPurposeCookieSign)
	payload := []byte("session=abc")
	signature, version, err := cookies.Sign(payload)
	require.NoError(t, err)
	require.Len(t, signature, 32)

	ok, err := cookies.Verify(payload, signature, version)
	require.NoError(t, err)
	assert.True(t, ok)

	refuses := func(payload, signature []byte, msgAndArgs ...any) {
		t.Helper()
		ok, err := cookies.Verify(payload, signature, version)
		require.NoError(t, err, msgAndArgs...)
		assert.False(t, ok, msgAndArgs...)
	}
	refuses([]byte("session=abd"), signature, "another payload")
	refuses(nil, signature, "no payload")
	for i := range signature {
		changed := bytes.Clone(signature)
		changed[i] ^= 0x80
		refuses(payload, changed, "byte %d changed", i)
	}
	refuses(payload, signature[:31], "a cut signature")
	refuses(payload, append(bytes.Clone(signature), 0), "a longer signature")
	refuses(payload, nil, "no signature")

	jwtSignature, _, err := crypto.NewSigner(km, crypto.KeyPurposeJWTSign).Sign(payload)
	require.NoError(t, err)
	refuses(payload, jwtSignature, "the JWT signer's signature of the same payload")
}

// A signature verifies with the version Sign returned, also after a
// rotation, and with no other. A version the key manager does not hold is
// the key manager's error, and no match.
func TestSignerKeyVersions(t *testing.T) {
	km, src := newKeys(t, map[int]string{1: secretV1}, 1)
	s := crypto.NewSigner(km, crypto.KeyPurposeCookieSign)
	payload := []byte("payload")
	old, oldVersion, err := s.Sign(payload)
	require.NoError(t, err)

	rotateToV2(src)
	fresh, version, err := s.Sign(payload)
	require.NoError(t, err)
	assert.Equal(t, 2, version, "a new signature is made with the current key")
	assert.NotEqual(t, old, fresh)

	ok, err := s.Verify(payload, old, oldVersion)
	require.NoError(t, err)
	assert.True(t, ok, "a signature made before the rotation still verifies")
	ok, err = s.Verify(payload, old, 2)
	require.NoError(t, err)
	assert.False(t, ok, "with another version's key it does not")

	ok, err = s.Verify(payload, old, 9)
	securityError(t, err, "unknown_key_version")
	assert.False(t, ok)
}

// The key PrepareSigning returns is fixed: after a rotation it still signs
// with the key it was given and reports that key's version, so a token whose
// header names the version gets a signature that version verifies.
func TestPrepareSigningFixesTheKey(t *testing.T) {
	km, src := newKeys(t, map[int]string{1: secretV1}, 1)
	s := crypto.NewSigner(km, crypto.KeyPurposeJWTSign)
	payload := []byte("header.claims")
	want, _, err := s.Sign(payload)
	require.NoError(t, err)

	key, err := s.PrepareSigning()
	require.NoError(t, err)
	rotateToV2(src)

	assert.Equal(t, 1, key.Version())
	assert.Equal(t, want, key.Sign(payload), "the key of version 1, not the current one")
	ok, err := s.Verify(payload, key.Sign(payload), key.Version())
	require.NoError(t, err)
	assert.True(t, ok)

	_, version, err := s.Sign(payload)
	require.NoError(t, err)
	assert.Equal(t, 2, version, "Sign itself takes the current key")
}

// A key manager that fails makes signing and verifying fail.
func TestSignerKeyFailure(t *testing.T) {
	s := crypto.NewSigner(fixedKeys{err: errKeys}, crypto.KeyPurposeCookieSign)
	_, err := s.PrepareSigning()
	assert.ErrorIs(t, err, errKeys)
	signature, _, err := s.Sign([]byte("payload"))
	assert.ErrorIs(t, err, errKeys)
	assert.Nil(t, signature)
	ok, err := s.Verify([]byte("payload"), make([]byte, 32), 1)
	assert.ErrorIs(t, err, errKeys)
	assert.False(t, ok)
}
