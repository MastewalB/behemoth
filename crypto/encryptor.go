package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/MastewalB/behemoth/errs"
)

// AESGCMEncryptor is the Encryptor Boot builds: AES-256-GCM under the key
// manager's KeyPurposeEncryptAtRest key. The store seals OAuth tokens and
// the two-factor secrets with it.
type AESGCMEncryptor struct {
	km  KeyManager
	rnd Randomizer
}

// NewEncryptor returns an AESGCMEncryptor that takes its keys from km and
// its nonces from rnd.
func NewEncryptor(km KeyManager, rnd Randomizer) *AESGCMEncryptor {
	return &AESGCMEncryptor{km: km, rnd: rnd}
}

// Encrypt seals plaintext under the current key, bound to associatedData,
// and returns the version of that key. The ciphertext is a random 12-byte
// nonce, then the sealed plaintext and its 16-byte tag; two calls with the
// same plaintext return different ciphertexts. associatedData is
// authenticated by the tag and not part of the ciphertext.
func (e *AESGCMEncryptor) Encrypt(plaintext, associatedData []byte) ([]byte, int, error) {
	key, version, err := e.km.Current(KeyPurposeEncryptAtRest)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, 0, errs.NewSecurityError("AESGCMEncryptor.Encrypt", "aes_gcm_error", err)
	}

	nonce, err := e.rnd.SecureRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, 0, err
	}

	// GCM convention: Nonce is prepended to the ciphertext, so Decrypt
	// only needs (ciphertext, keyVersion), nothing else to store separately.
	sealed := gcm.Seal(nonce, nonce, plaintext, associatedData)
	return sealed, version, nil
}

// Decrypt opens a ciphertext Encrypt returned, with the key of keyVersion
// and the associated data Encrypt was given. A ciphertext shorter than a
// nonce is a security error with the code short_cipher_length, and one that
// does not open (changed, cut, sealed under another version, or bound to
// other associated data) has the code invalid_payload. A version the key
// manager does not hold is its error.
func (e *AESGCMEncryptor) Decrypt(ciphertext []byte, keyVersion int, associatedData []byte) ([]byte, error) {
	key, err := e.km.GetByVersion(KeyPurposeEncryptAtRest, keyVersion)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, errs.NewSecurityError("AESGCMEncryptor.Decrypt", "aes_gcm_error", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errs.NewSecurityError("AESGCMEncryptor.Decrypt", "short_cipher_length", nil)
	}

	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, associatedData)
	if err != nil {
		return nil, errs.NewSecurityError("AESGCMEncryptor.Decrypt", "invalid_payload", err)
	}

	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
