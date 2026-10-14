package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
)

type AESGCMEncryptor struct {
	km  types.KeyManager
	rnd types.Randomizer
}

func NewEncryptor(km types.KeyManager, rnd types.Randomizer) *AESGCMEncryptor {
	return &AESGCMEncryptor{km: km, rnd: rnd}
}

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, int, error) {
	key, version, err := e.km.Current(types.KeyPurposeEncryptAtRest)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, 0, behemotherr.NewSecurityError("AESGCMEncryptor.Encrypt", "aes_gcm_error", err)
	}

	nonce, err := e.rnd.SecureRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, 0, err
	}

	// GCM convention: Nonce is prepended to the ciphertext, so Decrypt
	// only needs (ciphertext, keyVersion), nothing else to store separately.
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, version, nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext []byte, keyVersion int) ([]byte, error) {
	key, err := e.km.GetByVersion(types.KeyPurposeEncryptAtRest, keyVersion)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, behemotherr.NewSecurityError("AESGCMEncryptor.Decrypt", "short_cipher_length", nil)
	}

	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, behemotherr.NewSecurityError("AESGCMEncryptor.Decrypt", "invalid_payload", err)
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
