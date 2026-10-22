package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

type hmacSigningKey struct {
	key     []byte
	version int
}

func (k *hmacSigningKey) Version() int { return k.version }
func (k *hmacSigningKey) Sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, k.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

// HMACSigner is the Signer Boot builds: HMAC-SHA256 under the key manager's
// key of one purpose, such as KeyPurposeCookieSign or KeyPurposeJWTSign.
// Signers of different purposes sign with different keys, so a signature
// made for one is refused by the other.
type HMACSigner struct {
	km      KeyManager
	purpose KeyPurpose // e.g. KeyPurposeCookieSign
}

// NewSigner returns an HMACSigner with the keys km holds for purpose.
func NewSigner(km KeyManager, purpose KeyPurpose) *HMACSigner {
	return &HMACSigner{km: km, purpose: purpose}
}

// PrepareSigning returns the current key, fixed: it keeps signing with that
// key and reporting its version after a rotation.
func (s *HMACSigner) PrepareSigning() (SigningKey, error) {
	key, version, err := s.km.Current(s.purpose) // the ONE fetch for the whole operation
	if err != nil {
		return nil, err
	}

	return &hmacSigningKey{key: key, version: version}, nil
}

// Sign returns the 32-byte HMAC-SHA256 of payload under the current key,
// and the key's version.
func (s *HMACSigner) Sign(payload []byte) ([]byte, int, error) {
	sk, err := s.PrepareSigning()
	if err != nil {
		return nil, 0, err
	}

	return sk.Sign(payload), sk.Version(), nil
}

// Verify reports whether signature is the signature of payload under the
// key of keyVersion. It compares in constant time. A version the key
// manager does not hold is its error, and false.
func (s *HMACSigner) Verify(payload, signature []byte, keyVersion int) (bool, error) {
	key, err := s.km.GetByVersion(s.purpose, keyVersion)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, signature), nil
}
