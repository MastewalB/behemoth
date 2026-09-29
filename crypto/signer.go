package crypto

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/MastewalB/behemoth/types"
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

type HMACSigner struct {
	km      types.KeyManager
	purpose types.KeyPurpose // e.g. KeyPurposeCookieSign
}

func NewSigner(km types.KeyManager, purpose types.KeyPurpose) *HMACSigner {
	return &HMACSigner{km: km, purpose: purpose}
}

func (s *HMACSigner) PrepareSigning() (types.SigningKey, error) {
	key, version, err := s.km.Current(s.purpose) // the ONE fetch for the whole operation
	if err != nil {
		return nil, err
	}

	return &hmacSigningKey{key: key, version: version}, nil
}

func (s *HMACSigner) Sign(payload []byte) ([]byte, int, error) {
	sk, err := s.PrepareSigning()
	if err != nil {
		return nil, 0, err
	}

	return sk.Sign(payload), sk.Version(), nil
}

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
