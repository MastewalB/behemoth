package crypto

import (
	"context"
	"crypto/ed25519"
	"slices"
	"strconv"

	"github.com/go-behemoth/behemoth/errs"
)

// derivedKeySet is the ExternalKeySet whose keys are derived from the master
// secret (ADR-0002): one Ed25519 key per secret version, whose seed is the
// key manager's key of purpose jwt_external for that version. The kid is
// the version, as a decimal string. Nothing is stored: every replica derives
// the same keys, and a rotation of the master secret rotates them.
type derivedKeySet struct {
	km KeyManager
}

// NewDerivedKeySet returns the key set of external JWTs derived from km's
// secrets. It publishes a key for every version km holds, so a token stays
// verifiable as long as its version stays in the secret source.
func NewDerivedKeySet(km KeyManager) ExternalKeySet {
	return &derivedKeySet{km: km}
}

// algEdDSA is the JWS algorithm of every derived key.
const algEdDSA = "EdDSA"

// CurrentKey implements [ExternalKeySet]. The seed and its version
// come from one call, so a rotation can't land between them.
func (s *derivedKeySet) CurrentKey(context.Context) (ExternalSigningKey, error) {
	seed, version, err := s.km.Current(KeyPurposeJWTExternal)
	if err != nil {
		return nil, err
	}
	// The HKDF output is the seed as it is: any 32 bytes are an Ed25519
	// seed (RFC 8032, section 5.1.5). A step in between would change every
	// key.
	return &derivedSigningKey{kid: strconv.Itoa(version), key: ed25519.NewKeyFromSeed(seed)}, nil
}

// PublicKey implements [ExternalKeySet]. A kid that is not the version
// of a secret the manager holds is a refused token.
func (s *derivedKeySet) PublicKey(_ context.Context, kid string) (PublishedKey, error) {
	const op = "ExternalKeySet.PublicKey"
	version, err := strconv.Atoi(kid)
	if err != nil || strconv.Itoa(version) != kid || !slices.Contains(s.km.Versions(), version) {
		return PublishedKey{}, errs.NewJWTError(op, errs.CodeJWTUnknownKey, err)
	}
	return s.publicKey(version)
}

// PublicKeys implements [ExternalKeySet], in ascending versions.
func (s *derivedKeySet) PublicKeys(context.Context) ([]PublishedKey, error) {
	versions := s.km.Versions()
	keys := make([]PublishedKey, 0, len(versions))
	for _, version := range versions {
		key, err := s.publicKey(version)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *derivedKeySet) publicKey(version int) (PublishedKey, error) {
	seed, err := s.km.GetByVersion(KeyPurposeJWTExternal, version)
	if err != nil {
		return PublishedKey{}, err
	}
	return PublishedKey{
		KID: strconv.Itoa(version), Algorithm: algEdDSA,
		Key: ed25519.NewKeyFromSeed(seed).Public(),
	}, nil
}

type derivedSigningKey struct {
	kid string
	key ed25519.PrivateKey
}

func (k *derivedSigningKey) KID() string       { return k.kid }
func (k *derivedSigningKey) Algorithm() string { return algEdDSA }
func (k *derivedSigningKey) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(k.key, payload), nil
}
