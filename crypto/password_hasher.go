package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/types"
	"golang.org/x/crypto/argon2"
)

// Params holds the Argon2id configuration.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams provides reasonable interactive defaults
// (≈64 MiB, 3 iterations, parallelism 4).
var DefaultParams = &Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// Argon2idHasher implements PasswordHasher using Argon2id + PHC string format.
type Argon2idHasher struct {
	params *Params
	km     types.KeyManager
}

// NewArgon2idHasher returns a hasher that uses the supplied parameters.
// If params is nil, DefaultParams is used.
func NewArgon2idHasher(params *Params, km types.KeyManager) *Argon2idHasher {
	if params == nil {
		params = DefaultParams
	}
	return &Argon2idHasher{
		params: params,
		km:     km,
	}
}

// Hash produces a PHC-formatted Argon2id hash of the password.
func (h *Argon2idHasher) Hash(password string) (string, error) {
	pepper, version, err := h.km.Current(types.KeyPurposePasswordHash)
	if err != nil {
		return "", fmt.Errorf("get current pepper: %w", err)
	}

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Derive a peppered password (HMAC-SHA256) before Argon2.
	peppered := hmacSHA256(pepper, []byte(password))

	key := argon2.IDKey(
		peppered,
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d,kv=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Iterations,
		h.params.Parallelism,
		version,
		b64Salt,
		b64Key,
	), nil
}

// Verify performs a constant-time comparison of the password against the
// stored PHC hash. It returns false for any malformed hash or mismatch.
func (h *Argon2idHasher) Verify(hash, password string) (bool, error) {
	params, keyVersion, salt, key, err := decodeHash(hash)
	if err != nil {
		return false, err
	}

	pepper, err := h.km.GetByVersion(types.KeyPurposePasswordHash, keyVersion)
	if err != nil {
		return false, err
	}

	peppered := hmacSHA256(pepper, []byte(password))

	otherKey := argon2.IDKey(
		peppered,
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(key, otherKey) == 1, nil
}

// NeedsRehash reports whether the stored hash used weaker Argon2 parameters
// or an older pepper version than the current configuration.
func (h *Argon2idHasher) NeedsRehash(hash string) bool {
	params, keyVersion, _, _, err := decodeHash(hash)
	if err != nil {
		return true
	}

	_, currentVersion, err := h.km.Current(types.KeyPurposePasswordHash)
	if err != nil {
		return true
	}

	return keyVersion < currentVersion ||
		params.Memory < h.params.Memory ||
		params.Iterations < h.params.Iterations ||
		params.Parallelism < h.params.Parallelism ||
		params.KeyLength < h.params.KeyLength
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func decodeHash(encoded string) (params *Params, keyVersion int, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, 0, nil, nil, errors.New("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return nil, 0, nil, nil, errors.New("unsupported algorithm")
	}

	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, 0, nil, nil, err
	}
	if version != argon2.Version {
		return nil, 0, nil, nil, errors.New("incompatible argon2 version")
	}

	params = &Params{}
	// Accept both old format (no kv) and new format (with kv=).
	n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d,kv=%d",
		&params.Memory, &params.Iterations, &params.Parallelism, &keyVersion)
	if err != nil || n != 4 {
		// fallback for hashes created without a key version
		if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
			&params.Memory, &params.Iterations, &params.Parallelism); err != nil {
			return nil, 0, nil, nil, err
		}
		keyVersion = 0 // treat as unversioned / legacy
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, 0, nil, nil, err
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, 0, nil, nil, err
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	return params, keyVersion, salt, key, nil
}
