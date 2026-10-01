package types

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/MastewalB/behemoth"
)

type Crypto struct {
	Keys       KeyManager
	Random     Randomizer
	Secrets    SecretHasher
	Passwords  PasswordHasher
	CookieSign Signer
	JWTSign    Signer
	AtRest     Encryptor
}

type KeyPurpose string

const (
	KeyPurposePasswordHash  KeyPurpose = "password_hash"
	KeyPurposeTokenHash     KeyPurpose = "token_hash"      // Token/Session hashing (HMAC)
	KeyPurposeCookieSign    KeyPurpose = "cookie_sign"     // HMAC over cookie payloads
	KeyPurposeEncryptAtRest KeyPurpose = "encrypt_at_rest" // TOTP secrets, OAuth tokens
	KeyPurposeJWTSign       KeyPurpose = "jwt_sign"
)

// KeyManager is the interface for managing various cryptographic keys used by the system.
// Implementations of this interface are responsible for key rotation, retrieval, and storage.
type KeyManager interface {

	// Current returns the current active key for a purpose, along with its version number.
	Current(purpose KeyPurpose) (key []byte, version int, err error)

	// GetByVersion looks up a specific historical key - required for verifying
	// or decrypting data signed/encrypted before the most recent rotation.
	GetByVersion(purpose KeyPurpose, version int) (key []byte, err error)

	CurrentVersion() int

	// RemoveVersion removes a key version.
	RemoveVersion(version int) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)

	// Implementations of this method should be constant-time
	Verify(hash, password string) (bool, error)

	// NeedsRehash reports whether an existing hash used weaker parameters than
	// current config. Lets SignIn upgrade a hash after a
	// successful verify, without forcing a mass migration.
	NeedsRehash(hash string) bool
}

// SecretHasher is a simpler interface for hashing and verifying high-entropy secrets (e.g. TOTP secrets, tokens)
// Implementations should use fast functions like SHA256 or HMAC, rather than slow password hashing functions like bcrypt/argon2.
type SecretHasher interface {
	Hash(secret string) (string, int, error)
	Verify(secret, hash string, keyVersion int) (bool, error)
}

// Encryptor is an interface for encrypting and decrypting data at rest.
type Encryptor interface {
	Encrypt(plaintext []byte) (ciphertext []byte, keyVersion int, err error)
	Decrypt(ciphertext []byte, keyVersion int) (plaintext []byte, err error)
}

// SigningKey is a snapshot of key material fixed at the moment it was obtained.
// Calling Version() and Sign() methods stay consistent regardless of KeyManager's status.
// It's useful for operations that need to get the Key version ahead of performing sign.
// (for e.g. to embed "kid" in JWT header but also again to sign the header with payload)
// Independently re-fetching KeyManager.Current() would introduce a risk of a hot rotation in between the calls
// and version and signature mismatch.
type SigningKey interface {
	Version() int
	Sign(payload []byte) []byte
}

type Signer interface {
	Sign(payload []byte) ([]byte, int, error)

	// Implementations of this method should be time consistent
	// MUST not use '==' or bytes.Equal on secret-derived data
	Verify(payload, signature []byte, keyVersion int) (bool, error)

	// PrepareSigning
	PrepareSigning() (SigningKey, error)
}

type JWTKind string

const (
	// JWTInternal: HMAC-signed, internal claims shape
	// Rotation compatible via KeyManager.
	JWTInternal JWTKind = "internal"

	// JWTExternal: Asymmetric (EdDSA/ES256), standard claims served via JWKS endpoints,
	// Intended for for third parties ( API consumers, downstream services) to verify tokens without hitting session db
	JWTExternal JWTKind = "external"
)

type JWTConfig struct {
	Issuer          string
	Audience        map[JWTKind]string
	TTL             map[JWTKind]time.Duration
	ExternalKeyType string

	// JWKSPath is where the public keyset is served. Defaults to the
	// standards convention (RFC 8615 well-known URI) so external verifiers
	// can find it without out-of-band configuration.
	JWKSPath string // default "/.well-known/jwks.json"
}

// JWT Claims according to the official JWT specification.
//
// Custom is used for caller-supplied payloads to avoid possible collisions with the registered claims.
type Claims struct {
	Issuer    string     `json:"iss,omitempty"`
	Audience  string     `json:"aud,omitempty"`
	Subject   string     `json:"sub,omitempty"`
	ExpiresAt time.Time  `json:"exp"`
	IssuedAt  time.Time  `json:"iat"`
	NotBefore time.Time  `json:"nbf"`
	Custom    behemoth.M `json:"custom,omitempty"`
}

type JWTProvider interface {
	Sign(ctx context.Context, kind JWTKind, subject string, custom behemoth.M) (token string, err error)

	// Verify: Verifies a given token and returns the claim data.
	// Algorithm must not be taken from the token header.
	Verify(ctx context.Context, kind JWTKind, token string) (claims *Claims, err error)
}

// JWKKeyPair is persisted model
// asymmetric keypairs don't derive from a
// master secret via HKDF, so they must be generated once and stored.
type JWKKeyPair struct {
	// ID is the "kid", exposed publicly in JWKS and in every token's header
	ID        string            `json:"id"`
	Algorithm string            `json:"alg"` // "EdDSA"
	PublicKey ed25519.PublicKey `json:"public_key"`

	// The PrivateKey encrypted via Encryptor (AES-256-GCM, KeyPurposeAtRest)
	EncryptedPrivateKey []byte `json:"encrypted_pk"`

	// Encryptor's key version, for decrypting EncryptedPrivateKey even after key rotation
	// PrivateKeyVersion identifies which KeyManager-derived
	// encryption key protects it at rest.
	PrivateKeyVersion int `json:"pk_version"`

	// Active: Only one true at a time. Rotate() flips the old one to
	// false without deleting it; a token signed under the previous key
	// must keep verifying until it naturally expires.
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

func (k *JWKKeyPair) SchemaName() string     { return "jwk_keypairs" }
func (k *JWKKeyPair) PrimaryKeyName() string { return "id" }
func (k *JWKKeyPair) PrimaryKeyField() any   { return k.ID }
func (k *JWKKeyPair) New() behemoth.Model    { return &JWKKeyPair{} }

type JWKSStore interface {
	Current(ctx context.Context) (*JWKKeyPair, error)
	ByKid(ctx context.Context, kid string) (*JWKKeyPair, error)
	All(ctx context.Context) ([]*JWKKeyPair, error) // for serving the JWKS endpoint; public keys only

	// Rotate generates a fresh keypair, marks it Active, demoting the previous one
	Rotate(ctx context.Context) (*JWKKeyPair, error)
}

type Randomizer interface {
	SecureRandomString(n int) (string, error) // crypto/rand, base64url

	SecureRandomBytes(n int) ([]byte, error)
}

type CSRFProtector interface {
	IssueToken(sessionID string) string
	ValidateToken(sessionID, submittedToken string) bool
}

type OriginValidator interface {
	IsTrusted(origin string) bool // checks against RouterConfig.TrustedOrigins
}

// SecretSource is the pull-based secret source. Every backend(env, key-management-systems) supports this at minimum.
type SecretSource interface {

	// Load returns the full current state, including every valid secrets
	Load(ctx context.Context) (secrets map[int]string, current int, err error)
}

// WatchableSecretSource is optional contract for sources that can poll secret updates.
// The KeyManager checks if watching is implemented and falls back to basic SecretSource if not.
type WatchableSecretSource interface {
	SecretSource
	Watch(ctx context.Context, onUpdate func(secrets map[int]string, current int)) error
}
