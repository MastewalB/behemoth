// Package cryptotypes holds behemoth's cryptography contracts: the interfaces
// the crypto package implements and everything else consumes.
//
// It sits below the types package, which re-exports every name here
// (types.Encryptor is cryptotypes.Encryptor), so packages types itself
// imports — store — can use the same definitions. It must never import
// github.com/MastewalB/behemoth/types.
package cryptotypes

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
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
	// KeyPurposeJWTExternal derives the Ed25519 seed of the key that signs
	// external JWTs, one per secret version. It must never change: every
	// external key, and every token issued with one, depends on it
	// (ADR-0002).
	KeyPurposeJWTExternal KeyPurpose = "jwt_external"
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

	// Versions returns the versions of the secrets the manager holds, in
	// ascending order. Every one of them can still verify or decrypt what
	// it signed or encrypted.
	Versions() []int

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

	// JWTExternal: EdDSA-signed with a key of an ExternalKeySet, for other
	// services to verify with the published keys, without a call to
	// behemoth.
	JWTExternal JWTKind = "external"
)

type JWTConfig struct {
	// Issuer is the iss of every token, and what Verify expects.
	Issuer string
	// Audiences are, per kind, the audiences a token may be issued for. The
	// first is the one a token gets when its request names none. Verify
	// accepts a token whose aud names any of them.
	Audiences map[JWTKind][]string
	// TTL is, per kind, how long a token is valid.
	TTL map[JWTKind]time.Duration

	// JWKSPath is where the public keyset is served. Defaults to the
	// standards convention (RFC 8615 well-known URI) so external verifiers
	// can find it without out-of-band configuration.
	JWKSPath string // default "/.well-known/jwks.json"
}

// DefaultJWTTTL is how long a token is valid when JWTConfig.TTL names no
// lifetime for its kind. It is also the longest a session token stays valid
// after its session ended.
const DefaultJWTTTL = 15 * time.Minute

// DefaultJWKSPath is where the key set is served when JWTConfig.JWKSPath is
// empty: the well-known URI of RFC 8615.
const DefaultJWKSPath = "/.well-known/jwks.json"

// WithDefaults returns c with every field left at zero set to its default:
// DefaultJWTTTL for each kind, and DefaultJWKSPath.
func (c JWTConfig) WithDefaults() JWTConfig {
	ttl := make(map[JWTKind]time.Duration, 2)
	for kind, d := range c.TTL {
		ttl[kind] = d
	}
	for _, kind := range []JWTKind{JWTInternal, JWTExternal} {
		if ttl[kind] == 0 {
			ttl[kind] = DefaultJWTTTL
		}
	}
	c.TTL = ttl
	if c.JWKSPath == "" {
		c.JWKSPath = DefaultJWKSPath
	}
	return c
}

// ExternalEnabled reports whether external tokens are on: c names at least
// one external audience.
func (c JWTConfig) ExternalEnabled() bool { return len(c.Audiences[JWTExternal]) > 0 }

// Validate reports what in c can't work: a negative lifetime, an empty
// audience, external tokens without an issuer, and a key set path that is
// not absolute.
func (c JWTConfig) Validate() error {
	for kind, d := range c.TTL {
		if d < 0 {
			return fmt.Errorf("JWTConfig.TTL[%s] is negative: %s", kind, d)
		}
	}
	for kind, audiences := range c.Audiences {
		for i, a := range audiences {
			if a == "" {
				return fmt.Errorf("JWTConfig.Audiences[%s][%d] is empty", kind, i)
			}
		}
	}
	if c.ExternalEnabled() && c.Issuer == "" {
		return errors.New("JWTConfig.Issuer is empty; external tokens need an issuer, which verifiers check")
	}
	if c.JWKSPath != "" && !strings.HasPrefix(c.JWKSPath, "/") {
		return fmt.Errorf("JWTConfig.JWKSPath %q is not an absolute path", c.JWKSPath)
	}
	return nil
}

// JWTRequest is what a token is issued for.
type JWTRequest struct {
	// Subject is the sub claim: who the token is about. Required.
	Subject string
	// Audience is the aud claim. It is one of JWTConfig.Audiences of the
	// kind, and empty means the first of them.
	Audience string
	// SessionID is the sid claim, the session the token was issued for.
	// Empty means none.
	SessionID string
	// Custom holds claims of the caller's own. They travel under "custom",
	// so that none can stand in for a registered claim.
	Custom behemoth.M
}

// Claims are the claims of a verified token.
type Claims struct {
	Issuer    string
	Audience  string // the configured audience the token named
	Subject   string
	SessionID string // sid
	ID        string // jti, a random id of the token
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Custom    behemoth.M
}

type JWTProvider interface {
	// Sign issues a token of kind for req.
	Sign(ctx context.Context, kind JWTKind, req JWTRequest) (token string, err error)

	// Verify: Verifies a given token and returns the claim data.
	// Algorithm must not be taken from the token header.
	Verify(ctx context.Context, kind JWTKind, token string) (claims *Claims, err error)
}

// ExternalKeySet holds the keys of external JWTs: the one new tokens are
// signed with, and every one a verifier may still need. It signs, and never
// hands out a private key, so that a key held by a KMS or an HSM can
// implement it (ADR-0002).
type ExternalKeySet interface {
	// CurrentKey returns the key new tokens are signed with, fixed for one
	// token: its id and algorithm go into the header, which is signed with
	// the claims.
	CurrentKey(ctx context.Context) (ExternalSigningKey, error)
	// PublicKey returns the key kid names, to verify a token with. An
	// unknown kid is a refused token: a CategoryToken error with
	// ErrorCodeJWTUnknownKey.
	PublicKey(ctx context.Context, kid string) (PublishedKey, error)
	// PublicKeys returns every key a verifier may still need, to publish.
	PublicKeys(ctx context.Context) ([]PublishedKey, error)
}

// ExternalSigningKey is one key of an ExternalKeySet, ready to sign.
type ExternalSigningKey interface {
	KID() string
	// Algorithm is the JWS algorithm the key signs with, such as "EdDSA".
	Algorithm() string
	Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// PublishedKey is the public half of a key of an ExternalKeySet.
type PublishedKey struct {
	KID       string
	Algorithm string
	// Key is an ed25519.PublicKey for EdDSA.
	Key crypto.PublicKey
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
