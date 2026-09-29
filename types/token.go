package types

import (
	"context"
	"encoding/json"
	"time"

	"github.com/MastewalB/behemoth"
)

type TokenKind string

const (
	TokenKindEmailVerification TokenKind = "email_verification"
	TokenKindPasswordReset     TokenKind = "password_reset"
	TokenKindMagicLink         TokenKind = "magic_link"
	TokenKindOAuthState        TokenKind = "oauth_state"
	TokenKindAPIKey            TokenKind = "api_key"
)

type TokenBackend string

const (
	TokenBackendDB TokenBackend = "db"
	TokenBackendKV TokenBackend = "kv"
)

type TokenKindDef struct {
	Kind       TokenKind
	SingleUse  bool          // password reset/email verification/magic link/oauth state: true. API key: false.
	DefaultTTL time.Duration // 0 = no expiry (API keys)
	Backend    TokenBackend
	Owner      string // plugin name, or "core"
}

type TokenConfig struct {
	TTLOverrides map[TokenKind]time.Duration // overrides TokenKindDef.DefaultTTL per kind
}

type TokenCatalog interface {
	Declare(def TokenKindDef) error
	Lookup(kind TokenKind) (TokenKindDef, bool)
}

type Token struct {
	ID           string
	Kind         TokenKind
	Subject      any
	LookupHash   string
	TokenHash    string
	KeyVersion   int
	ExpiresAt    time.Time
	ConsumedAt   *time.Time // nil until used - for SingleUse kinds
	RevokedAt    *time.Time
	MetadataJSON behemoth.M // kind-specific payload: redirect URL for magic link, scopes for API key
	CreatedAt    time.Time
}

func (t *Token) SchemaName() string     { return "tokens" }
func (t *Token) PrimaryKeyName() string { return "id" }
func (t *Token) PrimaryKeyField() any   { return t.ID }
func (t *Token) New() behemoth.Model    { return &Token{} }

func (t *Token) ToMap() (map[string]any, error) {
	var consumedAt, revokedAt any
	if t.ConsumedAt != nil {
		consumedAt = *t.ConsumedAt
	}
	if t.RevokedAt != nil {
		revokedAt = *t.RevokedAt
	}
	return map[string]any{
		"id":          t.ID,
		"kind":        t.Kind,
		"subject":     t.Subject,
		"lookup_hash": t.LookupHash,
		"token_hash":  t.TokenHash,
		"key_version": t.KeyVersion,
		"metadata":    t.MetadataJSON,
		"expires_at":  t.ExpiresAt,
		"consumed_at": consumedAt,
		"revoked_at":  revokedAt,
		"created_at":  t.CreatedAt,
	}, nil
}

func (t *Token) FromMap(m map[string]any) error {
	t.ID, _ = m["id"].(string)
	kind, _ := m["kind"].(string)
	t.Kind = TokenKind(kind)
	t.Subject, _ = m["subject"].(string)
	t.LookupHash, _ = m["lookup_hash"].(string)
	t.TokenHash, _ = m["token_hash"].(string)
	if kv, ok := m["key_version"].(int64); ok {
		t.KeyVersion = int(kv)
	}

	metadata, _ := m["metadata"].(string)

	var meta behemoth.M
	_ = json.Unmarshal([]byte(metadata), &meta)

	t.MetadataJSON = meta

	t.ExpiresAt, _ = m["expires_at"].(time.Time)
	if v, ok := m["consumed_at"].(time.Time); ok {
		t.ConsumedAt = &v
	}
	if v, ok := m["revoked_at"].(time.Time); ok {
		t.RevokedAt = &v
	}
	t.CreatedAt, _ = m["created_at"].(time.Time)
	return nil
}

type TokenManager interface {
	// Issue generates a raw token, persists only its hash and returns the raw value
	Issue(ctx context.Context, kind TokenKind, subject any, meta behemoth.M) (token *Token, rawToken string, err error)

	// Verify checks validity (hash match, not expired, not revoked, not
	// consumed) without side effects. Safe to call repeatedly
	Verify(ctx context.Context, kind TokenKind, rawToken string) (*Token, error)

	// Consume atomically verifies and marks single-use.
	// Implementations must use a single transactional operation (check-and-invalidate)
	// to avoid usage of the same token be consumed twice concurrently.
	// Returns ErrTokenAlreadyConsumed / ErrTokenExpired / ErrTokenRevoked
	Consume(ctx context.Context, kind TokenKind, rawToken string) (*Token, error)

	Revoke(ctx context.Context, tokenID string) error
	RevokeAllForSubject(ctx context.Context, kind TokenKind, subject any) error
}
