package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// The token kinds Behemoth names. The plugin that issues tokens of a kind
// declares it in the TokenCatalog.
const (
	TokenKindEmailVerification models.TokenKind = "email_verification"
	TokenKindPasswordReset     models.TokenKind = "password_reset"
	TokenKindMagicLink         models.TokenKind = "magic_link"
	TokenKindOAuthState        models.TokenKind = "oauth_state"
	TokenKindAPIKey            models.TokenKind = "api_key"
)

type TokenBackend string

const (
	TokenBackendDB TokenBackend = "db"
	TokenBackendKV TokenBackend = "kv"
)

type TokenKindDef struct {
	Kind       models.TokenKind
	SingleUse  bool          // password reset/email verification/magic link/oauth state: true. API key: false.
	DefaultTTL time.Duration // 0 = no expiry (API keys)
	Backend    TokenBackend
	Owner      string // plugin name, or "core"
}

type TokenConfig struct {
	TTLOverrides map[models.TokenKind]time.Duration // overrides TokenKindDef.DefaultTTL per kind
}

type TokenCatalog interface {
	Declare(def TokenKindDef) error
	Lookup(kind models.TokenKind) (TokenKindDef, bool)
}

// TokenManager issues and checks tokens of the kinds in the TokenCatalog. It
// stores a token's hash, and the raw value exists only in what Issue returns.
type TokenManager interface {
	// Issue generates a raw token, persists only its hash and returns the raw value
	Issue(ctx context.Context, kind models.TokenKind, subject any, meta behemoth.M) (token *models.Token, rawToken string, err error)

	// Verify checks validity (hash match, not expired, not revoked, not
	// consumed) without side effects. Safe to call repeatedly
	Verify(ctx context.Context, kind models.TokenKind, rawToken string) (*models.Token, error)

	// Consume atomically verifies and marks single-use.
	// Implementations must use a single transactional operation (check-and-invalidate)
	// to avoid usage of the same token be consumed twice concurrently.
	// Returns ErrTokenAlreadyConsumed / ErrTokenExpired / ErrTokenRevoked
	Consume(ctx context.Context, kind models.TokenKind, rawToken string) (*models.Token, error)

	Revoke(ctx context.Context, tokenID string) error
	RevokeAllForSubject(ctx context.Context, kind models.TokenKind, subject any) error

	// ListForSubject returns the tokens of kind issued to subject that can
	// still be used: not revoked, not consumed, not expired. Oldest first.
	// They are records: a raw token can't be recovered from one. A plugin
	// uses it to see what is pending for a user, or to revoke some of a
	// subject's tokens and not all. Like RevokeAllForSubject it is not
	// supported for a kind kept in the key-value storage.
	ListForSubject(ctx context.Context, kind models.TokenKind, subject any) ([]*models.Token, error)
}
