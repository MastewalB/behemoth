package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// TokenKind is models.TokenKind: the token model lives in package models so
// the store (which can't import types) can persist it.
type TokenKind = models.TokenKind

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

// Token is models.Token; see TokenKind.
type Token = models.Token

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
