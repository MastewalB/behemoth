package models

import (
	"time"

	"github.com/MastewalB/behemoth"
)

// ProviderCredential is the provider id of the account holding a user's
// password; its AccountID is the user's id.
const ProviderCredential = "credential"

// Canonical names of the accounts table and its columns — the single source
// for ToMap/FromMap, schema declarations, query conditions and update maps.
const (
	AccountTable = "accounts"

	AccountID                    = "id"
	AccountUserID                = "user_id"
	AccountProviderID            = "provider_id"
	AccountAccountID             = "account_id"
	AccountPasswordHash          = "password_hash"
	AccountAccessToken           = "access_token"
	AccountRefreshToken          = "refresh_token"
	AccountIDToken               = "id_token"
	AccountAccessTokenExpiresAt  = "access_token_expires_at"
	AccountRefreshTokenExpiresAt = "refresh_token_expires_at"
	AccountScope                 = "scope"
	AccountCreatedAt             = "created_at"
	AccountUpdatedAt             = "updated_at"
)

// accountColumns are Account's own columns; any other column FromMap
// receives is a contribution, kept in the Extension.
var accountColumns = columnSet(AccountID, AccountUserID, AccountProviderID, AccountAccountID,
	AccountPasswordHash, AccountAccessToken, AccountRefreshToken, AccountIDToken,
	AccountAccessTokenExpiresAt, AccountRefreshTokenExpiresAt, AccountScope,
	AccountCreatedAt, AccountUpdatedAt)

// AccountSecretColumns are the columns encrypted at rest. The store seals
// them on the way in and opens them on the way out, so an Account read from
// the store holds plaintext; rows seen by data hooks and by the database hold
// the sealed form.
var AccountSecretColumns = []string{AccountAccessToken, AccountRefreshToken, AccountIDToken}

// Account links a user to one way of signing in: the "credential" provider
// (a password) or an external one ("google", "github", ...). A user has at
// most one account per (ProviderID, AccountID).
type Account struct {
	Extension
	ID         string `db:"id"`
	UserID     string `db:"user_id"`
	ProviderID string `db:"provider_id"` // "credential" | "google" | ...
	AccountID  string `db:"account_id"`  // the provider's id for the user; for "credential", the user id

	PasswordHash string `db:"password_hash" json:"-"` // "credential" only

	AccessToken           string     `db:"access_token" json:"-"`
	RefreshToken          string     `db:"refresh_token" json:"-"`
	IDToken               string     `db:"id_token" json:"-"`
	AccessTokenExpiresAt  *time.Time `db:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `db:"refresh_token_expires_at"`
	Scope                 string     `db:"scope"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Implementations of the Model interface.
func (a *Account) SchemaName() string     { return AccountTable }
func (a *Account) PrimaryKeyName() string { return AccountID }
func (a *Account) PrimaryKeyField() any   { return a.ID }
func (a *Account) New() behemoth.Model    { return &Account{} }

// ToMap stores an absent secret, hash, scope or expiry as NULL.
func (a *Account) ToMap() (map[string]any, error) {
	return a.mergeExtras(map[string]any{
		AccountID:                    a.ID,
		AccountUserID:                a.UserID,
		AccountProviderID:            a.ProviderID,
		AccountAccountID:             a.AccountID,
		AccountPasswordHash:          nullIfEmpty(a.PasswordHash),
		AccountAccessToken:           nullIfEmpty(a.AccessToken),
		AccountRefreshToken:          nullIfEmpty(a.RefreshToken),
		AccountIDToken:               nullIfEmpty(a.IDToken),
		AccountAccessTokenExpiresAt:  nullIfNil(a.AccessTokenExpiresAt),
		AccountRefreshTokenExpiresAt: nullIfNil(a.RefreshTokenExpiresAt),
		AccountScope:                 nullIfEmpty(a.Scope),
		AccountCreatedAt:             a.CreatedAt,
		AccountUpdatedAt:             a.UpdatedAt,
	}), nil
}

func (a *Account) FromMap(m map[string]any) error {
	a.ID, _ = m[AccountID].(string)
	a.UserID, _ = m[AccountUserID].(string)
	a.ProviderID, _ = m[AccountProviderID].(string)
	a.AccountID, _ = m[AccountAccountID].(string)
	a.PasswordHash, _ = m[AccountPasswordHash].(string)
	a.AccessToken, _ = m[AccountAccessToken].(string)
	a.RefreshToken, _ = m[AccountRefreshToken].(string)
	a.IDToken, _ = m[AccountIDToken].(string)
	a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt = nil, nil
	if t, ok := m[AccountAccessTokenExpiresAt].(time.Time); ok {
		a.AccessTokenExpiresAt = &t
	}
	if t, ok := m[AccountRefreshTokenExpiresAt].(time.Time); ok {
		a.RefreshTokenExpiresAt = &t
	}
	a.Scope, _ = m[AccountScope].(string)
	a.CreatedAt, _ = m[AccountCreatedAt].(time.Time)
	a.UpdatedAt, _ = m[AccountUpdatedAt].(time.Time)
	a.collectExtras(m, accountColumns)
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
