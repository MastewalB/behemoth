package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
)

// TokenKind names what a token is for (email verification, password reset,
// API key, …). The kinds behemoth defines, and the catalog plugins declare
// theirs in, live in package types; types.TokenKind is this type.
type TokenKind string

// Canonical names of the tokens table and its columns — the single source for
// ToMap/FromMap, schema declarations, query conditions and update maps.
const (
	TokenTable = "tokens"

	TokenID         = "id"
	TokenKindColumn = "kind"
	TokenSubject    = "subject"
	TokenLookupHash = "lookup_hash"
	TokenTokenHash  = "token_hash"
	TokenKeyVersion = "key_version"
	TokenMetadata   = "metadata"
	TokenExpiresAt  = "expires_at"
	TokenConsumedAt = "consumed_at"
	TokenRevokedAt  = "revoked_at"
	TokenCreatedAt  = "created_at"
)

// Token is a hashed credential of some kind: the raw value is handed out
// once; only its lookup hash and keyed hash are stored.
// tokenColumns are Token's own columns; any other column FromMap receives is
// a contribution, kept in the Extension.
var tokenColumns = columnSet(TokenID, TokenKindColumn, TokenSubject, TokenLookupHash, TokenTokenHash,
	TokenKeyVersion, TokenMetadata, TokenExpiresAt, TokenConsumedAt, TokenRevokedAt, TokenCreatedAt)

type Token struct {
	Extension
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

func (t *Token) SchemaName() string     { return TokenTable }
func (t *Token) PrimaryKeyName() string { return TokenID }
func (t *Token) PrimaryKeyField() any   { return t.ID }
func (t *Token) New() behemoth.Model    { return &Token{} }

// ToMap stores metadata as JSON text: a map can't be bound as a column value.
func (t *Token) ToMap() (map[string]any, error) {
	var consumedAt, revokedAt, metadata any
	if t.ConsumedAt != nil {
		consumedAt = *t.ConsumedAt
	}
	if t.RevokedAt != nil {
		revokedAt = *t.RevokedAt
	}
	if t.MetadataJSON != nil {
		b, err := json.Marshal(t.MetadataJSON)
		if err != nil {
			return nil, fmt.Errorf("token metadata: %w", err)
		}
		metadata = string(b)
	}
	return t.mergeExtras(map[string]any{
		TokenID:         t.ID,
		TokenKindColumn: string(t.Kind),
		TokenSubject:    t.Subject,
		TokenLookupHash: t.LookupHash,
		TokenTokenHash:  t.TokenHash,
		TokenKeyVersion: t.KeyVersion,
		TokenMetadata:   metadata,
		TokenExpiresAt:  t.ExpiresAt,
		TokenConsumedAt: consumedAt,
		TokenRevokedAt:  revokedAt,
		TokenCreatedAt:  t.CreatedAt,
	}), nil
}

func (t *Token) FromMap(m map[string]any) error {
	t.ID, _ = m[TokenID].(string)
	kind, _ := m[TokenKindColumn].(string)
	t.Kind = TokenKind(kind)
	t.Subject, _ = m[TokenSubject].(string)
	t.LookupHash, _ = m[TokenLookupHash].(string)
	t.TokenHash, _ = m[TokenTokenHash].(string)
	if kv, ok := m[TokenKeyVersion].(int64); ok {
		t.KeyVersion = int(kv)
	} else if kv, ok := m[TokenKeyVersion].(int); ok {
		t.KeyVersion = kv
	}

	// Metadata is JSON text in the database ([]byte from some drivers); an
	// in-memory row (a hook payload) may still hold the map itself.
	t.MetadataJSON = nil
	switch v := m[TokenMetadata].(type) {
	case behemoth.M:
		t.MetadataJSON = v
	case map[string]any:
		t.MetadataJSON = v
	case string:
		if err := json.Unmarshal([]byte(v), &t.MetadataJSON); err != nil {
			return fmt.Errorf("token metadata: %w", err)
		}
	case []byte:
		if err := json.Unmarshal(v, &t.MetadataJSON); err != nil {
			return fmt.Errorf("token metadata: %w", err)
		}
	}

	t.ExpiresAt, _ = m[TokenExpiresAt].(time.Time)
	t.ConsumedAt, t.RevokedAt = nil, nil
	if v, ok := m[TokenConsumedAt].(time.Time); ok {
		t.ConsumedAt = &v
	}
	if v, ok := m[TokenRevokedAt].(time.Time); ok {
		t.RevokedAt = &v
	}
	t.CreatedAt, _ = m[TokenCreatedAt].(time.Time)
	t.collectExtras(m, tokenColumns)
	return nil
}
