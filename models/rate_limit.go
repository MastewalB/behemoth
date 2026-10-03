package models

import (
	"time"

	"github.com/MastewalB/behemoth"
)

// Canonical names of the rate_limits table and its columns. The key column
// is limit_key, not key: adapters emit column names unquoted, and KEY is a
// reserved word in MySQL and SQL Server.
const (
	RateLimitTable = "rate_limits"

	RateLimitKey       = "limit_key"
	RateLimitCount     = "count"
	RateLimitExpiresAt = "expires_at"
)

var rateLimitColumns = columnSet(RateLimitKey, RateLimitCount, RateLimitExpiresAt)

// RateLimit is one fixed-window counter: Count attempts against Key in the
// window ending at ExpiresAt. The table is only written when rate limiting
// has no KeyValueStorage with a native atomic increment to count in.
type RateLimit struct {
	Key       string    `db:"limit_key"`
	Count     int64     `db:"count"`
	ExpiresAt time.Time `db:"expires_at"`
}

func (r *RateLimit) SchemaName() string     { return RateLimitTable }
func (r *RateLimit) PrimaryKeyName() string { return RateLimitKey }
func (r *RateLimit) PrimaryKeyField() any   { return r.Key }
func (r *RateLimit) New() behemoth.Model    { return &RateLimit{} }

func (r *RateLimit) ToMap() (map[string]any, error) {
	return map[string]any{
		RateLimitKey:       r.Key,
		RateLimitCount:     r.Count,
		RateLimitExpiresAt: r.ExpiresAt,
	}, nil
}

func (r *RateLimit) FromMap(m map[string]any) error {
	r.Key, _ = m[RateLimitKey].(string)
	switch n := m[RateLimitCount].(type) {
	case int64:
		r.Count = n
	case int:
		r.Count = int64(n)
	case int32:
		r.Count = int64(n)
	default:
		r.Count = 0
	}
	r.ExpiresAt, _ = m[RateLimitExpiresAt].(time.Time)
	return nil
}
