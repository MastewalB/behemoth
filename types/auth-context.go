package types

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
)

type AuthContext struct {
	// DB is the root database adapter, for a plugin's or the application's
	// own tables. By convention behemoth's tables are written through Store
	// (and sessions and tokens through their managers): the adapter skips
	// the hooks, ids, timestamps, normalization and token sealing they add.
	// See Store.DB and docs/api/core-tables.md.
	DB behemoth.Database
	KV behemoth.KeyValueStorage
	// Store is the data layer plugins use instead of DB. It is a concrete
	// type: store never imports types, so no interface is needed to break
	// an import cycle.
	Store          *store.Store
	Crypto         Crypto
	SessionManager SessionManager
	TokenManager   TokenManager
	Dispatcher     Dispatcher
	RateLimiter    RateLimiter
	// Telemetry is never nil on an AuthContext Boot returns, and neither are
	// its fields. Plugins take their logger from here, usually through
	// telemetry.Named.
	Telemetry *telemetry.Telemetry
}
