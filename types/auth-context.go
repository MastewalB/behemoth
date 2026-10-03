package types

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/store"
)

type AuthContext struct {
	DB behemoth.Database
	KV behemoth.KeyValueStorage
	// Store is the data layer plugins use instead of DB. It is a concrete
	// type: store never imports types, so no interface is needed to break
	// an import cycle.
	Store           *store.Store
	Crypto          Crypto
	PasswordOptions PasswordOptions
	SessionManager  SessionManager
	TokenManager    TokenManager
	Dispatcher      Dispatcher
	RateLimiter     RateLimiter
	Telemetry       Telemetry
	Validator       Validator
}
