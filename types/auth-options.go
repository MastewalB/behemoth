package types

import (
	"time"

	"github.com/MastewalB/behemoth"
)

// type JWTConfig struct {
// 	Secret        string
// 	Expiry        time.Duration
// 	SigningMethod jwt.SigningMethod
// 	Claims        jwt.Claims
// }

type SessionConfig struct {
	CookieName         string
	ExpiresIn          time.Duration // default 7d
	PendingExpiresIn   time.Duration
	UpdateAge          time.Duration            // default 1d; throttle window for rolling expiration
	FreshAge           time.Duration            // default DefaultFreshAge (15m): how long after a sign-in a session counts as fresh (SessionManager.IsFresh)
	MaxConcurrent      int                      // default 0 (unlimited)
	EvictOldestOnLimit bool                     // false = reject new session creation once MaxConcurrent is reached
	SecondaryStorage   behemoth.KeyValueStorage // nil = DB-only, no cache layer
	CaptureIPAndAgent  bool
	Transport          TokenTransport // default: cookie
}

// var DefaultJWTConfig = JWTConfig{
// 	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
// 	Expiry:        24 * time.Hour,
// 	SigningMethod: jwt.SigningMethodHS256,
// }
