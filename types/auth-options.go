package types

import (
	"time"

	"github.com/MastewalB/behemoth"
)

type PasswordOptions struct {
	PasswordHasher PasswordHasher
	HashCost       int
	MinLength      int
	MaxLength      int
}

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
	FreshAge           time.Duration            // default 15m; step-up re-auth window
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

var DefaultPasswordConfig = PasswordOptions{
	HashCost: 10,
}
