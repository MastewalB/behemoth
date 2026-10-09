package types

import (
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
)

// type JWTConfig struct {
// 	Secret        string
// 	Expiry        time.Duration
// 	SigningMethod jwt.SigningMethod
// 	Claims        jwt.Claims
// }

// Defaults of SessionConfig, applied by SessionConfig.WithDefaults to the
// fields left at zero.
const (
	DefaultSessionCookieName       = "session_token"
	DefaultSessionExpiresIn        = 7 * 24 * time.Hour
	DefaultSessionPendingExpiresIn = 10 * time.Minute
	// DefaultFreshAge is how long a session counts as fresh.
	DefaultFreshAge = 15 * time.Minute
)

// SessionConfig configures the session manager. The zero value works: a
// field left at zero takes the default named on it (WithDefaults), or means
// what its comment says zero means.
type SessionConfig struct {
	// CookieName is the name of the session cookie, for the transports that
	// use one. Default DefaultSessionCookieName.
	CookieName string
	// ExpiresIn is how long an active session lasts. Default 7 days.
	ExpiresIn time.Duration
	// PendingExpiresIn is how long a session that waits for a second factor
	// lasts. Default 10 minutes.
	PendingExpiresIn time.Duration
	// UpdateAge turns the rolling expiration on: a session in use is
	// extended by ExpiresIn once less than UpdateAge is left of it. Zero,
	// the default, means a session is not extended and ends ExpiresIn after
	// its sign-in. It has no other default on purpose: a value that is not
	// smaller than ExpiresIn extends the session, with a write, on every
	// request.
	//
	// "In use" means a request through RequireSession, which is where the
	// extension happens. With a cookie transport that response sets the
	// cookie again, so that it expires with the extended session.
	UpdateAge time.Duration
	// FreshAge is how long after a sign-in a session counts as fresh
	// (SessionManager.IsFresh). Default DefaultFreshAge, 15 minutes.
	FreshAge           time.Duration
	MaxConcurrent      int                      // default 0 (unlimited)
	EvictOldestOnLimit bool                     // false = reject new session creation once MaxConcurrent is reached
	SecondaryStorage   behemoth.KeyValueStorage // nil = DB-only, no cache layer
	CaptureIPAndAgent  bool
	// Transport is where the session token travels: how a sign-in hands it
	// to the client and where a request carries it. Default TransportCookie.
	Transport TokenTransport
}

// WithDefaults returns c with every field left at zero set to its default.
// The session manager applies it, so a SessionConfig read anywhere else may
// still hold zeros.
func (c SessionConfig) WithDefaults() SessionConfig {
	if c.CookieName == "" {
		c.CookieName = DefaultSessionCookieName
	}
	if c.ExpiresIn == 0 {
		c.ExpiresIn = DefaultSessionExpiresIn
	}
	if c.PendingExpiresIn == 0 {
		c.PendingExpiresIn = DefaultSessionPendingExpiresIn
	}
	if c.FreshAge == 0 {
		c.FreshAge = DefaultFreshAge
	}
	if c.Transport == "" {
		c.Transport = TransportCookie
	}
	return c
}

// Validate reports a setting no default can repair: a Transport that is not
// one of the TokenTransport values, or a negative duration. Boot calls it.
// A zero field is not an error; it takes its default.
func (c SessionConfig) Validate() error {
	switch c.Transport {
	case "", TransportCookie, TransportHeader, TransportBody, TransportBoth:
	default:
		return fmt.Errorf("SessionConfig.Transport %q is not a known transport (cookie, header, body, both)", c.Transport)
	}
	for name, d := range map[string]time.Duration{
		"ExpiresIn": c.ExpiresIn, "PendingExpiresIn": c.PendingExpiresIn, "UpdateAge": c.UpdateAge, "FreshAge": c.FreshAge,
	} {
		if d < 0 {
			return fmt.Errorf("SessionConfig.%s is negative: %s", name, d)
		}
	}
	return nil
}

// var DefaultJWTConfig = JWTConfig{
// 	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
// 	Expiry:        24 * time.Hour,
// 	SigningMethod: jwt.SigningMethodHS256,
// }
