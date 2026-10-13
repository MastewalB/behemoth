package types

import (
	"fmt"
	"strings"
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

	// CookieDomain is the session cookie's Domain attribute: a host name
	// such as "example.com", which makes the browser send the cookie to
	// that host and its subdomains. Empty, the default, sets no Domain, and
	// the cookie goes only to the host that set it. Set it when a
	// server-rendered front end on a sibling subdomain has to receive the
	// cookie. Changing it on a running deployment leaves the old cookie in
	// browsers next to the new one, until it expires or the user signs out.
	CookieDomain string
	// CookieSameSite is the session cookie's SameSite attribute. Default
	// SameSiteLax. SameSiteNone is for a front end on another site: the
	// browser then sends the cookie with cross-site requests, and the
	// origin check is the only thing that refuses a forged one, so Boot
	// requires RouterConfig.BaseURL with it.
	CookieSameSite SameSiteMode
	// CookieInsecure leaves the Secure attribute off the session cookie,
	// for development over plain HTTP on a host that is not localhost.
	// False, the default, sets Secure. Validate refuses it together with
	// SameSiteNone, which browsers accept on a Secure cookie only.
	CookieInsecure bool
}

// SameSiteMode is the SameSite attribute of the session cookie: when a
// browser sends the cookie with a request that another site caused.
type SameSiteMode string

const (
	// SameSiteLax sends the cookie with same-site requests and with a
	// cross-site navigation to a GET. The default.
	SameSiteLax SameSiteMode = "lax"
	// SameSiteStrict sends the cookie with same-site requests only. A user
	// who follows a link from another site arrives signed out.
	SameSiteStrict SameSiteMode = "strict"
	// SameSiteNone sends the cookie with every request, for a front end on
	// another site than behemoth.
	SameSiteNone SameSiteMode = "none"
)

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
	if c.CookieSameSite == "" {
		c.CookieSameSite = SameSiteLax
	}
	return c
}

// Validate reports a setting no default can repair: a Transport that is not
// one of the TokenTransport values, a negative duration, a CookieSameSite
// that is not one of the SameSiteMode values, SameSiteNone on a cookie
// without Secure, or a CookieDomain that is not a host name. Boot calls it.
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
	switch c.CookieSameSite {
	case "", SameSiteLax, SameSiteStrict:
	case SameSiteNone:
		if c.CookieInsecure {
			return fmt.Errorf("SessionConfig.CookieSameSite %q needs a Secure cookie, and CookieInsecure is set", c.CookieSameSite)
		}
	default:
		return fmt.Errorf("SessionConfig.CookieSameSite %q is not a known mode (lax, strict, none)", c.CookieSameSite)
	}
	// A host name only: a scheme, a port or a path would be sent to the
	// browser as part of the attribute, and the cookie would be dropped.
	if d := strings.TrimPrefix(c.CookieDomain, "."); c.CookieDomain != "" && (d == "" || strings.ContainsAny(d, ":/;, \t") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".")) {
		return fmt.Errorf("SessionConfig.CookieDomain %q is not a host name, such as example.com", c.CookieDomain)
	}
	return nil
}

// var DefaultJWTConfig = JWTConfig{
// 	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
// 	Expiry:        24 * time.Hour,
// 	SigningMethod: jwt.SigningMethodHS256,
// }
