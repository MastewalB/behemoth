package httpapi

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// TokenDelivery is where the session token travels over HTTP, in both
// directions: how a sign-in hands it to the client, and where the client's
// later requests carry it.
//
//	delivery  the sign-in response has it in      a request carries it in
//	cookie    a Set-Cookie header                 the cookie
//	header    the Set-Auth-Token header           Authorization: Bearer <token>
//	body      the JSON body, under "token"        Authorization: Bearer <token>
//	both      the cookie and Set-Auth-Token       either
type TokenDelivery string

const (
	// DeliveryCookie keeps the token in an HttpOnly cookie, which the
	// browser stores and sends by itself and scripts can't read. The
	// default.
	DeliveryCookie TokenDelivery = "cookie"
	// DeliveryHeader returns the token in the SessionTokenHeader response
	// header. The client keeps it and sends it as a bearer token. A browser
	// script on another origin can read the header only if the application
	// exposes it (Access-Control-Expose-Headers).
	DeliveryHeader TokenDelivery = "header"
	// DeliveryBody returns the token in the JSON body of the sign-in
	// response, under SignInTokenKey. It differs from DeliveryHeader in
	// that one respect: the client sends it back the same way, as a bearer
	// token. Nothing is ever read from a request's body.
	DeliveryBody TokenDelivery = "body"
	// DeliveryBoth is the cookie and the header together: a sign-in sets
	// both, and a request may carry either. It is for an application with
	// browser and non-browser clients, or one moving between the two.
	DeliveryBoth TokenDelivery = "both"
)

// ReadsCookie reports whether a request under d is authenticated by a cookie
// the browser attaches by itself. Those are the deliveries a cross-site
// request can abuse, and the ones Boot installs the origin check for.
func (d TokenDelivery) ReadsCookie() bool {
	return d == DeliveryCookie || d == DeliveryBoth
}

// SessionTokenHeader is the response header a sign-in returns the session
// token in under DeliveryHeader and DeliveryBoth. It mirrors Set-Cookie: the
// server sets a credential, and the client stores it.
const SessionTokenHeader = "Set-Auth-Token"

// DefaultSessionCookieName is the name of the session cookie when
// TokenCarrierConfig.CookieName is empty.
const DefaultSessionCookieName = "session_token"

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

// HTTP returns the net/http value of m. A mode that is not one of the three
// is SameSiteLax, the default; TokenCarrierConfig.Validate refuses one.
func (m SameSiteMode) HTTP() http.SameSite {
	switch m {
	case SameSiteStrict:
		return http.SameSiteStrictMode
	case SameSiteNone:
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

// TokenCarrierConfig configures the token carrier: where the session token
// travels over HTTP, and the attributes of the session cookie. It is
// RouterConfig.Carrier. The zero value works: a field left at zero takes the
// default named on it (WithDefaults).
//
// How long a session lasts is the session manager's (SessionConfig). These
// settings are about HTTP only, and a session reached another way does not
// read them.
type TokenCarrierConfig struct {
	// Delivery is where the session token travels: how a sign-in hands it
	// to the client and where a request carries it. Default DeliveryCookie.
	Delivery TokenDelivery
	// CookieName is the name of the session cookie, for the deliveries that
	// use one. Default DefaultSessionCookieName.
	CookieName string
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

// WithDefaults returns c with every field left at zero set to its default.
// NewTokenCarrier applies it, and TokenCarrier.Config returns the result.
func (c TokenCarrierConfig) WithDefaults() TokenCarrierConfig {
	if c.Delivery == "" {
		c.Delivery = DeliveryCookie
	}
	if c.CookieName == "" {
		c.CookieName = DefaultSessionCookieName
	}
	if c.CookieSameSite == "" {
		c.CookieSameSite = SameSiteLax
	}
	return c
}

// Validate reports a setting no default can repair: a Delivery that is not
// one of the TokenDelivery values, a CookieSameSite that is not one of the
// SameSiteMode values, SameSiteNone on a cookie without Secure, or a
// CookieDomain that is not a host name. Boot calls it. A zero field is not
// an error; it takes its default.
func (c TokenCarrierConfig) Validate() error {
	switch c.Delivery {
	case "", DeliveryCookie, DeliveryHeader, DeliveryBody, DeliveryBoth:
	default:
		return fmt.Errorf("RouterConfig.Carrier.Delivery %q is not a known delivery (cookie, header, body, both)", c.Delivery)
	}
	switch c.CookieSameSite {
	case "", SameSiteLax, SameSiteStrict:
	case SameSiteNone:
		if c.CookieInsecure {
			return fmt.Errorf("RouterConfig.Carrier.CookieSameSite %q needs a Secure cookie, and CookieInsecure is set", c.CookieSameSite)
		}
	default:
		return fmt.Errorf("RouterConfig.Carrier.CookieSameSite %q is not a known mode (lax, strict, none)", c.CookieSameSite)
	}
	// A host name only: a scheme, a port or a path would be sent to the
	// browser as part of the attribute, and the cookie would be dropped.
	if d := strings.TrimPrefix(c.CookieDomain, "."); c.CookieDomain != "" && (d == "" || strings.ContainsAny(d, ":/;, \t") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".")) {
		return fmt.Errorf("RouterConfig.Carrier.CookieDomain %q is not a host name, such as example.com", c.CookieDomain)
	}
	return nil
}

// TokenCarrier carries the session token over HTTP: it hands a new token to
// the client, reads it from a request, writes the cookie again when a
// session is extended, and takes the token back when the session has ended.
// Where the token goes is TokenCarrierConfig.Delivery.
//
// It is the HTTP half of a session. The session manager creates, resolves,
// extends and revokes sessions and knows nothing of requests; the
// authentication stage (AuthenticateRequests) and the routes that sign a
// user in or out join the two. Another transport would carry the token its
// own way and call the same manager.
//
// The router builds one from RouterConfig.Carrier and hands it to every
// handler as RequestContext.TokenCarrier. It holds only its settings, so it
// is safe for concurrent use.
type TokenCarrier struct {
	cfg TokenCarrierConfig
}

// NewTokenCarrier returns the carrier of cfg, with its defaults applied. It
// does not validate cfg; Boot calls cfg.Validate first.
func NewTokenCarrier(cfg TokenCarrierConfig) *TokenCarrier {
	return &TokenCarrier{cfg: cfg.WithDefaults()}
}

// Config returns the settings c runs with, defaults applied. A route that
// hands the client a value of its own reads them to deliver it the way the
// session token travels (Delivery), in a cookie that a browser treats like
// the session cookie (CookieSameSite, CookieInsecure). It is a copy:
// changing it changes nothing.
func (c *TokenCarrier) Config() TokenCarrierConfig { return c.cfg }

// Write hands a new session's token to the client the way Delivery says: a
// Set-Cookie header for DeliveryCookie, the SessionTokenHeader response
// header for DeliveryHeader, both for DeliveryBoth. The cookie expires at
// expiresAt, the session's expiry.
//
// For DeliveryBody it writes nothing, because the body is the route's to
// write. It returns true then, and the route puts the token in its JSON
// body. WriteSignIn does both steps, and is what a sign-in route calls; a
// route that calls Write itself has to act on the result.
func (c *TokenCarrier) Write(rctx *RequestContext, rawToken string, expiresAt time.Time) (inBody bool) {
	switch c.cfg.Delivery {
	case DeliveryCookie, DeliveryBoth:
		c.setCookie(rctx, c.sessionCookie(rawToken, expiresAt))
	}
	switch c.cfg.Delivery {
	case DeliveryHeader, DeliveryBoth:
		rctx.Response.SetHeader(SessionTokenHeader, rawToken)
	}
	// The body is the route's to write, so for DeliveryBody the caller is
	// told to put the token there.
	return c.cfg.Delivery == DeliveryBody
}

// Extract reads the token from a request per Delivery: the session cookie,
// the Authorization header ("Bearer <token>"), or either, the header first.
// The header is where a client of DeliveryHeader and of DeliveryBody sends
// it: the two differ only in how the sign-in delivered the token.
func (c *TokenCarrier) Extract(r *http.Request) (string, bool) {
	switch c.cfg.Delivery {
	case DeliveryHeader, DeliveryBody, DeliveryBoth:
		if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && token != "" {
			return token, true
		}
	}
	switch c.cfg.Delivery {
	case DeliveryCookie, DeliveryBoth:
		if cookie, err := r.Cookie(c.cfg.CookieName); err == nil && cookie.Value != "" {
			return cookie.Value, true
		}
	}
	return "", false
}

// Clear takes the token back from the client once the session the request
// presented has ended: a route calls it after it ended its caller's own
// session, such as sign-out, and the authentication stage calls it when it
// finds the session gone. It is the counterpart of Write.
//
// For DeliveryCookie and DeliveryBoth it sets the session cookie again,
// empty and already expired, so that the browser drops it: the cookie is
// HttpOnly, which a script can't remove. It does so for the request that
// presented its token in that cookie. Under DeliveryBoth a request that came
// with a bearer token keeps its cookie, which may be another session's. For
// DeliveryHeader and DeliveryBody it writes nothing, because the client
// holds the token itself and discards it.
//
// It only writes to the response. Ending the session is the session
// manager's job, and a route calls Clear after the revoke has succeeded.
func (c *TokenCarrier) Clear(rctx *RequestContext) {
	if !c.cfg.Delivery.ReadsCookie() {
		return
	}
	// The cookie is removed for the request that presented its token in
	// it. Another cookie is left alone: its session is still live.
	token, ok := c.Extract(rctx.Request)
	if !ok || !c.cookieCarries(rctx.Request, token) {
		return
	}
	// An empty cookie that has already expired makes the browser drop the
	// one it holds. Max-Age says so to current browsers, and the date to
	// those that only read Expires.
	expired := c.sessionCookie("", time.Unix(0, 0))
	expired.MaxAge = -1
	c.setCookie(rctx, expired)
}

// Extend keeps the client's copy of the token in step with a session the
// session manager extended (SessionManager.Touch). A browser drops a cookie
// at the date the cookie was set with, however long the session lasts on
// the server, so for DeliveryCookie and DeliveryBoth it sets the cookie
// again, expiring at expiresAt. It does so only when the request carried
// rawToken in that cookie: under DeliveryBoth a request may present the
// token as a bearer token while its cookie holds another session's. For
// DeliveryHeader and DeliveryBody it writes nothing, because those clients
// keep the token without a date.
//
// It reports whether it wrote the cookie. The response then carries the
// session token, and the caller keeps it out of caches, as the
// authentication stage does with Cache-Control: no-store.
func (c *TokenCarrier) Extend(rctx *RequestContext, rawToken string, expiresAt time.Time) (written bool) {
	// Only a client that sent the token in the cookie depends on the
	// cookie's date.
	if !c.cfg.Delivery.ReadsCookie() || !c.cookieCarries(rctx.Request, rawToken) {
		return false
	}
	c.setCookie(rctx, c.sessionCookie(rawToken, expiresAt))
	return true
}

// sessionCookie is the cookie the session token travels in. Write, Extend
// and Clear build it here, because a browser replaces a cookie only with one
// of the same name, path and domain. HttpOnly and the path are fixed; the
// domain, SameSite and Secure come from the settings.
func (c *TokenCarrier) sessionCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name: c.cfg.CookieName, Value: value, Expires: expires,
		HttpOnly: true, Secure: !c.cfg.CookieInsecure, SameSite: c.cfg.CookieSameSite.HTTP(),
		Path: "/", Domain: strings.TrimPrefix(c.cfg.CookieDomain, "."),
	}
}

// setCookie queues the session cookie on the response, in place of one an
// earlier step of the same request queued. One request can write it twice:
// the authentication stage extends the cookie, and the sign-out route then
// removes it. A response should not set a cookie twice (RFC 6265, section
// 4.1.1), so the last write is the only one sent.
func (c *TokenCarrier) setCookie(rctx *RequestContext, cookie *http.Cookie) {
	headers := rctx.Response.Headers
	headers["Set-Cookie"] = slices.DeleteFunc(headers["Set-Cookie"], func(queued string) bool {
		return strings.HasPrefix(queued, cookie.Name+"=")
	})
	rctx.Response.Cookie(cookie)
}

// cookieCarries reports whether r sent rawToken in the session cookie. It
// is how Extend and Clear know that the cookie on the client is the one they
// are about. Under DeliveryBoth a request may present its token as a bearer
// token, and its cookie, if it has one, may be another session's.
func (c *TokenCarrier) cookieCarries(r *http.Request, rawToken string) bool {
	sent, err := r.Cookie(c.cfg.CookieName)
	return err == nil && sent.Value == rawToken
}
