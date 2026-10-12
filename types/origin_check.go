package types

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
)

// The reasons an OriginCheck refuses a request with. They are the "reason"
// attribute of telemetry.MetricOriginRefused and part of the error's
// internal message. A client receives behemotherr.ErrorCodeUntrustedOrigin
// for each of them.
const (
	OriginRefusedNull      = "null_origin"      // Origin: null, from a sandboxed frame or a file
	OriginRefusedMalformed = "malformed_origin" // Origin is not an origin, or is sent more than once
	OriginRefusedUntrusted = "untrusted_origin" // Origin is neither behemoth's own nor a trusted one
	OriginRefusedCrossSite = "cross_site"       // no Origin, and Sec-Fetch-Site is not same-origin or none
)

// OriginCheck protects cookie-authenticated routes from cross-site request
// forgery: it refuses a state-changing request that a browser sent from a
// page of another origin. Boot builds one from RouterConfig.BaseURL and
// RouterConfig.TrustedOrigins, and puts its Middleware in front of every
// behemoth route when SessionConfig.Transport reads a cookie.
//
// It looks at the request's headers only. It reads no cookie and no session,
// so it covers sign-in and sign-up like the routes behind a session.
//
// Not built: a CSRF token (CSRFProtector has no implementation), a Referer
// fallback, a check of the request's Content-Type, and X-Forwarded-Host for
// an application that leaves BaseURL unset behind a proxy.
type OriginCheck struct {
	own     string // behemoth's origin as originOf writes it; "" compares with the request's Host
	trusted OriginValidator
}

// NewOriginCheck returns the check for a behemoth served at baseURL, an
// origin such as "https://auth.example.com", which also accepts the origins
// trusted trusts. A baseURL that is not an http or https origin is an error.
//
// With an empty baseURL the check compares the host and port of a request's
// Origin with its Host header and ignores the scheme. That refuses every
// browser request when a proxy in front rewrites Host, so an application
// behind one sets baseURL. A nil trusted trusts no further origin.
func NewOriginCheck(baseURL string, trusted OriginValidator) (*OriginCheck, error) {
	c := &OriginCheck{trusted: trusted}
	if strings.TrimSpace(baseURL) == "" {
		return c, nil
	}
	own, err := parseOrigin(baseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL %w", err)
	}
	c.own = own
	return c, nil
}

// Check reports whether r may change state. It returns nil, or a forbidden
// error with the code behemotherr.ErrorCodeUntrustedOrigin.
//
//   - GET, HEAD and OPTIONS pass: no behemoth route changes state on them.
//   - A request with an Origin header passes when the origin is behemoth's
//     own or a trusted one. "null" is refused.
//   - A request without one passes when it has no Sec-Fetch-Site header
//     either, since every current browser sends at least one of the two, or
//     when Sec-Fetch-Site is "same-origin" or "none".
func (c *OriginCheck) Check(r *http.Request) error {
	if reason := c.refusal(r); reason != "" {
		return behemotherr.NewUntrustedOrigin("OriginCheck", reason)
	}
	return nil
}

// refusal returns the reason r is refused for, one of the OriginRefused
// constants, or "" when r passes.
func (c *OriginCheck) refusal(r *http.Request) string {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return ""
	}
	values := r.Header.Values("Origin")
	if len(values) == 0 || (len(values) == 1 && values[0] == "") {
		switch r.Header.Get("Sec-Fetch-Site") {
		case "", "same-origin", "none":
			return ""
		}
		return OriginRefusedCrossSite
	}
	if len(values) > 1 {
		return OriginRefusedMalformed
	}
	if values[0] == "null" {
		return OriginRefusedNull
	}
	u, err := url.Parse(values[0])
	if err != nil {
		return OriginRefusedMalformed
	}
	origin, ok := originOf(u)
	if !ok || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return OriginRefusedMalformed
	}
	if origin == c.ownOrigin(u.Scheme, r.Host) || (c.trusted != nil && c.trusted.IsTrusted(origin)) {
		return ""
	}
	return OriginRefusedUntrusted
}

// ownOrigin returns behemoth's origin for one request. Without a base URL
// it is the request's Host under the scheme the Origin header named: the
// scheme the browser used is not known behind a proxy that ends TLS, so
// only the host and the port are compared.
func (c *OriginCheck) ownOrigin(scheme, host string) string {
	if c.own != "" {
		return c.own
	}
	u, err := url.Parse(scheme + "://" + host)
	if err != nil {
		return ""
	}
	own, _ := originOf(u)
	return own
}

// Middleware returns the check as a middleware for Router.Build. Boot passes
// it first, so a refused request reaches no plugin middleware, no rate limit
// and no handler, and the router maps the refusal like any other error. A
// refusal is counted in telemetry.MetricOriginRefused and writes no audit
// event.
func (c *OriginCheck) Middleware() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			reason := c.refusal(rctx.Request)
			if reason == "" {
				return next(rctx)
			}
			if rctx.Auth != nil && rctx.Auth.Telemetry.MetricsEnabled() {
				rctx.Auth.Telemetry.Count(rctx.Ctx, telemetry.MetricOriginRefused, behemoth.M{telemetry.AttrReason: reason})
			}
			return behemotherr.NewUntrustedOrigin("OriginCheck", reason)
		}
	}
}
