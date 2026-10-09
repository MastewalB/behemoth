package types

import (
	"fmt"
	"net/url"
	"strings"
)

// TrustedOrigins is the OriginValidator Boot builds from
// RouterConfig.TrustedOrigins and puts on AuthContext.Origins. It answers
// whether a browser may be sent to an origin, which is what a plugin asks
// before it accepts a redirect URL from a request (TrustedRedirect).
//
// An origin is a scheme, a host and an optional port: "https://app.example.com".
// The match is exact. Wildcards and subdomain patterns are not built: list
// each origin.
type TrustedOrigins struct {
	origins map[string]bool
}

// NewTrustedOrigins returns the validator for origins. An entry that is not
// an http or https origin, or that carries a path, a query or credentials,
// is an error, so a typo is found at Boot and not by a refused redirect.
func NewTrustedOrigins(origins []string) (*TrustedOrigins, error) {
	t := &TrustedOrigins{origins: make(map[string]bool, len(origins))}
	for _, raw := range origins {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("trusted origin %q: %w", raw, err)
		}
		origin, ok := originOf(u)
		if !ok || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("trusted origin %q: want a scheme and a host, such as https://app.example.com", raw)
		}
		t.origins[origin] = true
	}
	return t, nil
}

// IsTrusted implements [OriginValidator]. origin is compared without regard
// to case and with its default port removed, so "https://App.example.com:443"
// matches "https://app.example.com". A nil *TrustedOrigins trusts nothing.
func (t *TrustedOrigins) IsTrusted(origin string) bool {
	if t == nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	normalized, ok := originOf(u)
	return ok && (u.Path == "" || u.Path == "/") && t.origins[normalized]
}

// TrustedRedirect reports whether a browser may be sent to target, a URL
// that came from a request. Two forms pass:
//
//   - a path on the application's own site: it starts with one "/", as in
//     "/dashboard?tab=1";
//   - an absolute http or https URL whose origin v trusts.
//
// Everything else is refused, including "//host/path" and "/\host", which a
// browser reads as another site, a URL with credentials, and the empty
// string. A caller for which the redirect is optional checks for "" first.
// A nil v trusts no origin, so only paths pass.
func TrustedRedirect(v OriginValidator, target string) bool {
	if target == "" || strings.ContainsAny(target, "\\\r\n\t") {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	if u.Scheme == "" && u.Host == "" {
		return strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//")
	}
	origin, ok := originOf(u)
	return ok && v != nil && v.IsTrusted(origin)
}

// originOf returns u's origin in the form trusted origins are stored in:
// lowercased, without the scheme's default port. ok is false when u is not
// an http or https URL with a host, or carries credentials.
func originOf(u *url.URL) (origin string, ok bool) {
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // an IPv6 literal
	}
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

var _ OriginValidator = (*TrustedOrigins)(nil)
