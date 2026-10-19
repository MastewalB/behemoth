package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A zero TokenCarrierConfig takes every documented default, and a field
// that was set is kept.
func TestTokenCarrierConfigDefaults(t *testing.T) {
	got := TokenCarrierConfig{}.WithDefaults()
	want := TokenCarrierConfig{Delivery: DeliveryCookie, CookieName: "session_token", CookieSameSite: SameSiteLax}
	if got != want {
		t.Errorf("defaults = %+v, want %+v", got, want)
	}
	if got := NewTokenCarrier(TokenCarrierConfig{}).Config(); got != want {
		t.Errorf("NewTokenCarrier applies the defaults: Config = %+v", got)
	}

	set := TokenCarrierConfig{
		Delivery: DeliveryBody, CookieName: "sid", CookieDomain: "example.com",
		CookieSameSite: SameSiteStrict, CookieInsecure: true,
	}
	if got := set.WithDefaults(); got != set {
		t.Errorf("WithDefaults changed a config that was set: %+v", got)
	}
}

// Validate refuses what no default can repair, and accepts zero fields.
func TestTokenCarrierConfigValidate(t *testing.T) {
	for _, delivery := range []TokenDelivery{"", DeliveryCookie, DeliveryHeader, DeliveryBody, DeliveryBoth} {
		if err := (TokenCarrierConfig{Delivery: delivery}).Validate(); err != nil {
			t.Errorf("delivery %q: %v", delivery, err)
		}
	}
	for _, ok := range []TokenCarrierConfig{
		{CookieSameSite: SameSiteLax}, {CookieSameSite: SameSiteStrict}, {CookieSameSite: SameSiteNone},
		{CookieSameSite: SameSiteLax, CookieInsecure: true},
		{CookieDomain: "example.com"}, {CookieDomain: ".example.com"}, {CookieDomain: "localhost"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for name, tc := range map[string]struct {
		cfg  TokenCarrierConfig
		want string
	}{
		"a misspelled delivery":               {TokenCarrierConfig{Delivery: "Header"}, "Delivery"},
		"a misspelled SameSite mode":          {TokenCarrierConfig{CookieSameSite: "None"}, "CookieSameSite"},
		"SameSite none without Secure":        {TokenCarrierConfig{CookieSameSite: SameSiteNone, CookieInsecure: true}, "CookieInsecure"},
		"a cookie domain with a scheme":       {TokenCarrierConfig{CookieDomain: "https://example.com"}, "CookieDomain"},
		"a cookie domain with a port":         {TokenCarrierConfig{CookieDomain: "example.com:8080"}, "CookieDomain"},
		"a cookie domain with a path":         {TokenCarrierConfig{CookieDomain: "example.com/app"}, "CookieDomain"},
		"a cookie domain that is only a dot":  {TokenCarrierConfig{CookieDomain: "."}, "CookieDomain"},
		"a cookie domain with a trailing dot": {TokenCarrierConfig{CookieDomain: "example.com."}, "CookieDomain"},
	} {
		err := tc.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "RouterConfig.Carrier") {
			t.Errorf("%s: Validate = %v, want an error naming RouterConfig.Carrier.%s", name, err, tc.want)
		}
	}
}

// carrierRequest returns a request context for req with an empty response.
func carrierRequest(req *http.Request) *RequestContext {
	if req == nil {
		req = httptest.NewRequest(http.MethodPost, "/x", nil)
	}
	return &RequestContext{Ctx: req.Context(), Request: req, Response: NewResponseRecorder(), Values: map[string]any{}}
}

// setCookies returns the cookies a response sets.
func setCookies(rctx *RequestContext) []*http.Cookie {
	return (&http.Response{Header: rctx.Response.Headers}).Cookies()
}

// The session cookie carries the attributes the settings name, and the
// cookie that removes it carries the same ones: a browser replaces a cookie
// only with one of the same name, path and domain.
func TestTokenCarrierCookieAttributes(t *testing.T) {
	const raw = "raw-token"
	for name, tc := range map[string]struct {
		cfg      TokenCarrierConfig
		domain   string
		sameSite http.SameSite
		secure   bool
	}{
		"the defaults":      {TokenCarrierConfig{}, "", http.SameSiteLaxMode, true},
		"a domain":          {TokenCarrierConfig{CookieDomain: "example.com"}, "example.com", http.SameSiteLaxMode, true},
		"a domain as .host": {TokenCarrierConfig{CookieDomain: ".example.com"}, "example.com", http.SameSiteLaxMode, true},
		"strict":            {TokenCarrierConfig{CookieSameSite: SameSiteStrict}, "", http.SameSiteStrictMode, true},
		"none":              {TokenCarrierConfig{CookieSameSite: SameSiteNone}, "", http.SameSiteNoneMode, true},
		"without Secure":    {TokenCarrierConfig{CookieInsecure: true}, "", http.SameSiteLaxMode, false},
	} {
		if err := tc.cfg.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		carrier := NewTokenCarrier(tc.cfg)
		written := carrierRequest(nil)
		carrier.Write(written, raw, time.Now().Add(time.Hour))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: raw})
		cleared := carrierRequest(req)
		carrier.Clear(cleared)

		for step, rctx := range map[string]*RequestContext{"written": written, "removed": cleared} {
			cookies := setCookies(rctx)
			if len(cookies) != 1 {
				t.Fatalf("%s, %s: %d cookies set, want 1", name, step, len(cookies))
			}
			c := cookies[0]
			if c.Domain != tc.domain || c.SameSite != tc.sameSite || c.Secure != tc.secure {
				t.Errorf("%s, %s: Domain %q, SameSite %v, Secure %v; want %q, %v, %v", name, step, c.Domain, c.SameSite, c.Secure, tc.domain, tc.sameSite, tc.secure)
			}
			if !c.HttpOnly || c.Path != "/" {
				t.Errorf("%s, %s: HttpOnly and the path are fixed: HttpOnly %v, Path %q", name, step, c.HttpOnly, c.Path)
			}
		}
	}
}

// Each delivery hands the token over in its own place, and reads it back
// from where its client sends it. Clear takes back what Write handed over,
// from the request that presented it.
func TestTokenCarrierDeliveries(t *testing.T) {
	const raw = "raw-token"
	for name, tc := range map[string]struct {
		cfg        TokenCarrierConfig
		cookie     string // the cookie's name when one is set, "" when none is
		header     bool   // the token is in Set-Auth-Token
		inBody     bool   // the route is told to put it in the body
		readCookie bool   // a request's cookie is accepted
		readBearer bool   // a request's Authorization header is accepted
	}{
		"the default":   {TokenCarrierConfig{}, "session_token", false, false, true, false},
		"cookie":        {TokenCarrierConfig{Delivery: DeliveryCookie}, "session_token", false, false, true, false},
		"cookie, named": {TokenCarrierConfig{Delivery: DeliveryCookie, CookieName: "sid"}, "sid", false, false, true, false},
		"header":        {TokenCarrierConfig{Delivery: DeliveryHeader}, "", true, false, false, true},
		"body":          {TokenCarrierConfig{Delivery: DeliveryBody}, "", false, true, false, true},
		"both":          {TokenCarrierConfig{Delivery: DeliveryBoth, CookieName: "sid"}, "sid", true, false, true, true},
	} {
		carrier := NewTokenCarrier(tc.cfg)
		expires := time.Now().Add(time.Hour)

		rctx := carrierRequest(nil)
		if got := carrier.Write(rctx, raw, expires); got != tc.inBody {
			t.Errorf("%s: Write says in the body = %v, want %v", name, got, tc.inBody)
		}
		setCookie := rctx.Response.Headers.Get("Set-Cookie")
		if tc.cookie == "" && setCookie != "" {
			t.Errorf("%s: a cookie was set: %q", name, setCookie)
		}
		if tc.cookie != "" && (!strings.HasPrefix(setCookie, tc.cookie+"="+raw+";") || !strings.Contains(setCookie, "HttpOnly")) {
			t.Errorf("%s: Set-Cookie = %q", name, setCookie)
		}
		if tc.cookie != "" && !setCookies(rctx)[0].Expires.Equal(expires.UTC().Truncate(time.Second)) {
			t.Errorf("%s: the cookie expires at %s, want the session's %s", name, setCookies(rctx)[0].Expires, expires)
		}
		wantHeader := ""
		if tc.header {
			wantHeader = raw
		}
		if got := rctx.Response.Headers.Get(SessionTokenHeader); got != wantHeader {
			t.Errorf("%s: %s = %q, want %q", name, SessionTokenHeader, got, wantHeader)
		}
		if len(rctx.Values) != 0 {
			t.Errorf("%s: something was parked in the request's values: %v", name, rctx.Values)
		}

		cookieName := carrier.Config().CookieName
		withCookie := httptest.NewRequest(http.MethodGet, "/x", nil)
		withCookie.AddCookie(&http.Cookie{Name: cookieName, Value: raw})
		if got, ok := carrier.Extract(withCookie); ok != tc.readCookie || (ok && got != raw) {
			t.Errorf("%s: Extract of the cookie = %q, %v; want it read: %v", name, got, ok, tc.readCookie)
		}
		withBearer := httptest.NewRequest(http.MethodGet, "/x", nil)
		withBearer.Header.Set("Authorization", "Bearer "+raw)
		if got, ok := carrier.Extract(withBearer); ok != tc.readBearer || (ok && got != raw) {
			t.Errorf("%s: Extract of the bearer token = %q, %v; want it read: %v", name, got, ok, tc.readBearer)
		}
		if _, ok := carrier.Extract(httptest.NewRequest(http.MethodGet, "/x", nil)); ok {
			t.Errorf("%s: a token in a request without one", name)
		}

		// A browser replaces a cookie only with one of the same name and
		// path, so the cookie Clear sets is the one above, emptied and
		// expired. A delivery without a cookie has nothing to take back.
		clear := func(req *http.Request) *RequestContext {
			cleared := carrierRequest(req)
			carrier.Clear(cleared)
			return cleared
		}
		cleared := clear(withCookie)
		if tc.cookie == "" {
			if len(cleared.Response.Headers) != 0 {
				t.Errorf("%s: Clear wrote %v", name, cleared.Response.Headers)
			}
		} else {
			written, gone := setCookies(rctx), setCookies(cleared)
			if len(gone) != 1 {
				t.Fatalf("%s: Clear set %d cookies, want 1", name, len(gone))
			}
			g := gone[0]
			if g.Name != written[0].Name || g.Path != written[0].Path || g.SameSite != written[0].SameSite || !g.HttpOnly || !g.Secure {
				t.Errorf("%s: the removal is not the cookie it replaces: %+v, wrote %+v", name, g, written[0])
			}
			if g.Value != "" || g.MaxAge >= 0 || !g.Expires.Before(time.Now()) {
				t.Errorf("%s: the removal keeps the cookie: value %q, Max-Age %d, Expires %s", name, g.Value, g.MaxAge, g.Expires)
			}
			if cleared.Response.Headers.Get(SessionTokenHeader) != "" {
				t.Errorf("%s: Clear set the token header", name)
			}
		}
		// A request that did not present its token in the cookie keeps
		// whatever cookie it has: under DeliveryBoth the token may come as
		// a bearer token next to the cookie of another session.
		if h := clear(withBearer).Response.Headers; len(h) != 0 {
			t.Errorf("%s: no cookie in the request, and Clear wrote %v", name, h)
		}
		otherCookie := httptest.NewRequest(http.MethodGet, "/x", nil)
		otherCookie.Header.Set("Authorization", "Bearer "+raw)
		otherCookie.AddCookie(&http.Cookie{Name: cookieName, Value: "another-sessions-token"})
		if h := clear(otherCookie).Response.Headers; tc.readBearer && len(h) != 0 {
			t.Errorf("%s: the cookie is another session's, and Clear wrote %v", name, h)
		}
	}
}

// Extend writes the cookie again with the new expiry, for the request that
// sent the token in the cookie, and nothing for a client that keeps the
// token without a date.
func TestTokenCarrierExtend(t *testing.T) {
	const raw = "raw-token"
	later := time.Now().Add(48 * time.Hour)
	request := func(cookie, bearer string) *RequestContext {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "session_token", Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return carrierRequest(req)
	}

	byCookie := NewTokenCarrier(TokenCarrierConfig{})
	rctx := request(raw, "")
	if !byCookie.Extend(rctx, raw, later) {
		t.Fatal("Extend did not write the cookie")
	}
	set := setCookies(rctx)
	if len(set) != 1 || set[0].Value != raw || !set[0].Expires.Equal(later.UTC().Truncate(time.Second)) {
		t.Errorf("the cookie comes back with the same token and the new date: %+v", set)
	}

	for name, tc := range map[string]struct {
		carrier        *TokenCarrier
		cookie, bearer string
	}{
		"the header delivery":                   {NewTokenCarrier(TokenCarrierConfig{Delivery: DeliveryHeader}), "", raw},
		"the body delivery":                     {NewTokenCarrier(TokenCarrierConfig{Delivery: DeliveryBody}), "", raw},
		"a bearer token next to another cookie": {NewTokenCarrier(TokenCarrierConfig{Delivery: DeliveryBoth}), "another-sessions-token", raw},
		"no cookie":                             {byCookie, "", ""},
	} {
		rctx := request(tc.cookie, tc.bearer)
		if tc.carrier.Extend(rctx, raw, later) || len(rctx.Response.Headers) != 0 {
			t.Errorf("%s: Extend wrote %v", name, rctx.Response.Headers)
		}
	}
}

// One request can write the session cookie twice: the authentication stage
// extends it, and the sign-out route then removes it. Only the last write
// is sent.
func TestTokenCarrierSetsTheCookieOnce(t *testing.T) {
	const raw = "raw-token"
	carrier := NewTokenCarrier(TokenCarrierConfig{})
	req := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: raw})
	rctx := carrierRequest(req)
	rctx.Response.Cookie(&http.Cookie{Name: "unrelated", Value: "kept"})

	carrier.Extend(rctx, raw, time.Now().Add(time.Hour))
	carrier.Clear(rctx)
	set := setCookies(rctx)
	if len(set) != 2 || set[0].Name != "unrelated" || set[1].Name != "session_token" || set[1].Value != "" {
		t.Errorf("want the unrelated cookie and the removal: %+v", set)
	}
}
