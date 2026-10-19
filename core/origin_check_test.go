package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/errs"
)

func TestNewOriginCheckRefusesABadBaseURL(t *testing.T) {
	for _, bad := range []string{"auth.example.com", "ftp://auth.example.com", "https://auth.example.com/api/auth", "https://user@auth.example.com"} {
		if _, err := NewOriginCheck(bad, nil); err == nil {
			t.Errorf("NewOriginCheck(%q) = nil error, want it refused", bad)
		}
	}
	for _, good := range []string{"", "https://auth.example.com", "http://localhost:8080/"} {
		if _, err := NewOriginCheck(good, nil); err != nil {
			t.Errorf("NewOriginCheck(%q) = %v", good, err)
		}
	}
}

func TestOriginCheck(t *testing.T) {
	trusted, err := NewTrustedOrigins([]string{"https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	withBaseURL, err := NewOriginCheck("https://auth.example.com", trusted)
	if err != nil {
		t.Fatal(err)
	}
	fromHost, err := NewOriginCheck("", trusted)
	if err != nil {
		t.Fatal(err)
	}

	type headers map[string][]string
	cases := []struct {
		name   string
		check  *OriginCheck
		method string
		host   string
		header headers
		reason string // "" = the request passes
	}{
		{name: "a safe method is not checked", check: withBaseURL, method: http.MethodGet, header: headers{"Origin": {"https://evil.example"}}},
		{name: "its own origin", check: withBaseURL, header: headers{"Origin": {"https://auth.example.com"}}},
		{name: "its own origin, another case and the default port", check: withBaseURL, header: headers{"Origin": {"https://AUTH.example.com:443"}}},
		{name: "a trusted origin, although the browser calls it cross-site", check: withBaseURL, header: headers{"Origin": {"https://app.example.com"}, "Sec-Fetch-Site": {"cross-site"}}},
		{name: "another origin", check: withBaseURL, header: headers{"Origin": {"https://evil.example"}}, reason: OriginRefusedUntrusted},
		{name: "a sibling subdomain", check: withBaseURL, header: headers{"Origin": {"https://evil.example.com"}}, reason: OriginRefusedUntrusted},
		{name: "its own host under another scheme", check: withBaseURL, header: headers{"Origin": {"http://auth.example.com"}}, reason: OriginRefusedUntrusted},
		{name: "another origin that claims to be same-origin", check: withBaseURL, header: headers{"Origin": {"https://evil.example"}, "Sec-Fetch-Site": {"same-origin"}}, reason: OriginRefusedUntrusted},
		{name: "the Host header does not count when a base URL is set", check: withBaseURL, host: "evil.example", header: headers{"Origin": {"https://evil.example"}}, reason: OriginRefusedUntrusted},
		{name: "null", check: withBaseURL, header: headers{"Origin": {"null"}}, reason: OriginRefusedNull},
		{name: "two Origin headers", check: withBaseURL, header: headers{"Origin": {"https://auth.example.com", "https://evil.example"}}, reason: OriginRefusedMalformed},
		{name: "an origin with a path", check: withBaseURL, header: headers{"Origin": {"https://auth.example.com/"}}, reason: OriginRefusedMalformed},
		{name: "not an origin", check: withBaseURL, header: headers{"Origin": {"auth.example.com"}}, reason: OriginRefusedMalformed},

		{name: "no Origin and no Sec-Fetch-Site: not a browser", check: withBaseURL},
		{name: "no Origin, same-origin", check: withBaseURL, header: headers{"Sec-Fetch-Site": {"same-origin"}}},
		{name: "no Origin, none", check: withBaseURL, header: headers{"Sec-Fetch-Site": {"none"}}},
		{name: "no Origin, cross-site", check: withBaseURL, header: headers{"Sec-Fetch-Site": {"cross-site"}}, reason: OriginRefusedCrossSite},
		{name: "no Origin, same-site", check: withBaseURL, header: headers{"Sec-Fetch-Site": {"same-site"}}, reason: OriginRefusedCrossSite},
		{name: "an empty Origin, cross-site", check: withBaseURL, header: headers{"Origin": {""}, "Sec-Fetch-Site": {"cross-site"}}, reason: OriginRefusedCrossSite},

		{name: "no base URL: the Host's origin", check: fromHost, host: "auth.example.com", header: headers{"Origin": {"https://auth.example.com"}}},
		{name: "no base URL: the scheme is not compared", check: fromHost, host: "auth.example.com", header: headers{"Origin": {"http://auth.example.com"}}},
		{name: "no base URL: a port", check: fromHost, host: "localhost:8080", header: headers{"Origin": {"http://localhost:8080"}}},
		{name: "no base URL: a default port in Host", check: fromHost, host: "auth.example.com:443", header: headers{"Origin": {"https://auth.example.com"}}},
		{name: "no base URL: another port", check: fromHost, host: "localhost:8080", header: headers{"Origin": {"http://localhost:3000"}}, reason: OriginRefusedUntrusted},
		{name: "no base URL: another host", check: fromHost, host: "auth.example.com", header: headers{"Origin": {"https://evil.example"}}, reason: OriginRefusedUntrusted},
		{name: "no base URL: a trusted origin", check: fromHost, host: "auth.example.com", header: headers{"Origin": {"https://app.example.com"}}},
		{name: "no base URL: a rewritten Host refuses the application's own page", check: fromHost, host: "upstream.internal:9000", header: headers{"Origin": {"https://auth.example.com"}}, reason: OriginRefusedUntrusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			r := httptest.NewRequest(method, "/api/auth/sign-in/email", nil)
			if tc.host != "" {
				r.Host = tc.host
			}
			for name, values := range tc.header {
				r.Header[name] = values
			}
			err := tc.check.Check(r)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("Check = %v, want the request to pass", err)
				}
				return
			}
			if !errs.IsCode(err, errs.CodeUntrustedOrigin) || !errs.IsCategory(err, errs.CategoryForbidden) {
				t.Fatalf("Check = %v, want a forbidden error with the code %q", err, errs.CodeUntrustedOrigin)
			}
			if got := tc.check.refusal(r); got != tc.reason {
				t.Errorf("reason = %q, want %q", got, tc.reason)
			}
		})
	}
}

// The check is the first global middleware: a refused request is answered
// by the router's error mapper and reaches nothing behind it.
func TestOriginCheckMiddlewareInThePipeline(t *testing.T) {
	check, err := NewOriginCheck("https://auth.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	plugin := func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			reached = append(reached, "middleware")
			return next(rctx)
		}
	}
	router := NewRouter(RouterConfig{}, nil)
	if err := router.Mount("test", "", []Route{{Method: http.MethodPost, Path: "/act", Handler: func(rctx *RequestContext) error {
		reached = append(reached, "handler")
		return rctx.Response.JSON(http.StatusOK, map[string]any{"status": "ok"})
	}}}); err != nil {
		t.Fatal(err)
	}
	driver := &recordingDriver{}
	if err := router.Build(driver, check.Middleware(), plugin); err != nil {
		t.Fatal(err)
	}

	send := func(origin string) *httptest.ResponseRecorder {
		rctx := &RequestContext{
			Request:  httptest.NewRequest(http.MethodPost, "/api/auth/act", nil),
			Response: NewResponseRecorder(),
			Values:   map[string]any{},
		}
		rctx.Request.Header.Set("Origin", origin)
		if err := driver.routes[0].Handler(rctx); err != nil {
			t.Fatalf("handler returned %v; errors should already be mapped", err)
		}
		w := httptest.NewRecorder()
		rctx.Response.Flush(w)
		return w
	}

	w := send("https://evil.example")
	if w.Code != http.StatusForbidden || w.Body.String() != `{"code":"untrusted_origin","error":"request from an untrusted origin"}` {
		t.Errorf("refused request = %d %s", w.Code, w.Body.String())
	}
	if len(reached) != 0 {
		t.Errorf("a refused request reached %v", reached)
	}
	if w := send("https://auth.example.com"); w.Code != http.StatusOK || len(reached) != 2 {
		t.Errorf("own origin = %d, reached %v", w.Code, reached)
	}
}

// A state-changing request with one of the three types a form can send is
// refused with a 415. Every other type, and no type, passes.
func TestRefuseFormContentTypes(t *testing.T) {
	router := NewRouter(RouterConfig{}, nil)
	handler := func(rctx *RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]any{"status": "ok"})
	}
	if err := router.Mount("test", "", []Route{
		{Method: http.MethodPost, Path: "/act", Handler: handler},
		{Method: http.MethodGet, Path: "/read", Handler: handler},
	}); err != nil {
		t.Fatal(err)
	}
	driver := &recordingDriver{}
	if err := router.Build(driver, RefuseFormContentTypes()); err != nil {
		t.Fatal(err)
	}
	send := func(method, path, contentType string) *httptest.ResponseRecorder {
		for _, rt := range driver.routes {
			if rt.Method != method || rt.Path != path {
				continue
			}
			rctx := &RequestContext{
				Request:  httptest.NewRequest(method, path, strings.NewReader(`{"a":1}`)),
				Response: NewResponseRecorder(),
				Values:   map[string]any{},
			}
			if contentType != "" {
				rctx.Request.Header.Set("Content-Type", contentType)
			}
			if err := rt.Handler(rctx); err != nil {
				t.Fatalf("handler returned %v; errors should already be mapped", err)
			}
			w := httptest.NewRecorder()
			rctx.Response.Flush(w)
			return w
		}
		t.Fatalf("no route %s %s", method, path)
		return nil
	}

	for _, refused := range []string{
		"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
		"TEXT/PLAIN; charset=UTF-8", " text/plain ;charset=UTF-8",
	} {
		w := send(http.MethodPost, "/api/auth/act", refused)
		if w.Code != http.StatusUnsupportedMediaType || !strings.Contains(w.Body.String(), `"code":"unsupported_content_type"`) {
			t.Errorf("Content-Type %q = %d %s, want a 415", refused, w.Code, w.Body.String())
		}
	}
	for _, passed := range []string{"", "application/json", "application/json; charset=utf-8", "application/octet-stream", "text/plainer"} {
		if w := send(http.MethodPost, "/api/auth/act", passed); w.Code != http.StatusOK {
			t.Errorf("Content-Type %q = %d %s, want it to pass", passed, w.Code, w.Body.String())
		}
	}
	if w := send(http.MethodGet, "/api/auth/read", "text/plain"); w.Code != http.StatusOK {
		t.Errorf("a GET with a form type = %d, want it to pass", w.Code)
	}
}
