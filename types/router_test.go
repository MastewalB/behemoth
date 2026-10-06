package types

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
)

// recordingDriver keeps the routes Build hands it, so tests can call them.
type recordingDriver struct{ routes []Route }

func (d *recordingDriver) Mount(routes ...Route) error {
	d.routes = append(d.routes, routes...)
	return nil
}

func (d *recordingDriver) serve(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	for _, rt := range d.routes {
		if rt.Method == method && rt.Path == path {
			rctx := &RequestContext{
				Request:  httptest.NewRequest(method, path, nil),
				Response: NewResponseRecorder(),
				Values:   map[string]any{},
			}
			if err := rt.Handler(rctx); err != nil {
				t.Fatalf("%s %s: handler returned %v; errors should already be mapped", method, path, err)
			}
			w := httptest.NewRecorder()
			rctx.Response.Flush(w)
			return w
		}
	}
	t.Fatalf("%s %s not mounted", method, path)
	return nil
}

func TestRouterMountConflicts(t *testing.T) {
	r := NewRouter(RouterConfig{}, nil)
	ok := func(rctx *RequestContext) error { return nil }

	if err := r.Mount("a", "/a", []Route{{Method: http.MethodGet, Path: "/status", Handler: ok}}); err != nil {
		t.Fatal(err)
	}
	// Same relative path under a different mount path is a different route.
	if err := r.Mount("b", "/b", []Route{{Method: http.MethodGet, Path: "/status", Handler: ok}}); err != nil {
		t.Fatalf("distinct full paths reported as conflicting: %v", err)
	}
	err := r.Mount("c", "/a", []Route{{Method: http.MethodGet, Path: "/status", Handler: ok}})
	if err == nil || !strings.Contains(err.Error(), "/api/auth/a/status") {
		t.Fatalf("expected a conflict on /api/auth/a/status, got %v", err)
	}
	if err := r.MountAbsolute("core", Route{Method: http.MethodGet, Path: "/api/auth/b/status", Handler: ok}); err == nil {
		t.Fatal("expected MountAbsolute to conflict with a mounted route")
	}
	if got := len(r.Routes()); got != 2 {
		t.Errorf("routes = %d, want 2 (conflicting routes are not added)", got)
	}
}

func TestRouterBuildPipeline(t *testing.T) {
	auth := &AuthContext{}
	var order []string
	trace := func(name string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(rctx *RequestContext) error {
				order = append(order, name)
				return next(rctx)
			}
		}
	}

	r := NewRouter(RouterConfig{}, auth)
	err := r.Mount("p", "", []Route{
		{Method: http.MethodGet, Path: "/ok", Middlewares: []Middleware{trace("route")}, Handler: func(rctx *RequestContext) error {
			order = append(order, "handler")
			if rctx.Auth != auth {
				t.Error("handler did not receive the router's AuthContext")
			}
			if RequestFrom(rctx.Ctx) != rctx {
				t.Error("rctx.Ctx does not carry the request (ContextWithRequest)")
			}
			return rctx.Response.JSON(http.StatusOK, map[string]string{"status": "ok"})
		}},
		{Method: http.MethodGet, Path: "/limited", Handler: func(rctx *RequestContext) error {
			return behemotherr.NewRateLimited("test", "rule", 30*time.Second)
		}},
		{Method: http.MethodGet, Path: "/broken", Handler: func(rctx *RequestContext) error {
			return errors.New("raw internal detail")
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	d := &recordingDriver{}
	if err := r.Build(d, trace("global1"), trace("global2")); err != nil {
		t.Fatal(err)
	}

	if w := d.serve(t, http.MethodGet, "/api/auth/ok"); w.Code != http.StatusOK {
		t.Errorf("/ok status = %d, want 200", w.Code)
	}
	if want := []string{"global1", "global2", "route", "handler"}; !slices.Equal(order, want) {
		t.Errorf("execution order = %v, want %v", order, want)
	}

	w := d.serve(t, http.MethodGet, "/api/auth/limited")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "30" {
		t.Errorf("/limited = %d, Retry-After %q; want 429, \"30\"", w.Code, w.Header().Get("Retry-After"))
	}

	w = d.serve(t, http.MethodGet, "/api/auth/broken")
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "raw internal detail") {
		t.Errorf("/broken = %d %s; want 500 without the raw error", w.Code, w.Body.String())
	}
}

func TestRouterGlobalMiddlewareErrorIsMapped(t *testing.T) {
	r := NewRouter(RouterConfig{}, nil)
	called := false
	if err := r.Mount("p", "", []Route{{Method: http.MethodGet, Path: "/x", Handler: func(*RequestContext) error {
		called = true
		return nil
	}}}); err != nil {
		t.Fatal(err)
	}
	reject := func(HandlerFunc) HandlerFunc {
		return func(*RequestContext) error { return behemotherr.NewRateLimited("mw", "rule", 0) }
	}

	d := &recordingDriver{}
	if err := r.Build(d, reject); err != nil {
		t.Fatal(err)
	}
	if w := d.serve(t, http.MethodGet, "/api/auth/x"); w.Code != http.StatusTooManyRequests || called {
		t.Errorf("status = %d, handler called = %v; want 429 and the handler skipped", w.Code, called)
	}
}

type fixedRuleCatalog struct{ routes []RouteRateLimitRule }

func (c fixedRuleCatalog) DeclareHookRateLimitRule(HookRateLimitRule) error   { return nil }
func (c fixedRuleCatalog) RulesForHook(HookPoint) []HookRateLimitRule         { return nil }
func (c fixedRuleCatalog) DeclareRouteRateLimitRule(RouteRateLimitRule) error { return nil }
func (c fixedRuleCatalog) RulesForRoute() []RouteRateLimitRule                { return c.routes }

// rejectingLimiter rejects every request and reports which rule fired.
type rejectingLimiter struct{}

func (rejectingLimiter) CheckHookLimit(context.Context, HookPoint, *HookContext) error { return nil }
func (rejectingLimiter) CheckRouteLimit(_ context.Context, rule RouteRateLimitRule, _ *http.Request, _ *ClientIPConfig) error {
	return behemotherr.NewRateLimited("test", rule.Name, time.Second)
}

func TestApplyRateLimitingMatchesRelativeAndAbsolutePaths(t *testing.T) {
	ok := func(rctx *RequestContext) error { return rctx.Response.JSON(http.StatusOK, map[string]string{}) }

	r := NewRouter(RouterConfig{BasePath: "/custom/base"}, nil)
	if err := r.Mount("emailpassword", "", []Route{{Method: http.MethodPost, Path: "/sign-in/email", Handler: ok}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Mount("audit", "/audit", []Route{
		{Method: http.MethodGet, Path: "/status", Handler: ok},
		{Method: http.MethodGet, Path: "/open", Handler: ok},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.MountAbsolute("core", Route{Method: http.MethodGet, Path: "/.well-known/jwks.json", Handler: ok}); err != nil {
		t.Fatal(err)
	}

	rule := func(name, method, path string) RouteRateLimitRule {
		return RouteRateLimitRule{Name: name, Method: method, Path: path}
	}
	r.ApplyRateLimiting(rejectingLimiter{}, fixedRuleCatalog{routes: []RouteRateLimitRule{
		rule("signin", http.MethodPost, "/sign-in/email"),            // relative to BasePath, no MountPath
		rule("audit", http.MethodGet, "/audit/status"),               // relative to BasePath, includes MountPath
		rule("jwks", http.MethodGet, "/.well-known/jwks.json"),       // absolute route: its full path
		rule("full-path", http.MethodGet, "/custom/base/audit/open"), // full paths never match mounted routes
	}}, &ClientIPConfig{})

	d := &recordingDriver{}
	if err := r.Build(d); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		method, path string
		limited      bool
	}{
		{http.MethodPost, "/custom/base/sign-in/email", true},
		{http.MethodGet, "/custom/base/audit/status", true},
		{http.MethodGet, "/.well-known/jwks.json", true},
		{http.MethodGet, "/custom/base/audit/open", false},
	} {
		w := d.serve(t, tc.method, tc.path)
		if got := w.Code == http.StatusTooManyRequests; got != tc.limited {
			t.Errorf("%s %s: status %d, limited = %v, want %v", tc.method, tc.path, w.Code, got, tc.limited)
		}
	}
}

func TestRouterRequestID(t *testing.T) {
	var seen string
	handler := func(rctx *RequestContext) error {
		seen = telemetry.RequestIDFrom(rctx.Ctx)
		return behemotherr.NewInternalError("test", errors.New("boom")) // the header is set on error responses too
	}
	build := func(cfg RouterConfig) Route {
		r := NewRouter(cfg, nil)
		if err := r.Mount("test", "", []Route{{Method: http.MethodGet, Path: "/x", Handler: handler}}); err != nil {
			t.Fatal(err)
		}
		d := &recordingDriver{}
		if err := r.Build(d); err != nil {
			t.Fatal(err)
		}
		return d.routes[0]
	}
	serve := func(rt Route, ctx context.Context, header, value string) string {
		req := httptest.NewRequest(http.MethodGet, rt.Path, nil)
		if header != "" {
			req.Header.Set(header, value)
		}
		rctx := &RequestContext{Ctx: ctx, Request: req, Response: NewResponseRecorder(), Values: map[string]any{}}
		if err := rt.Handler(rctx); err != nil {
			t.Fatal(err)
		}
		return rctx.Response.Headers.Get(header)
	}

	rt := build(RouterConfig{})
	const header = telemetry.DefaultRequestIDHeader

	// The caller's ID is kept and echoed.
	if got := serve(rt, nil, header, "client-id-1"); got != "client-id-1" || seen != "client-id-1" {
		t.Errorf("echoed %q, handler saw %q; want client-id-1 for both", got, seen)
	}
	// An unusable value is replaced.
	if got := serve(rt, nil, header, "bad id\twith spaces"); got == "" || got != seen || !telemetry.ValidRequestID(got) || strings.Contains(got, "bad") {
		t.Errorf("echoed %q, handler saw %q; want one generated ID", got, seen)
	}
	// No header: one is generated.
	req := httptest.NewRequest(http.MethodGet, rt.Path, nil)
	rctx := &RequestContext{Request: req, Response: NewResponseRecorder(), Values: map[string]any{}}
	if err := rt.Handler(rctx); err != nil {
		t.Fatal(err)
	}
	if got := rctx.Response.Headers.Get(header); len(got) != 32 || got != seen {
		t.Errorf("echoed %q, handler saw %q; want one generated ID", got, seen)
	}
	// An ID the application put on the context wins over the header.
	ctx := telemetry.ContextWithRequestID(context.Background(), "from-app")
	if got := serve(rt, ctx, header, "client-id-2"); got != "from-app" || seen != "from-app" {
		t.Errorf("echoed %q, handler saw %q; want from-app for both", got, seen)
	}

	// A configured header replaces the default one.
	custom := build(RouterConfig{RequestIDHeader: "X-Correlation-ID"})
	if got := serve(custom, nil, "X-Correlation-ID", "corr-1"); got != "corr-1" || seen != "corr-1" {
		t.Errorf("echoed %q, handler saw %q; want corr-1 for both", got, seen)
	}
}

// A 5xx is the server's failure and is logged at Error with the error's
// taxonomy fields; a rejection is logged at Debug only.
func TestRouterLogsFailures(t *testing.T) {
	tel, rec := telemetrytest.New()
	r := NewRouter(RouterConfig{}, &AuthContext{Telemetry: tel})
	err := r.Mount("test", "", []Route{
		{Method: http.MethodGet, Path: "/users/{id}", Handler: func(*RequestContext) error {
			return behemotherr.NewDatabaseError("Store.FindUser", errors.New("connection refused"))
		}},
		{Method: http.MethodGet, Path: "/missing", Handler: func(*RequestContext) error {
			return behemotherr.NewNotFound("Store.FindUser", "user", nil)
		}},
		{Method: http.MethodGet, Path: "/ok", Handler: func(rctx *RequestContext) error {
			return rctx.Response.JSON(http.StatusOK, map[string]string{})
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := &recordingDriver{}
	if err := r.Build(d); err != nil {
		t.Fatal(err)
	}

	w := d.serve(t, http.MethodGet, "/api/auth/users/{id}")
	d.serve(t, http.MethodGet, "/api/auth/missing")
	d.serve(t, http.MethodGet, "/api/auth/ok")

	errorLines := rec.Logger.At(slog.LevelError)
	if len(errorLines) != 1 {
		t.Fatalf("error lines = %v, want exactly the 500", errorLines)
	}
	got := errorLines[0].Fields
	want := map[string]any{
		telemetry.FieldComponent:     "router",
		telemetry.FieldMethod:        http.MethodGet,
		telemetry.FieldRoute:         "/api/auth/users/{id}",
		telemetry.FieldStatus:        http.StatusInternalServerError,
		telemetry.FieldError:         "connection refused",
		telemetry.FieldErrorCode:     "database_error",
		telemetry.FieldErrorCategory: "database",
		telemetry.FieldOp:            "Store.FindUser",
		telemetry.FieldRequestID:     w.Header().Get(telemetry.DefaultRequestIDHeader),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if got[telemetry.FieldRequestID] == "" {
		t.Error("the error line has no request ID")
	}
	if strings.Contains(w.Body.String(), "connection refused") {
		t.Errorf("the internal message reached the client: %s", w.Body.String())
	}

	debugLines := rec.Logger.At(slog.LevelDebug)
	if len(debugLines) != 1 || debugLines[0].Fields[telemetry.FieldStatus] != http.StatusNotFound {
		t.Errorf("debug lines = %v, want exactly the 404", debugLines)
	}
}
