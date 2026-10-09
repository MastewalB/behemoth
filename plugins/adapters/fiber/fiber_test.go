package fiber

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/types"
	"github.com/gofiber/fiber/v3"
)

func ok(*types.RequestContext) error { return nil }

// serve sends req through app and returns the response with its body read.
func serve(t *testing.T, app *fiber.App, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestMountServesAndReportsConflicts(t *testing.T) {
	app := fiber.New()
	app.Get("/api/auth/taken", func(c fiber.Ctx) error { return c.SendStatus(http.StatusTeapot) })

	echoParam := types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]string{"id": rctx.Param("id")})
	}}
	if err := New(app).Mount(echoParam); err != nil {
		t.Fatal(err)
	}

	resp, body := serve(t, app, httptest.NewRequest(http.MethodGet, "/api/auth/users/42", nil))
	if resp.StatusCode != http.StatusOK || body != `{"id":"42"}` {
		t.Errorf("got %d %s, want 200 {\"id\":\"42\"}", resp.StatusCode, body)
	}

	conflict := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: ok}
	if err := New(app).Mount(conflict); err == nil {
		t.Error("expected an error for a route the app already has")
	}
	// The application's own handler must survive the rejected mount.
	resp, _ = serve(t, app, httptest.NewRequest(http.MethodGet, "/api/auth/taken", nil))
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("existing route status = %d, want 418", resp.StatusCode)
	}
}

func TestMountRejectsDuplicatesWithinOneCall(t *testing.T) {
	err := New(fiber.New()).Mount(
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
	)
	if err == nil {
		t.Error("expected an error for the same route twice")
	}
}

func TestMountConflictsWithAllMethodsRoute(t *testing.T) {
	app := fiber.New()
	app.All("/api/auth/any", func(c fiber.Ctx) error { return nil })
	if err := New(app).Mount(types.Route{Method: http.MethodPost, Path: "/api/auth/any", Handler: ok}); err == nil {
		t.Error("expected a conflict with a route registered for all methods")
	}
}

// Fiber matches paths without case and without a trailing slash unless the
// app is configured otherwise, and the conflict check follows the app.
func TestMountConflictFollowsTheAppsMatching(t *testing.T) {
	route := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: ok}
	existing := func(c fiber.Ctx) error { return nil }

	loose := fiber.New()
	loose.Get("/API/Auth/Taken/", existing)
	if err := New(loose).Mount(route); err == nil {
		t.Error("default config: expected a conflict with the same path in another case")
	}

	strict := fiber.New(fiber.Config{CaseSensitive: true, StrictRouting: true})
	strict.Get("/API/Auth/Taken/", existing)
	if err := New(strict).Mount(route); err != nil {
		t.Errorf("case-sensitive, strict config: %v", err)
	}
}

// Middleware on a path is not a route, and it is how an application wraps
// behemoth's routes.
func TestMiddlewareOnThePathIsNotAConflict(t *testing.T) {
	app := fiber.New()
	app.Use("/api/auth", func(c fiber.Ctx) error {
		c.Set("X-Seen-By", "middleware")
		return c.Next()
	})
	if err := New(app).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth", Handler: ok}); err != nil {
		t.Fatal(err)
	}
	resp, _ := serve(t, app, httptest.NewRequest(http.MethodGet, "/api/auth", nil))
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Seen-By") != "middleware" {
		t.Errorf("got %d with X-Seen-By %q, want 200 through the middleware", resp.StatusCode, resp.Header.Get("X-Seen-By"))
	}
}

func TestInvalidRouteIsErrorNotPanic(t *testing.T) {
	err := New(fiber.New()).Mount(types.Route{Method: "BREW", Path: "/api/auth/x", Handler: ok})
	if err == nil {
		t.Error("expected an error for a method fiber rejects")
	}
}

func TestHandlerFailureIsInternalServerError(t *testing.T) {
	app := fiber.New()
	if err := New(app).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/fail", Handler: func(*types.RequestContext) error {
		return http.ErrHandlerTimeout // routes arrive mapped; a returned error means the response could not be built
	}}); err != nil {
		t.Fatal(err)
	}
	resp, _ := serve(t, app, httptest.NewRequest(http.MethodGet, "/api/auth/fail", nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

type ctxKey struct{}

// The handler reads a *http.Request that fiber never had. It has to carry
// what a net/http server would have put there.
func TestRequestIsBuiltFromFibersRequest(t *testing.T) {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.SetContext(context.WithValue(c.Context(), ctxKey{}, "from middleware"))
		return c.Next()
	})

	var got *types.RequestContext
	var body string
	if err := New(app).Mount(types.Route{Method: http.MethodPost, Path: "/api/auth/echo/{name}", Handler: func(rctx *types.RequestContext) error {
		got = rctx
		b, err := io.ReadAll(rctx.Request.Body)
		body = string(b)
		return err
	}}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/echo/a%20b?next=%2Fhome", strings.NewReader(`{"k":"v"}`))
	req.Host = "auth.example.com"
	req.Header.Set("User-Agent", "behemoth-test")
	req.Header.Add("X-Forwarded-For", "203.0.113.7")
	req.Header.Add("X-Forwarded-For", "10.0.0.1")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "tok"})
	if resp, _ := serve(t, app, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	r := got.Request
	for name, pair := range map[string][2]string{
		"Method":         {r.Method, http.MethodPost},
		"URL.Path":       {r.URL.Path, "/api/auth/echo/a b"},
		"query next":     {r.URL.Query().Get("next"), "/home"},
		"Host":           {r.Host, "auth.example.com"},
		"User-Agent":     {r.UserAgent(), "behemoth-test"},
		"body":           {body, `{"k":"v"}`},
		"path param":     {got.Param("name"), "a b"},
		"Host header":    {r.Header.Get("Host"), ""},
		"forwarded":      {strings.Join(r.Header.Values("X-Forwarded-For"), "|"), "203.0.113.7|10.0.0.1"},
		"Ctx value":      {got.Ctx.Value(ctxKey{}).(string), "from middleware"},
		"request ctx":    {r.Context().Value(ctxKey{}).(string), "from middleware"},
		"Content-Length": {r.Header.Get("Content-Length"), "9"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
	if c, err := r.Cookie("session_token"); err != nil || c.Value != "tok" {
		t.Errorf("cookie = %v, %v, want tok", c, err)
	}
	if r.ContentLength != 9 {
		t.Errorf("ContentLength = %d, want 9", r.ContentLength)
	}
	// The client IP is resolved from RemoteAddr, which must be host:port.
	if _, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
		t.Errorf("RemoteAddr = %q: %v", r.RemoteAddr, err)
	}
}

func TestResponseIsWrittenToFiber(t *testing.T) {
	app := fiber.New()
	err := New(app).Mount(
		types.Route{Method: http.MethodPost, Path: "/api/auth/sign-in", Handler: func(rctx *types.RequestContext) error {
			rctx.Response.Cookie(&http.Cookie{Name: "session_token", Value: "tok", HttpOnly: true})
			rctx.Response.Cookie(&http.Cookie{Name: "csrf", Value: "c"})
			rctx.Response.SetHeader("X-Request-ID", "req-1")
			return rctx.Response.JSON(http.StatusCreated, map[string]bool{"ok": true})
		}},
		types.Route{Method: http.MethodGet, Path: "/api/auth/verify", Handler: func(rctx *types.RequestContext) error {
			rctx.Response.Redirect(http.StatusFound, "https://app.example.com/welcome")
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, body := serve(t, app, httptest.NewRequest(http.MethodPost, "/api/auth/sign-in", nil))
	if resp.StatusCode != http.StatusCreated || body != `{"ok":true}` {
		t.Errorf("got %d %s, want 201 {\"ok\":true}", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if id := resp.Header.Get("X-Request-ID"); id != "req-1" {
		t.Errorf("X-Request-ID = %q, want req-1", id)
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c
	}
	if len(cookies) != 2 || cookies["session_token"] == nil || !cookies["session_token"].HttpOnly || cookies["csrf"] == nil {
		t.Errorf("cookies = %v, want session_token (HttpOnly) and csrf", resp.Header.Values("Set-Cookie"))
	}

	resp, body = serve(t, app, httptest.NewRequest(http.MethodGet, "/api/auth/verify", nil))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://app.example.com/welcome" || body != "" {
		t.Errorf("got %d to %q with body %q, want an empty 302 to the welcome page", resp.StatusCode, resp.Header.Get("Location"), body)
	}
}

// Fiber routes a request URI with a broken percent escape. net/url does not
// parse it, so no request can be built for the handler.
func TestUnparsableRequestURIIsBadRequest(t *testing.T) {
	app := fiber.New()
	called := false
	if err := New(app).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(*types.RequestContext) error {
		called = true
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/users/x", nil)
	req.URL.Opaque = "/api/auth/users/%zz" // written to the request line as it is
	resp, _ := serve(t, app, req)
	if resp.StatusCode != http.StatusBadRequest || called {
		t.Errorf("status = %d, handler called = %v, want 400 without the handler", resp.StatusCode, called)
	}
}

// Fiber reuses a request's memory for the next request on the connection.
// Behemoth keeps what it read (a session's user agent, the RequestContext of
// a hook that runs in the background), so the first request has to read the
// same after the second has been served.
func TestRequestStaysValidAfterTheHandler(t *testing.T) {
	app := fiber.New()
	kept := make(chan *types.RequestContext, 2)
	if err := New(app).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		kept <- rctx
		return nil
	}}); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	t.Cleanup(func() { app.Shutdown() })

	// One client, so both requests travel on one connection.
	client := &http.Client{}
	for _, id := range []string{"aaaa", "bbbb"} {
		req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/api/auth/users/"+id+"?q="+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", "agent-"+id)
		req.Header.Set("X-Forwarded-For", "203.0.113."+id)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	first := <-kept
	for name, pair := range map[string][2]string{
		"path param": {first.Param("id"), "aaaa"},
		"URL.Path":   {first.Request.URL.Path, "/api/auth/users/aaaa"},
		"query":      {first.Request.URL.RawQuery, "q=aaaa"},
		"User-Agent": {first.Request.UserAgent(), "agent-aaaa"},
		"forwarded":  {first.Request.Header.Get("X-Forwarded-For"), "203.0.113.aaaa"},
		"Method":     {first.Request.Method, http.MethodGet},
	} {
		if pair[0] != pair[1] {
			t.Errorf("after a second request, the first request's %s = %q, want %q", name, pair[0], pair[1])
		}
	}
}
