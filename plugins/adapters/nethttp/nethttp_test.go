package nethttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth/types"
)

func ok(*types.RequestContext) error { return nil }

func TestMountServesAndReportsConflicts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/taken", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })

	echoParam := types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]string{"id": rctx.Param("id")})
	}}
	if err := New(mux).Mount(echoParam); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/users/42", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"id":"42"}` {
		t.Errorf("got %d %s, want 200 {\"id\":\"42\"}", w.Code, w.Body.String())
	}

	conflict := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: ok}
	if err := New(mux).Mount(conflict); err == nil {
		t.Error("expected an error for a route the mux already has")
	}
	// The application's own handler must survive the rejected mount.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/taken", nil))
	if w.Code != http.StatusTeapot {
		t.Errorf("existing route status = %d, want 418 (not replaced)", w.Code)
	}
}

func TestMountRejectsDuplicatesWithinOneCall(t *testing.T) {
	err := New(http.NewServeMux()).Mount(
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
	)
	if err == nil {
		t.Error("expected an error for the same route twice")
	}
}

// The mux compares what patterns match, so a parameter under another name
// is still a conflict.
func TestMountConflictsWithDifferentlyNamedParam(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/users/{name}", func(http.ResponseWriter, *http.Request) {})
	err := New(mux).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: ok})
	if err == nil {
		t.Error("expected a conflict with the same pattern under another parameter name")
	}
}

func TestInvalidRouteIsErrorNotPanic(t *testing.T) {
	for name, rt := range map[string]types.Route{
		"no leading slash": {Method: http.MethodGet, Path: "no-leading-slash", Handler: ok},
		"no method":        {Path: "/api/auth/x", Handler: ok},
	} {
		if err := New(http.NewServeMux()).Mount(rt); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHandlerFailureIsInternalServerError(t *testing.T) {
	mux := http.NewServeMux()
	if err := New(mux).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/fail", Handler: func(*types.RequestContext) error {
		return http.ErrHandlerTimeout // routes arrive mapped; a returned error means the response could not be built
	}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/fail", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// A mux pattern ending in a slash matches a whole subtree. A behemoth route
// is one path.
func TestTrailingSlashMatchesOnePath(t *testing.T) {
	mux := http.NewServeMux()
	err := New(mux).Mount(
		types.Route{Method: http.MethodGet, Path: "/", Handler: ok},
		types.Route{Method: http.MethodGet, Path: "/api/auth/", Handler: ok},
	)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int{
		"/":               http.StatusOK,
		"/api/auth/":      http.StatusOK,
		"/other":          http.StatusNotFound,
		"/api/auth/other": http.StatusNotFound,
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("GET %s = %d, want %d", path, w.Code, want)
		}
	}
}

func teapot(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

// To the mux, a pattern without a method and a route with one do not
// conflict: the route would take its method from the application's handler
// and nothing would report it. The driver refuses the route.
func TestMountConflictsWithMethodlessPattern(t *testing.T) {
	for _, tc := range []struct{ pattern, path, request string }{
		{"/api/auth/any", "/api/auth/any", "/api/auth/any"},                      // the same path
		{"\t/api/auth/any", "/api/auth/any", "/api/auth/any"},                    // the same, written with a leading blank
		{"/api/auth/users/{name}", "/api/auth/users/{id}", "/api/auth/users/42"}, // another parameter name
		{"/api/auth/{action}", "/api/auth/any", "/api/auth/any"},                 // reaches the route through a wildcard
		{"/api/auth/any/{$}", "/api/auth/any/", "/api/auth/any/"},                // both end in a slash
	} {
		mux := http.NewServeMux()
		mux.HandleFunc(tc.pattern, teapot)
		if err := New(mux).Mount(types.Route{Method: http.MethodPost, Path: tc.path, Handler: ok}); err == nil {
			t.Errorf("POST %s on a mux with %q: expected an error", tc.path, tc.pattern)
		}
		// The application's handler still answers the method the route asked for.
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tc.request, nil))
		if w.Code != http.StatusTeapot {
			t.Errorf("POST %s on a mux with %q = %d, want 418 from the application", tc.request, tc.pattern, w.Code)
		}
	}
}

// A pattern for a subtree is the application's catch-all, and a pattern that
// names its methods is compared by the mux itself. Neither is refused.
func TestMountLeavesCatchAllsAndNamedMethodsAlone(t *testing.T) {
	for _, pattern := range []string{
		"/",
		"/api/",
		"/api/auth/{rest...}",
		"/api/auth/any/",          // a subtree below the route's path
		"/api/auth/any/{$}",       // the path with a trailing slash, which is another path to the mux
		"GET /api/auth/any",       // another method
		"POST /api/auth/{action}", // the route's method, on a less specific pattern
	} {
		mux := http.NewServeMux()
		mux.HandleFunc(pattern, teapot)
		err := New(mux).Mount(types.Route{Method: http.MethodPost, Path: "/api/auth/any", Handler: func(rctx *types.RequestContext) error {
			rctx.Response.Status(http.StatusNoContent)
			return nil
		}})
		if err != nil {
			t.Errorf("on a mux with %q: %v", pattern, err)
			continue
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/any", nil))
		if w.Code != http.StatusNoContent {
			t.Errorf("on a mux with %q: POST = %d, want 204 from the route", pattern, w.Code)
		}
	}
}

// The check asks the mux about a request, and a request it makes up has no
// host. A pattern with a host is not found, and on that host it wins. The
// driver's documentation warns about this.
func TestPatternWithAHostIsNotSeen(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("auth.example.com/api/auth/any", teapot)
	if err := New(mux).Mount(types.Route{Method: http.MethodPost, Path: "/api/auth/any", Handler: ok}); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{
		"auth.example.com": http.StatusTeapot, // the application's pattern
		"example.org":      http.StatusOK,     // the route
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/any", nil)
		req.Host = host
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("POST on %s = %d, want %d", host, w.Code, want)
		}
	}
}
