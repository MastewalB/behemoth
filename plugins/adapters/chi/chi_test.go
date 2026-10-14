package chi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth/types"
	"github.com/go-chi/chi/v5"
)

func TestMountServesAndReportsConflicts(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/api/auth/taken", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })

	echoParam := types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]string{"id": rctx.Param("id")})
	}}
	if err := New(r).Mount(echoParam); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/users/42", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"id":"42"}` {
		t.Errorf("got %d %s, want 200 {\"id\":\"42\"}", w.Code, w.Body.String())
	}

	conflict := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: func(*types.RequestContext) error { return nil }}
	if err := New(r).Mount(conflict); err == nil {
		t.Error("expected an error for a route the router already has")
	}
	// The application's own handler must survive the rejected mount.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/taken", nil))
	if w.Code != http.StatusTeapot {
		t.Errorf("existing route status = %d, want 418 (not replaced)", w.Code)
	}
}

func TestMountRejectsDuplicatesWithinOneCall(t *testing.T) {
	ok := func(*types.RequestContext) error { return nil }
	err := New(chi.NewRouter()).Mount(
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
		types.Route{Method: http.MethodPost, Path: "/api/auth/x", Handler: ok},
	)
	if err == nil {
		t.Error("expected an error for the same route twice")
	}
}

func TestInvalidRouteIsErrorNotPanic(t *testing.T) {
	err := New(chi.NewRouter()).Mount(types.Route{Method: http.MethodGet, Path: "no-leading-slash", Handler: func(*types.RequestContext) error { return nil }})
	if err == nil {
		t.Error("expected an error for a pattern chi rejects")
	}
}

func TestHandlerFailureIsInternalServerError(t *testing.T) {
	r := chi.NewRouter()
	if err := New(r).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/fail", Handler: func(*types.RequestContext) error {
		return http.ErrHandlerTimeout
	}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/fail", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMountConflictsWithAllMethodsRoute(t *testing.T) {
	r := chi.NewRouter()
	r.Handle("/api/auth/any", http.NotFoundHandler()) // registered for every method
	err := New(r).Mount(types.Route{Method: http.MethodPost, Path: "/api/auth/any", Handler: func(*types.RequestContext) error { return nil }})
	if err == nil {
		t.Error("expected a conflict with a route registered for all methods")
	}
}
