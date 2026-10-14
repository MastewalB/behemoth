package echo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth/types"
	"github.com/labstack/echo/v5"
)

func TestMountServesAndReportsConflicts(t *testing.T) {
	e := echo.New()
	e.GET("/api/auth/taken", func(c *echo.Context) error { return c.NoContent(http.StatusTeapot) })

	echoParam := types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]string{"id": rctx.Param("id")})
	}}
	if err := New(e).Mount(echoParam); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/users/42", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"id":"42"}` {
		t.Errorf("got %d %s, want 200 {\"id\":\"42\"}", w.Code, w.Body.String())
	}

	conflict := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: func(*types.RequestContext) error { return nil }}
	if err := New(e).Mount(conflict); err == nil {
		t.Error("expected an error for a route the server already has")
	}
}

func TestHandlerFailureIsInternalServerError(t *testing.T) {
	e := echo.New()
	failing := types.Route{Method: http.MethodGet, Path: "/api/auth/fail", Handler: func(*types.RequestContext) error {
		return http.ErrHandlerTimeout // routes arrive mapped; a returned error means the response could not be built
	}}
	if err := New(e).Mount(failing); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/fail", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
