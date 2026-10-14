package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth/types"
	"github.com/gin-gonic/gin"
)

func TestMountServesAndReportsConflicts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/api/auth/taken", func(c *gin.Context) { c.Status(http.StatusTeapot) })

	echoParam := types.Route{Method: http.MethodGet, Path: "/api/auth/users/{id}", Handler: func(rctx *types.RequestContext) error {
		return rctx.Response.JSON(http.StatusOK, map[string]string{"id": rctx.Param("id")})
	}}
	if err := New(engine).Mount(echoParam); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/users/42", nil))
	if w.Code != http.StatusOK || w.Body.String() != `{"id":"42"}` {
		t.Errorf("got %d %s, want 200 {\"id\":\"42\"}", w.Code, w.Body.String())
	}

	conflict := types.Route{Method: http.MethodGet, Path: "/api/auth/taken", Handler: func(*types.RequestContext) error { return nil }}
	if err := New(engine).Mount(conflict); err == nil {
		t.Error("expected an error for a route the engine already has")
	}
}

func TestHandlerFailureIsInternalServerError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if err := New(engine).Mount(types.Route{Method: http.MethodGet, Path: "/api/auth/fail", Handler: func(*types.RequestContext) error {
		return http.ErrHandlerTimeout // routes arrive mapped; a returned error means the response could not be built
	}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/fail", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
