// Package echo mounts behemoth's routes onto an application's *echo.Echo:
//
//	e := echo.New()
//	ac, err := engine.Boot(ctx, app, db, engine.BootConfig{HTTP: echoadapter.New(e), ...})
package echo

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/httpapi"
	"github.com/labstack/echo/v5"
)

type EchoDriver struct {
	e *echo.Echo
}

func New(e *echo.Echo) *EchoDriver {
	return &EchoDriver{e: e}
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// toEchoPath converts behemoth's {param} path parameters to echo's :param.
func toEchoPath(path string) string {
	return pathParam.ReplaceAllString(path, ":$1")
}

// Mount implements [httpapi.FrameworkDriver]. It returns an error for a route
// that the Echo instance already has with the same method and path.
//
// The adapter checks this itself. Echo v5.4 and later let echo.New overwrite a
// duplicate route without an error, and a route of Behemoth must never replace
// one of the application's, or be replaced by it, unnoticed.
func (ed *EchoDriver) Mount(routes ...httpapi.Route) error {
	for _, rt := range routes {
		handler := rt.Handler
		path := toEchoPath(rt.Path)
		for _, existing := range ed.e.Router().Routes() {
			if existing.Method == rt.Method && existing.Path == path {
				return fmt.Errorf("echo: cannot mount %s %s: the server already has that route", rt.Method, rt.Path)
			}
		}
		_, err := ed.e.AddRoute(echo.Route{
			Method: rt.Method,
			Path:   path,
			Handler: func(c *echo.Context) error {
				rctx := buildRequestContext(c)
				if err := handler(rctx); err != nil {
					// Routes arrive with errors already mapped to responses; an
					// error here means the response itself could not be built.
					return c.NoContent(http.StatusInternalServerError)
				}
				rctx.Response.Flush(c.Response())
				return nil
			},
		})
		if err != nil {
			return fmt.Errorf("echo: cannot mount %s %s: %w", rt.Method, rt.Path, err)
		}
	}
	return nil
}

func buildRequestContext(c *echo.Context) *httpapi.RequestContext {
	params := make(map[string]string)
	for _, p := range c.PathValues() {
		params[p.Name] = p.Value
	}

	return &httpapi.RequestContext{
		Ctx:      c.Request().Context(),
		Request:  c.Request(),
		Response: httpapi.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}
}

var _ httpapi.FrameworkDriver = (*EchoDriver)(nil)
