// Package echo mounts behemoth's routes onto an application's *echo.Echo:
//
//	e := echo.New()
//	ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{HTTP: echoadapter.New(e), ...})
package echo

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
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

// Mount implements [types.FrameworkDriver].
func (ed *EchoDriver) Mount(routes ...types.Route) error {
	for _, rt := range routes {
		handler := rt.Handler
		_, err := ed.e.AddRoute(echo.Route{
			Method: rt.Method,
			Path:   toEchoPath(rt.Path),
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

func buildRequestContext(c *echo.Context) *types.RequestContext {
	params := make(map[string]string)
	for _, p := range c.PathValues() {
		params[p.Name] = p.Value
	}

	return &types.RequestContext{
		Ctx:      c.Request().Context(),
		Request:  c.Request(),
		Response: types.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}
}

var _ types.FrameworkDriver = (*EchoDriver)(nil)
