package echo

import (
	"net/http"

	"github.com/MastewalB/behemoth/plugins"
	"github.com/MastewalB/behemoth/types"
	"github.com/labstack/echo/v5"
)

type EchoDriver struct {
	e *echo.Echo
}

func New(e *echo.Echo) *EchoDriver {
	return &EchoDriver{e: e}
}

func (ed *EchoDriver) Mount(endpoints ...plugins.Route) {
	for _, ep := range endpoints {
		handler := ep.Handler
		ed.e.Add(ep.Method, ep.Path, func(c *echo.Context) error {
			requestContext := &types.RequestContext{
				Ctx: c.Request().Context(),
				Request: c.Request(),
				Response: types.NewResponseRecorder(),
				Values: make(types.M),
			}

			if err := handler(requestContext); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			requestContext.Response.Flush(c.Response())
			return nil
		})
	}
}
