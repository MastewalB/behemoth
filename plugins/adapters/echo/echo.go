package echo

import (
	"regexp"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/labstack/echo/v5"
)

type EchoDriver struct {
	e           *echo.Echo
	errorMapper types.ErrorMapper
}

func New(e *echo.Echo, errorMapper types.ErrorMapper) *EchoDriver {
	return &EchoDriver{
		e:           e,
		errorMapper: errorMapper,
	}
}

func (ed *EchoDriver) Mount(endpoints ...types.Route) {
	for _, ep := range endpoints {
		handler := ep.Handler
		ed.e.Add(ep.Method, toEchoPath(ep.Path), func(c *echo.Context) error {
			requestContext := buildRequestContext(c)

			if err := handler(requestContext); err != nil {
				status, body := ed.errorMapper.Map(err)
				return requestContext.Response.JSON(status, body)
				// return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			requestContext.Response.Flush(c.Response())
			return nil
		})
	}
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

func toEchoPath(path string) string {
	// Echo uses :param for path parameters, while Behemoth uses {param}. This function converts Behemoth-style paths to Echo-style paths.
	return regexp.MustCompile(`\{(\w+)\}`).ReplaceAllString(path, ":$1")
}
