package gin

import (
	"regexp"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/gin-gonic/gin"
)

type GinDriver struct {
	errorMapper types.ErrorMapper
	router      *gin.Engine
}

func New(router *gin.Engine, errorMapper types.ErrorMapper) *GinDriver {
	return &GinDriver{
		router:      router,
		errorMapper: errorMapper,
	}
}

func toGinPath(path string) string {
	// Gin uses :param for path parameters, while Behemoth uses {param}. This function converts Behemoth-style paths to Gin-style paths.
	return regexp.MustCompile(`\{(\w+)\}`).ReplaceAllString(path, ":$1")
}

func (gd *GinDriver) Mount(endpoints ...types.Route) {

	for _, ep := range endpoints {
		handler := ep.Handler
		gd.router.Handle(ep.Method, toGinPath(ep.Path), func(c *gin.Context) {

			requestContext := buildRequestContext(c)

			if err := handler(requestContext); err != nil {
				status, body := gd.errorMapper.Map(err)
				requestContext.Response.JSON(status, body)
				// c.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			requestContext.Response.Flush(c.Writer)
		},
		)
	}
}

func (gd *GinDriver) MountMiddleware(middlewares ...types.Middleware) {

	ginMiddlewares := make([]gin.HandlerFunc, len(middlewares))
	for _, mw := range middlewares {

		ginMiddlewares = append(ginMiddlewares, func(c *gin.Context) {
			ginNextCaller := func() { c.Next() }
			requestContext := buildRequestContext(c)

			if err := mw(func(rctx *types.RequestContext) error {
				ginNextCaller()
				return nil
			})(requestContext); err != nil {
				status, body := gd.errorMapper.Map(err)
				requestContext.Response.JSON(status, body)
				// c.AbortWithError(http.StatusInternalServerError, err)
				return
			}

		})
	}

	gd.router.Use(ginMiddlewares...)
}

func buildRequestContext(c *gin.Context) *types.RequestContext {
	params := make(map[string]string)
	for _, p := range c.Params {
		params[p.Key] = p.Value
	}

	return &types.RequestContext{
		Ctx:      c.Request.Context(),
		Request:  c.Request,
		Response: types.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}
}
