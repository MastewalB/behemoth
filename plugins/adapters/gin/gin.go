package gin

import (
	"net/http"

	"github.com/MastewalB/behemoth/plugins"
	"github.com/MastewalB/behemoth/types"
	"github.com/gin-gonic/gin"
)

type GinDriver struct {
	router *gin.Engine
}

func New(router *gin.Engine) *GinDriver {
	return &GinDriver{router: router}
}

func (gd *GinDriver) Mount(endpoints ...plugins.Route) {

	for _, ep := range endpoints {
		handler := ep.Handler
		gd.router.Handle(ep.Method, ep.Path, func(c *gin.Context) {

			requestContext := buildRequestContext(c)

			if err := handler(requestContext); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			requestContext.Response.Flush(c.Writer)
		},
		)
	}
}

func (gd *GinDriver) MountMiddleware(middlewares ...plugins.PathMiddleware) {

	ginMiddlewares := make([]gin.HandlerFunc, len(middlewares))
	for _, mw := range middlewares {

		ginMiddlewares = append(ginMiddlewares, func(c *gin.Context) {
			ginNextCaller := func() { c.Next() }
			requestContext := buildRequestContext(c)

			if err := mw.Fn.Handle(requestContext, func(c *types.RequestContext) error {
				ginNextCaller()
				return nil
			}); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}

		})
	}

	gd.router.Use(ginMiddlewares...)
}

func buildRequestContext(c *gin.Context) *types.RequestContext {
	return &types.RequestContext{
		Ctx:      c.Request.Context(),
		Request:  c.Request,
		Response: types.NewResponseRecorder(),
		Values:   make(types.M),
	}
}
