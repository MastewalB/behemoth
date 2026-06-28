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

			requestContext := &types.RequestContext{
				Ctx:      c.Request.Context(),
				Request:  c.Request,
				Response: types.NewResponseRecorder(),
				Values:   make(types.M),
			}

			if err := handler(requestContext); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			requestContext.Response.Flush(c.Writer)
		},
		)
	}
}
