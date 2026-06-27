package gin

import (
	"github.com/MastewalB/behemoth/plugins"
	"github.com/gin-gonic/gin"
)

func init() {
	plugins.RegisterFrameworkDriver(
		"gin",
		&GinDriver{},
	)
}

type GinDriver struct {
}

func (gd *GinDriver) Mount(router any, endpoints ...plugins.Route) {
	r := router.(*gin.RouterGroup)

	for _, ep := range endpoints {
		handler := ep.Handler
		r.Handle(ep.Method, ep.Path,
			func(ctx *gin.Context) {
				handler(ctx.Request.Context())
			},
		)
	}
}
