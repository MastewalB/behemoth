// Package gin mounts behemoth's routes onto an application's *gin.Engine:
//
//	engine := gin.New()
//	ac, err := binit.Boot(ctx, app, db, binit.BootConfig{HTTP: ginadapter.New(engine), ...})
//
// Behemoth's routes then live on engine next to the application's own.
package gin

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/gin-gonic/gin"
)

type GinDriver struct {
	router gin.IRoutes
}

// New returns a driver mounting onto router: a *gin.Engine, or a
// *gin.RouterGroup to put behemoth's routes behind the group's prefix and
// middleware.
func New(router gin.IRoutes) *GinDriver {
	return &GinDriver{router: router}
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// toGinPath converts behemoth's {param} path parameters to gin's :param.
func toGinPath(path string) string {
	return pathParam.ReplaceAllString(path, ":$1")
}

// Mount implements [types.FrameworkDriver]. gin panics on a route it
// already has; that panic is returned as an error instead.
func (gd *GinDriver) Mount(routes ...types.Route) error {
	for _, rt := range routes {
		if err := gd.handle(rt); err != nil {
			return err
		}
	}
	return nil
}

func (gd *GinDriver) handle(rt types.Route) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gin: cannot mount %s %s: %v", rt.Method, rt.Path, r)
		}
	}()

	handler := rt.Handler
	gd.router.Handle(rt.Method, toGinPath(rt.Path), func(c *gin.Context) {
		rctx := buildRequestContext(c)
		if err := handler(rctx); err != nil {
			// Routes arrive with errors already mapped to responses; an
			// error here means the response itself could not be built.
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		rctx.Response.Flush(c.Writer)
	})
	return nil
}

func buildRequestContext(c *gin.Context) *types.RequestContext {
	params := make(map[string]string, len(c.Params))
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

var _ types.FrameworkDriver = (*GinDriver)(nil)
