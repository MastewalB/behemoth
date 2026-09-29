package plugins

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/types"
)

var frameworkDriverRegistry = map[string]types.FrameworkDriver{}

func RegisterFrameworkDriver(name string, driver types.FrameworkDriver) {
	frameworkDriverRegistry[name] = driver
}

// The route method and path must be unique (eg. "GET" - /health )
type routeKey struct{ method, path string }

func DetectPluginRouteConflicts(plugins []types.Plugin) error {
	registered := make(map[routeKey]string)
	var errs []string

	for _, p := range plugins {
		for _, route := range p.Routes() {
			key := routeKey{
				method: route.Method,
				path:   route.Path,
			}
			if owner, exists := registered[key]; exists {
				errs = append(errs, fmt.Sprintf(
					"%s %s: claimed by both %q and %q",
					key.method, key.path, owner, p.Meta().Name,
				))
			} else {
				registered[key] = p.Meta().Name
			}
		}
	}

	if len(errs) > 0 {
		return errors.New("route conflicts detected:\n  " + strings.Join(errs, "\n  "))
	}

	return nil
}

func ChainPluginMiddlewares(handler types.HandlerFunc, middlewares []types.Middleware) types.HandlerFunc {

	for i := len(middlewares) - 1; i >= 0; i-- {
		mw := middlewares[i]
		next := handler
		handler = mw(next)
	}

	return handler

	// return func(ctx *types.RequestContext) error {
	// 	var curr = -1

	// 	var next func(ctx *types.RequestContext) error
	// 	next = func(ctx *types.RequestContext) error {
	// 		if curr == len(middlewares)-1 {
	// 			return handler(ctx)
	// 		}
	// 		curr++
	// 		return middlewares[curr].Handle(ctx, next)
	// 	}

	// 	return next(ctx)
	// }
}
