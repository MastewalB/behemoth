package types

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

type RouterConfig struct {
	BasePath       string      // default "/api/auth"
	ErrorMapper    ErrorMapper // default DefaultErrorMapper{}
	TrustedOrigins []string
}

type Router struct {
	basePath    string
	routes      []Route
	errorMapper ErrorMapper
	routeOwners map[routeKey]string
}

// The route method and path must be unique (eg. "GET" - /health )
type routeKey struct{ method, path string }

func NewRouter(cfg RouterConfig) *Router {
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	if cfg.ErrorMapper == nil {
		cfg.ErrorMapper = &behemotherr.DefaultErrorMapper{}
	}
	return &Router{basePath: cfg.BasePath, errorMapper: cfg.ErrorMapper}
}

// Mount registers a plugin's endpoints under basePath + pluginMountPath +
// endpoint.Path, wrapping each in its declared Middlewares (innermost-last:
// Middlewares[0] executes first) and in a handler that converts any
// returned error through the shared ErrorMapper
func (r *Router) Mount(owner, pluginMountPath string, endpoints []Route) error {
	var duplicateErr []string
	for _, ep := range endpoints {
		fullPath := path.Join(r.basePath, pluginMountPath, ep.Path)
		key := routeKey{
			method: ep.Method,
			path:   ep.Path,
		}
		if existingOwner, dup := r.routeOwners[key]; dup {
			duplicateErr = append(duplicateErr, fmt.Sprintf(
				"%s %s: claimed by both %q and %q",
				key.method, key.path, existingOwner, owner,
			))
		}
		r.routeOwners[key] = owner

		h := r.wrapWithErrorMapping(ep.Handler)
		for i := len(ep.Middlewares) - 1; i >= 0; i-- {
			h = ep.Middlewares[i](h)
		}
		r.routes = append(r.routes, Route{Method: ep.Method, Path: fullPath, Handler: h})
	}

	if len(duplicateErr) > 0 {
		return behemotherr.NewConfigurationError("Router.Mount",
			fmt.Sprintf("route conflicts detected: \n  %s", strings.Join(duplicateErr, "\n  ")),
			nil,
		)
	}
	return nil

	// for _, ep := range endpoints {
	// 	fullPath := path.Join(r.basePath, mountPath, ep.Path)
	// 	routeKey := ep.Method + " " + fullPath
	// 	if existingOwner, dup := r.routeOwners[routeKey]; dup {
	// 		return behemotherr.NewConfigurationError("Router.Mount",
	// 			fmt.Sprintf("route %s already mounted by plugin %q, cannot also mount from %q", routeKey, existingOwner, owner), nil)
	// 	}
	// 	r.routeOwners[routeKey] = owner

	// 	h := r.wrapWithErrorMapping(ep.Handler)
	// 	for i := len(ep.Middlewares) - 1; i >= 0; i-- {
	// 		h = ep.Middlewares[i](h)
	// 	}
	// 	r.routes = append(r.routes, resolvedRoute{Method: ep.Method, Path: fullPath, Handler: h})
	// }
	// return nil
}

// MountAbsolute registers routes at their exact Path, bypassing basePath and
// plugin-mount joining, for standards-fixed routes (like JWKS) that
// must not live under the developer's configured auth API prefix.
func (r *Router) MountAbsolute(routes ...Route) {
	for _, rt := range routes {
		r.routes = append(r.routes, Route{Method: rt.Method, Path: rt.Path, Handler: r.wrapWithErrorMapping(rt.Handler)})
	}
}

func (r *Router) wrapWithErrorMapping(next HandlerFunc) HandlerFunc {
	return func(rctx *RequestContext) error {
		if err := next(rctx); err != nil {
			status, body := r.errorMapper.Map(err)
			if de, ok := errors.AsType[*behemotherr.DomainError](err); ok && de.RetryAfter > 0 {
				rctx.Response.Headers.Set("Retry-After", strconv.Itoa(int(de.RetryAfter.Seconds())))
			}
			return rctx.Response.JSON(status, body)
		}
		return nil
	}
}

// ApplyRateLimiting resolves, for each mounted route, its single most-specific matching RouteRateLimitRule once,
// and wraps that route's handler accordingly.
// It should run after every Mount/MountAbsolute call and after the rate-limit catalog has frozen
// ideally making it the last step before Build hands routes to a FrameworkDriver
func (r *Router) ApplyRateLimiting(rl RateLimiter, catalog RateLimitCatalog, ipCfg *ClientIPConfig) {
	rules := catalog.RulesForRoute()
	for i, rt := range r.routes {
		rule, ok := BestRouteMatch(rules, rt.Method, rt.Path)
		if !ok || rule.Disabled {
			continue
		}
		r.routes[i].Handler = rateLimitWrap(rt.Handler, rule, rl, ipCfg)
	}
}

// Build hands the fully resolved route table to a FrameworkDriver
// Returns the driver's native mountable value (http.Handler, *chi.Mux, *gin.Engine).
func (r *Router) Build(driver FrameworkDriver, globalMiddleware ...Middleware) any {
	driver.MountMiddleware(globalMiddleware...)
	driver.Mount(r.routes...)
	// return driver.Handler()
	return nil
}

// FrameworkDriver is the only seam between behemoth's plugin system and a
// concrete HTTP framework. Each framework (gin, echo, chi, ...) ships its own
// thin implementation. The core never imports gin or echo directly.
//
// Mount tells the framework to mount the given Route.
// How it does that is entirely up to the adapter:
//   - gin  - router.Handle(route.Method, route.Path, ginHandler)
//   - echo - e.Add(route.Method, route.Path, echoHandler)
//   - chi  - r.Method(route.Method, route.Path, httpHandler)
//
// Inside every adapter's handler, the pattern is always the same:
//  1. Build a *RequestContext from the framework's native request.
//  2. Call route.Handler(rc).
//  3. Call rc.Response.Flush(underlying ResponseWriter).
type FrameworkDriver interface {

	// Mount registers handlers for a path.
	Mount(endpoints ...Route)

	// MountMiddleware registers global middlewares.
	//
	// The param order matters. They are registered from left to right (Left - Outermost, Right - Innermost)
	MountMiddleware(middlewares ...Middleware)
}

// func (r *Router) ApplyRateLimiting(rl RateLimiter, catalog RateLimitCatalog, ipCfg *ClientIPConfig) {
// 	rules := catalog.RouteRules()
// 	for i, rt := range r.routes {
// 		rule, ok := BestRouteMatch(rules, rt.Method, rt.Path)
// 		if !ok || rule.Disabled {
// 			continue // no matching rule, or the most specific match is an explicit exemption — leave the handler untouched
// 		}
// 		r.routes[i].Handler = rateLimitWrap(rt.Handler, rule, rl, ipCfg)
// 	}
// }

func rateLimitWrap(next HandlerFunc, rule RouteRateLimitRule, rl RateLimiter, ipCfg *ClientIPConfig) HandlerFunc {
	return func(rctx *RequestContext) error {

		if err := rl.CheckRouteLimit(rctx.Ctx, rule, rctx.Request, ipCfg); err != nil {
			return err
		}
		return next(rctx)
	}
}
