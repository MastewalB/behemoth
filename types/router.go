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

	// TrustedProxies are the CIDR blocks (load balancers, reverse proxies)
	// allowed to set ClientIPHeader. Empty = the direct peer is the client.
	TrustedProxies []string
	ClientIPHeader string // default "X-Forwarded-For"
}

type Router struct {
	basePath    string
	routes      []mountedRoute
	errorMapper ErrorMapper
	routeOwners map[routeKey]string
	auth        *AuthContext
}

// The route method and full path must be unique (eg. "GET" - /api/auth/health )
type routeKey struct{ method, path string }

// mountedRoute is a route in the table plus the path route rate-limit rules
// are matched against. Rules are declared relative to BasePath (core cannot
// know the developer's BasePath), so a mounted route matches on its path
// below BasePath — MountPath + Route.Path — while an absolute route, which
// lives outside BasePath, matches on its full path.
type mountedRoute struct {
	Route
	matchPath string
}

// NewRouter returns an empty route table. auth is handed to every handler
// as RequestContext.Auth, so adapters never need to know about it.
func NewRouter(cfg RouterConfig, auth *AuthContext) *Router {
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	if cfg.ErrorMapper == nil {
		cfg.ErrorMapper = &behemotherr.DefaultErrorMapper{}
	}
	return &Router{
		basePath:    cfg.BasePath,
		errorMapper: cfg.ErrorMapper,
		routeOwners: map[routeKey]string{},
		auth:        auth,
	}
}

// Mount registers a plugin's endpoints under basePath + pluginMountPath +
// endpoint.Path, wrapping each in its declared Middlewares (Middlewares[0]
// executes first). Conflicts are reported for every endpoint at once.
func (r *Router) Mount(owner, pluginMountPath string, endpoints []Route) error {
	var duplicateErr []string
	for _, ep := range endpoints {
		fullPath := path.Join(r.basePath, pluginMountPath, ep.Path)
		if err := r.claim(owner, ep.Method, fullPath); err != "" {
			duplicateErr = append(duplicateErr, err)
			continue
		}

		h := ep.Handler
		for i := len(ep.Middlewares) - 1; i >= 0; i-- {
			h = ep.Middlewares[i](h)
		}
		r.routes = append(r.routes, mountedRoute{
			Route:     Route{Method: ep.Method, Path: fullPath, Handler: h},
			matchPath: path.Join("/", pluginMountPath, ep.Path),
		})
	}

	if len(duplicateErr) > 0 {
		return behemotherr.NewConfigurationError("Router.Mount",
			fmt.Sprintf("route conflicts detected: \n  %s", strings.Join(duplicateErr, "\n  ")),
			nil,
		)
	}
	return nil
}

// MountAbsolute registers routes at their exact Path, bypassing basePath and
// plugin-mount joining, for standards-fixed routes (like JWKS) that
// must not live under the developer's configured auth API prefix.
func (r *Router) MountAbsolute(owner string, routes ...Route) error {
	var duplicateErr []string
	for _, rt := range routes {
		if err := r.claim(owner, rt.Method, rt.Path); err != "" {
			duplicateErr = append(duplicateErr, err)
			continue
		}
		r.routes = append(r.routes, mountedRoute{
			Route:     Route{Method: rt.Method, Path: rt.Path, Handler: rt.Handler},
			matchPath: rt.Path,
		})
	}
	if len(duplicateErr) > 0 {
		return behemotherr.NewConfigurationError("Router.MountAbsolute",
			fmt.Sprintf("route conflicts detected: \n  %s", strings.Join(duplicateErr, "\n  ")),
			nil,
		)
	}
	return nil
}

// claim records owner for method+fullPath, or describes the conflict.
func (r *Router) claim(owner, method, fullPath string) string {
	key := routeKey{method: method, path: fullPath}
	if existingOwner, dup := r.routeOwners[key]; dup {
		return fmt.Sprintf("%s %s: claimed by both %q and %q", method, fullPath, existingOwner, owner)
	}
	r.routeOwners[key] = owner
	return ""
}

// Routes returns the resolved route table, for inspection and tests.
func (r *Router) Routes() []Route {
	routes := make([]Route, len(r.routes))
	for i, rt := range r.routes {
		routes[i] = rt.Route
	}
	return routes
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

func (r *Router) withAuth(next HandlerFunc) HandlerFunc {
	return func(rctx *RequestContext) error {
		rctx.Auth = r.auth
		return next(rctx)
	}
}

// ApplyRateLimiting resolves, for each mounted route, its single most-specific matching RouteRateLimitRule once,
// and wraps that route's handler accordingly. Rules are matched against a
// mounted route's path below BasePath, and an absolute route's full path
// (see mountedRoute).
// It should run after every Mount/MountAbsolute call and after the rate-limit catalog has frozen
// ideally making it the last step before Build hands routes to a FrameworkDriver
func (r *Router) ApplyRateLimiting(rl RateLimiter, catalog RateLimitCatalog, ipCfg *ClientIPConfig) {
	rules := catalog.RulesForRoute()
	for i, rt := range r.routes {
		rule, ok := BestRouteMatch(rules, rt.Method, rt.matchPath)
		if !ok || rule.Disabled {
			continue
		}
		r.routes[i].Handler = rateLimitWrap(rt.Handler, rule, rl, ipCfg)
	}
}

// Build wraps every route in the request pipeline and hands the table to
// driver. From outermost to innermost, a request passes through:
//
//	Auth injection -> error mapping -> global middlewares -> route rate limit -> route middlewares -> handler
//
// Error mapping sits outside everything that can fail, so an error from a
// middleware or the rate limiter becomes a response the same way a handler
// error does. Global middlewares wrap only behemoth's routes, never the rest
// of the application sharing the framework instance.
func (r *Router) Build(driver FrameworkDriver, globalMiddleware ...Middleware) error {
	routes := make([]Route, len(r.routes))
	for i, mr := range r.routes {
		rt := mr.Route
		h := rt.Handler
		for j := len(globalMiddleware) - 1; j >= 0; j-- {
			h = globalMiddleware[j](h)
		}
		rt.Handler = r.withAuth(r.wrapWithErrorMapping(h))
		routes[i] = rt
	}
	return driver.Mount(routes...)
}

// FrameworkDriver is the only seam between behemoth's plugin system and a
// concrete HTTP framework. Each framework (gin, echo, chi, ...) ships its own
// thin implementation, built around the application's own framework
// instance. The core never imports gin or echo directly.
//
// Mount tells the framework to mount the given Routes.
// How it does that is entirely up to the adapter:
//   - gin  - router.Handle(route.Method, route.Path, ginHandler)
//   - echo - e.Add(route.Method, route.Path, echoHandler)
//   - chi  - r.Method(route.Method, route.Path, httpHandler)
//
// Inside every adapter's handler, the pattern is always the same:
//  1. Build a *RequestContext from the framework's native request.
//  2. Call route.Handler(rc). Routes arrive fully wrapped: Auth is set and
//     errors are already mapped to responses, so a returned error means the
//     response itself could not be written.
//  3. Call rc.Response.Flush(underlying ResponseWriter).
type FrameworkDriver interface {
	// Mount registers handlers for every route. It returns an error, rather
	// than panicking, when the framework rejects a route (e.g. it conflicts
	// with one the application registered itself).
	Mount(routes ...Route) error
}

func rateLimitWrap(next HandlerFunc, rule RouteRateLimitRule, rl RateLimiter, ipCfg *ClientIPConfig) HandlerFunc {
	return func(rctx *RequestContext) error {

		if err := rl.CheckRouteLimit(rctx.Ctx, rule, rctx.Request, ipCfg); err != nil {
			return err
		}
		return next(rctx)
	}
}
