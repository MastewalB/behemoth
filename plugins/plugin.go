package plugins

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/types"
)

type HandlerFunc func(ctx *types.RequestContext) error

// Route describes a single HTTP endpoint a plugin wants to expose.
// The Handler receives a framework-agnostic RequestContext and writes its
// response into rc.Response
type Route struct {
	Method      string       // "GET", "POST", "PUT", "DELETE" ...
	Path        string       // "/plugin-name/some-action"
	Handler     HandlerFunc  // the core logic for this route
	Middlewares []Middleware // optional, run left-to-right before Handler
}

type Plugin interface {
	// Name returns a unique, human-readable identifier, e.g. "two-factor".
	Name() string

	// Version is the plugin version. e.g. "1.0.0"
	Version() string

	// Init is called once when behemoth starts up.
	// Plugins receive a PluginContext that contains access to core services.
	Init(ctx *types.AuthContext) error

	// Routes returns the HTTP endpoints this plugin wants to register.
	// Returning an empty slice is valid (the plugin may only use hooks).
	Routes() []Route

	// Middlewares() returns middleware functions and their paths this plugin wants to mount on.
	Middlewares() []PathMiddleware
}

// Middleware is a named function that wraps a HandlerFunc.
// It receives the RequestContext and a `next` function to call the next
// handler in the chain. Not calling next short-circuits the chain (useful
// for auth guards that want to reject a request early).
//
// Example: a minimal logger middleware:
//
//	plugin.Middleware{
//	    Name: "logger",
//	    Handle: func(rc *plugin.RequestContext, next plugin.HandlerFunc) error {
//	        log.Printf("--> %s %s", rc.Request.Method, rc.Request.URL.Path)
//	        err := next(rc)
//	        log.Printf("<-- %d", rc.Response.Code)
//	        return err
//	    },
//	}
type Middleware struct {
	Name   string
	Handle func(rc *types.RequestContext, next HandlerFunc) error
}

type PathMiddleware struct {
	Path string
	Fn   Middleware
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

	// MountMiddleware registers middlewares on their paths.
	//
	// The param order matters. They are registered from left to right (Left - Outermost, Right - Innermost)
	MountMiddleware(middlewares ...PathMiddleware)
}

var frameworkDriverRegistry = map[string]FrameworkDriver{}

func RegisterFrameworkDriver(name string, driver FrameworkDriver) {
	frameworkDriverRegistry[name] = driver
}

func DetectPluginNameConflicts(plugins []Plugin) error {
	var conflicts strings.Builder
	var conflictDetected bool

	seen := make(map[string]int, len(plugins))
	for _, p := range plugins {
		if _, exists := seen[p.Name()]; exists {
			conflictDetected = true
			seen[p.Name()] += 1
		}
		seen[p.Name()] += 1
	}

	if conflictDetected {
		conflicts.WriteString("Conflicting plugin names: \n")
		for k, v := range seen {
			if v > 1 {
				fmt.Fprintf(&conflicts, "\t %s - used %d times.\n", k, v)
			}
		}
		return fmt.Errorf("%s", conflicts.String())
	}

	return nil
}

// The route method and path must be unique (eg. "GET" - /health )
type routeKey struct{ method, path string }

func DetectPluginRouteConflicts(plugins []Plugin) error {
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
					key.method, key.path, owner, p.Name(),
				))
			} else {
				registered[key] = p.Name()
			}
		}
	}

	if len(errs) > 0 {
		return errors.New("route conflicts detected:\n  " + strings.Join(errs, "\n  "))
	}

	return nil
}

func ChainPluginMiddlewares(handler HandlerFunc, middlewares []Middleware) HandlerFunc {

	for i := len(middlewares) - 1; i >= 0; i-- {
		mw := middlewares[i]
		next := handler
		handler = func(rc *types.RequestContext) error {
			return mw.Handle(rc, next)
		}
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
