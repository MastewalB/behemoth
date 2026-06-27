package plugins

import (
	"context"

	"github.com/MastewalB/behemoth/types"
)

type HandlerFunc func(ctx context.Context) error

// Route describes a single HTTP endpoint a plugin wants to expose.
// The Handler receives a framework-agnostic RequestContext and writes its
// response into rc.Response
type Route struct {
	Method  string
	Path    string
	Handler HandlerFunc
}

type Plugin interface {
	Name() string

	Version() string

	// Init is called once when behemoth starts up.
	// Plugins receive a PluginContext that contains access to core services.
	Init(ctx *types.AuthContext) error

	// Routes returns the HTTP endpoints this plugin wants to register.
	// Returning an empty slice is valid (the plugin may only use hooks).
	Routes() []Route
}

type FrameworkDriver interface {
	Mount(router any, endpoints ...Route)
}

var frameworkDriverRegistry = map[string]FrameworkDriver{}

func RegisterFrameworkDriver(name string, driver FrameworkDriver) {
	frameworkDriverRegistry[name] = driver
}
