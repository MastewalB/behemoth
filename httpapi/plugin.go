package httpapi

import "github.com/MastewalB/behemoth/core"

// Plugin is a core.Plugin that serves HTTP routes. Boot mounts the routes of
// every plugin that implements it, below RouterConfig.BasePath and the
// plugin's PluginMeta.MountPath, after the plugin's Init. A plugin that only
// declares hooks, tables, or flows implements core.Plugin alone.
type Plugin interface {
	core.Plugin

	// Routes returns the HTTP endpoints this plugin wants to register.
	// Returning an empty slice is valid.
	Routes() []Route

	// Middlewares returns middleware functions that wrap every behemoth
	// route, not only the plugin's own. Boot applies those of all plugins
	// in plugin order, after the origin check.
	Middlewares() []Middleware
}

// RouteRulesPlugin is a core.Plugin with route rate-limit rules of its own.
// Prepare declares them after the plugin's Declare (DeclareRouteRules), and
// Boot applies them to every mounted route they match, the plugin's own or
// another's.
type RouteRulesPlugin interface {
	core.Plugin

	// RouteRateLimitRules returns the plugin's route rules. Their Owner is
	// set to the plugin's name.
	RouteRateLimitRules() []RouteRateLimitRule
}
