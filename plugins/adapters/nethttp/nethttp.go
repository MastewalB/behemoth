// Package nethttp mounts behemoth's routes onto an application's
// *http.ServeMux, the standard library's router:
//
//	mux := http.NewServeMux()
//	ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{HTTP: nethttp.New(mux), ...})
//
// It needs nothing outside the standard library, so unlike the gin, echo,
// chi and fiber adapters it is part of behemoth's own module. The mux and
// behemoth share the {param} path syntax, so paths are used as-is.
//
// Register the application's own patterns on the mux before Boot. Mount
// checks behemoth's routes against the patterns the mux has at that moment;
// see [ServeMuxDriver.Mount] for what the check covers and what it cannot
// see.
package nethttp

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
)

// ServeMuxDriver mounts behemoth's routes onto a *http.ServeMux.
type ServeMuxDriver struct {
	mux *http.ServeMux
}

// New returns a driver mounting onto mux. To put behemoth's routes behind
// the application's own middleware, give behemoth a mux of its own and
// register that mux, wrapped, on the application's:
//
//	authMux := http.NewServeMux()
//	// Boot with HTTP: nethttp.New(authMux), then:
//	mux.Handle("/api/auth/", logRequests(authMux))
func New(mux *http.ServeMux) *ServeMuxDriver {
	return &ServeMuxDriver{mux: mux}
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// toMuxPattern builds the mux pattern for a route: "METHOD /path".
//
// The mux treats a pattern that ends in a slash as a prefix: "/" matches
// every path. A behemoth route is one path on every other framework, so a
// trailing slash gets the mux's {$} marker, which matches that path only.
func toMuxPattern(method, path string) string {
	if strings.HasSuffix(path, "/") {
		path += "{$}"
	}
	return method + " " + path
}

// Mount implements [types.FrameworkDriver]. A route is refused, with an
// error, in two cases.
//
// The mux refuses it: it panics on a pattern it cannot parse and on one that
// matches the same requests as a pattern it already has, however the
// parameters are named. The panic is returned as an error.
//
// The application already answers the route's path without naming a method.
// To the mux, "/api/auth/session" and "POST /api/auth/session" do not
// conflict: it gives POST to the more specific pattern and leaves the other
// methods with the first, so the application's handler would lose POST
// without a word. Mount looks for this before it registers a route (see
// methodlessPattern). Patterns for a whole subtree, such as "/" and "/api/",
// are the application's catch-alls and are left alone.
//
// The second check has limits an application has to mind:
//
//   - It sees the patterns the mux has when Mount runs. A pattern without a
//     method that the application registers afterwards is accepted by the
//     mux and loses the route's method to behemoth.
//   - It does not see a pattern with a host ("example.com/api/auth/session").
//     On that host the mux prefers the application's pattern, and behemoth's
//     route is not reached there.
//   - It sees this driver's mux only. When that is a mux of behemoth's own,
//     registered on the application's under "/api/auth/" (see New), a more
//     specific pattern on the application's mux takes the requests first.
//   - It also refuses a pattern without a method that reaches the route
//     through a wildcard, such as "/api/auth/{action}". Naming the pattern's
//     methods ("GET /api/auth/{action}") takes it out of the check.
func (sd *ServeMuxDriver) Mount(routes ...types.Route) error {
	for _, rt := range routes {
		if err := sd.handle(rt); err != nil {
			return err
		}
	}
	return nil
}

func (sd *ServeMuxDriver) handle(rt types.Route) (err error) {
	// A mux pattern without a method matches every method, so a route that
	// names none would answer all of them.
	if rt.Method == "" {
		return fmt.Errorf("nethttp: cannot mount %s: route has no method", rt.Path)
	}
	if pattern := sd.methodlessPattern(rt); pattern != "" {
		return fmt.Errorf("nethttp: cannot mount %s %s: the mux already has %q, a pattern without a method that answers %s too",
			rt.Method, rt.Path, pattern, rt.Method)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("nethttp: cannot mount %s %s: %v", rt.Method, rt.Path, r)
		}
	}()

	handler := rt.Handler
	names := paramNames(rt.Path)
	sd.mux.HandleFunc(toMuxPattern(rt.Method, rt.Path), func(w http.ResponseWriter, r *http.Request) {
		rctx := buildRequestContext(r, names)
		if err := handler(rctx); err != nil {
			// Routes arrive with errors already mapped to responses; an
			// error here means the response itself could not be built.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rctx.Response.Flush(w)
	})
	return nil
}

// methodlessPattern returns the application's pattern that answers rt's
// requests without naming a method, or "" when there is none.
//
// The mux cannot list its patterns, but Handler reports the pattern it would
// give a request to. So this asks about a request rt would match, with a
// made-up value for each parameter, before rt is registered. Only the best
// match comes back, which is the one rt would take the method from.
func (sd *ServeMuxDriver) methodlessPattern(rt types.Route) string {
	path := pathParam.ReplaceAllString(rt.Path, "x")
	_, pattern := sd.mux.Handler(&http.Request{Method: rt.Method, URL: &url.URL{Path: path}})
	switch {
	case pattern == "":
		// Nothing answers this method and path yet.
	case strings.IndexAny(pattern, " \t") > 0:
		// The pattern names a method, so the mux compares it with rt's
		// pattern itself when rt is registered.
	case strings.HasSuffix(pattern, "/"), strings.HasSuffix(pattern, "...}"):
		// A subtree: the application's catch-all for what nothing more
		// specific claims.
	case strings.HasSuffix(pattern, "{$}") && !strings.HasSuffix(path, "/"):
		// The pattern answers path + "/" only. It came back because the
		// mux would redirect there.
	default:
		return pattern
	}
	return ""
}

// paramNames returns the names of path's {param} parameters. A request
// gives a parameter's value by name only (Request.PathValue), so the names
// are read from the route once, when it is mounted.
func paramNames(path string) []string {
	matches := pathParam.FindAllStringSubmatch(path, -1)
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m[1]
	}
	return names
}

func buildRequestContext(r *http.Request, names []string) *types.RequestContext {
	params := make(map[string]string, len(names))
	for _, name := range names {
		params[name] = r.PathValue(name)
	}

	return &types.RequestContext{
		Ctx:      r.Context(),
		Request:  r,
		Response: types.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}
}

var _ types.FrameworkDriver = (*ServeMuxDriver)(nil)
