// Package chi mounts behemoth's routes onto an application's chi.Router:
//
//	r := chi.NewRouter()
//	ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{HTTP: chiadapter.New(r), ...})
//
// chi and behemoth share the {param} path syntax, so paths are used as-is.
package chi

import (
	"fmt"
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/go-chi/chi/v5"
)

type ChiDriver struct {
	router chi.Router
}

// New returns a driver mounting onto router: a *chi.Mux, or any chi.Router
// such as one returned by Group or Route.
func New(router chi.Router) *ChiDriver {
	return &ChiDriver{router: router}
}

// Mount implements [types.FrameworkDriver].
//
// Unlike gin and echo, chi silently replaces a route registered twice, so
// conflicts with the application's existing routes are checked here, by
// exact method and pattern. Panics chi raises for an invalid route are
// returned as errors.
func (cd *ChiDriver) Mount(routes ...types.Route) error {
	existing, err := cd.existingRoutes()
	if err != nil {
		return err
	}
	for _, rt := range routes {
		if existing[routeKey{rt.Method, rt.Path}] {
			return fmt.Errorf("chi: cannot mount %s %s: route already registered", rt.Method, rt.Path)
		}
		if err := cd.handle(rt); err != nil {
			return err
		}
		existing[routeKey{rt.Method, rt.Path}] = true
	}
	return nil
}

type routeKey struct{ method, path string }

func (cd *ChiDriver) existingRoutes() (map[routeKey]bool, error) {
	existing := map[routeKey]bool{}
	err := chi.Walk(cd.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		existing[routeKey{method, route}] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chi: cannot list existing routes: %w", err)
	}
	return existing, nil
}

func (cd *ChiDriver) handle(rt types.Route) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("chi: cannot mount %s %s: %v", rt.Method, rt.Path, r)
		}
	}()

	handler := rt.Handler
	cd.router.Method(rt.Method, rt.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rctx := buildRequestContext(r)
		if err := handler(rctx); err != nil {
			// Routes arrive with errors already mapped to responses; an
			// error here means the response itself could not be built.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rctx.Response.Flush(w)
	}))
	return nil
}

func buildRequestContext(r *http.Request) *types.RequestContext {
	params := map[string]string{}
	if rc := chi.RouteContext(r.Context()); rc != nil {
		for i, key := range rc.URLParams.Keys {
			params[key] = rc.URLParams.Values[i]
		}
	}

	return &types.RequestContext{
		Ctx:      r.Context(),
		Request:  r,
		Response: types.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}
}

var _ types.FrameworkDriver = (*ChiDriver)(nil)
