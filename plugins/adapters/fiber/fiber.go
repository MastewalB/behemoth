// Package fiber mounts behemoth's routes onto an application's *fiber.App:
//
//	fiberApp := fiber.New()
//	ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{HTTP: fiberadapter.New(fiberApp), ...})
//
// Fiber is built on fasthttp, not net/http, so it has no *http.Request to
// hand to behemoth's handlers. The driver builds one for each request (see
// newRequest) and writes the response onto fiber's own.
package fiber

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
	"github.com/gofiber/fiber/v3"
)

// FiberDriver mounts behemoth's routes onto a *fiber.App.
type FiberDriver struct {
	app *fiber.App
}

// New returns a driver mounting onto app. It takes the app and not a
// fiber.Router, because only the app can list the routes it already has
// (see Mount). To put behemoth's routes behind the application's own
// middleware, register the middleware on their path before Boot:
// app.Use("/api/auth", mw).
func New(app *fiber.App) *FiberDriver {
	return &FiberDriver{app: app}
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// toFiberPath converts behemoth's {param} path parameters to fiber's :param.
func toFiberPath(path string) string {
	return pathParam.ReplaceAllString(path, ":$1")
}

// Mount implements [types.FrameworkDriver].
//
// Fiber accepts a route it already has and runs the one registered first,
// so a behemoth route that repeats one of the application's would never be
// reached. Conflicts with the application's existing routes are therefore
// checked here, by method and path. Panics fiber raises for an invalid route
// are returned as errors.
func (fd *FiberDriver) Mount(routes ...types.Route) error {
	cfg := fd.app.Config()
	existing := map[routeKey]bool{}
	for _, rt := range fd.app.GetRoutes(true) { // true leaves out middleware registered with Use
		existing[newRouteKey(cfg, rt.Method, rt.Path)] = true
	}

	for _, rt := range routes {
		key := newRouteKey(cfg, rt.Method, toFiberPath(rt.Path))
		if existing[key] {
			return fmt.Errorf("fiber: cannot mount %s %s: route already registered", rt.Method, rt.Path)
		}
		// Without Config.UnescapePath fiber leaves path parameters as they
		// were sent.
		if err := fd.handle(rt, !cfg.UnescapePath); err != nil {
			return err
		}
		existing[key] = true
	}
	return nil
}

type routeKey struct{ method, path string }

// newRouteKey returns the key two routes share when app would match the
// same requests to them: fiber ignores case unless Config.CaseSensitive is
// set, and a trailing slash unless Config.StrictRouting is set.
func newRouteKey(cfg fiber.Config, method, path string) routeKey {
	if !cfg.CaseSensitive {
		path = strings.ToLower(path)
	}
	if !cfg.StrictRouting && len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return routeKey{strings.ToUpper(method), path}
}

func (fd *FiberDriver) handle(rt types.Route, unescapeParams bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("fiber: cannot mount %s %s: %v", rt.Method, rt.Path, r)
		}
	}()

	handler := rt.Handler
	fd.app.Add([]string{rt.Method}, toFiberPath(rt.Path), func(c fiber.Ctx) error {
		rctx, err := buildRequestContext(c, unescapeParams)
		if err != nil {
			// Fiber routes a request URI that net/url refuses to parse,
			// such as one with a broken percent escape.
			c.Status(http.StatusBadRequest)
			return nil
		}
		if err := handler(rctx); err != nil {
			// Routes arrive with errors already mapped to responses; an
			// error here means the response itself could not be built.
			c.Status(http.StatusInternalServerError)
			return nil
		}
		rctx.Response.Flush(&responseWriter{c: c, header: make(http.Header)})
		return nil
	})
	return nil
}

func buildRequestContext(c fiber.Ctx, unescapeParams bool) (*types.RequestContext, error) {
	req, err := newRequest(c)
	if err != nil {
		return nil, err
	}

	names := c.Route().Params
	params := make(map[string]string, len(names))
	for _, name := range names {
		value := strings.Clone(c.Params(name)) // fiber's string is only valid inside the handler
		if unescapeParams {
			// The net/http routers hand out decoded parameters.
			if decoded, err := url.PathUnescape(value); err == nil {
				value = decoded
			}
		}
		params[name] = value
	}

	return &types.RequestContext{
		Ctx:      req.Context(),
		Request:  req,
		Response: types.NewResponseRecorder(),
		Values:   make(behemoth.M),
		Params:   params,
	}, nil
}

// newRequest builds the *http.Request behemoth's handlers read, from fiber's
// request.
//
// Fiber reuses a request's memory for the next request once the handler has
// returned, and the strings it hands out point into that memory. Behemoth
// holds on to what it reads for longer: mail sent in the background keeps
// the request's context, which carries the RequestContext and the request ID
// read from a header, and a trace span with that ID is exported later. Every
// string is therefore copied here. This is why the driver does not use
// fiber's adaptor package, whose request shares fiber's memory. The body is
// not copied: it is read while the handler runs, as with net/http.
//
// The request's context is c.Context(), the context the application's
// middleware set with SetContext, or an empty one. Fiber has no context that
// ends when the client goes away.
func newRequest(c fiber.Ctx) (*http.Request, error) {
	fctx := c.RequestCtx()

	uri := string(fctx.RequestURI())
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, err
	}

	proto := string(fctx.Request.Header.Protocol())
	major, minor, _ := http.ParseHTTPVersion(proto)
	body := fctx.Request.Body()

	req := &http.Request{
		Method:        string(fctx.Method()),
		URL:           u,
		Proto:         proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          string(fctx.Host()),
		RemoteAddr:    fctx.RemoteAddr().String(),
		RequestURI:    uri,
		TLS:           fctx.TLSConnectionState(),
	}
	for k, v := range fctx.Request.Header.All() {
		switch key := http.CanonicalHeaderKey(string(k)); key {
		case fiber.HeaderHost:
			// net/http keeps the host in Request.Host only.
		case fiber.HeaderTransferEncoding:
			req.TransferEncoding = append(req.TransferEncoding, string(v))
		default:
			req.Header[key] = append(req.Header[key], string(v))
		}
	}
	return req.WithContext(c.Context()), nil
}

// responseWriter lets ResponseRecorder.Flush, which writes to an
// http.ResponseWriter, write to fiber's response.
type responseWriter struct {
	c           fiber.Ctx
	header      http.Header
	wroteHeader bool
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	resp := w.c.Response()
	for k, vals := range w.header {
		for _, v := range vals {
			resp.Header.Add(k, v)
		}
	}
	resp.SetStatusCode(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.c.Write(b)
}

var _ types.FrameworkDriver = (*FiberDriver)(nil)
