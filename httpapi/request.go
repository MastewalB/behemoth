package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
)

// RequestContext is the normalized, framework-agnostic context every plugin
// handler receives. It wraps the standard *http.Request (which every Go
// framework exposes) and a ResponseRecorder that buffers the response until
// the framework adapter flushes it to the real connection.
type RequestContext struct {
	Ctx context.Context

	// The original http Request
	Request *http.Request

	// Custom ResponseRecorder for multiple plugins to write responses on
	Response *ResponseRecorder

	Auth *core.AuthContext

	// TokenCarrier carries the session token over HTTP, the way
	// RouterConfig.Carrier says: a sign-in route hands the token to the
	// client through it (WriteSignIn), and a route that ends its caller's
	// session takes the token back (Clear). A route that hands the client a
	// value of its own reads TokenCarrier.Config to deliver it the same way.
	// The router sets it, as it sets Auth.
	TokenCarrier *TokenCarrier

	// Per request map to store data (user ID, claims etc...)
	Values behemoth.M

	Params map[string]string // path params, populated by the driver before Handler runs
}

// Set stores val under key in Values.
func (rc *RequestContext) Set(key string, val any) {
	rc.Values[key] = val
}

// Get returns the value Values holds under key.
func (rc *RequestContext) Get(key string) (any, bool) {
	v, ok := rc.Values[key]
	return v, ok
}

// Param returns the path parameter name, such as "id" in "/users/{id}", or
// "" when the route has none of that name.
func (rc *RequestContext) Param(name string) string { return rc.Params[name] }

// ResponseRecorder buffers status code, headers, and body so the plugin
// handler can write a complete response without ever touching a framework type.
// The framework adapter calls Flush() once the handler returns, copying
// everything onto the real http.ResponseWriter and sending it over the wire.
type ResponseRecorder struct {
	Code    int
	Headers http.Header
	body    *bytes.Buffer
}

// NewResponseRecorder returns an empty response with the status 200.
func NewResponseRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		Code:    http.StatusOK,
		Headers: make(http.Header),
		body:    new(bytes.Buffer),
	}
}

// SetHeader sets an arbitrary response header.
// Call before JSON/Text/Redirect so the value is included on Flush.
func (r *ResponseRecorder) SetHeader(key, value string) {
	r.Headers.Set(key, value)
}

// JSON serialises v, sets Content-Type, and writes into the buffer.
// Nothing is sent over the network until Flush() is called.
func (r *ResponseRecorder) JSON(code int, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Code = code
	r.Headers.Set("Content-Type", "application/json")
	r.body.Write(data)
	return nil
}

// Status sets only the status code (useful for 204 No Content, etc.).
func (r *ResponseRecorder) Status(code int) {
	r.Code = code
}

// Text writes a plain-text body.
func (r *ResponseRecorder) Text(code int, body string) {
	r.Code = code
	r.Headers.Set("Content-Type", "text/plain; charset=utf-8")
	r.body.WriteString(body)
}

// Cookie queues an http.Cookie to be sent with the response.
// The cookie is serialised by the stdlib and added as a Set-Cookie header,
// so the full cookie spec (MaxAge, HttpOnly, SameSite, ...) is supported.
func (r *ResponseRecorder) Cookie(cookie *http.Cookie) {
	// http.Header.Add keeps existing Set-Cookie lines - multiple cookies work.
	r.Headers.Add("Set-Cookie", cookie.String())
}

// Redirect sets a 3xx status and a Location header.
// The body is intentionally empty; browsers follow the Location immediately.
func (r *ResponseRecorder) Redirect(code int, url string) {
	if code < 300 || code > 399 {
		// Guard against a common mistake; fall back to 302.
		code = http.StatusFound
	}
	r.Code = code
	r.Headers.Set("Location", url)
}

// Error writes {"error": err} with code. A handler that fails returns its
// error instead, for the router's error mapping to answer.
func (r *ResponseRecorder) Error(code int, err string) error {
	return r.JSON(code, map[string]string{"error": err})
}

// Flush copies the buffered response onto the real http.ResponseWriter.
// Called once by the framework adapter after the plugin handler returns.
func (r *ResponseRecorder) Flush(w http.ResponseWriter) {

	// type Header map[string][]string
	for k, vals := range r.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(r.Code)
	r.body.WriteTo(w)
}

// HandlerFunc handles one request: it writes the response into
// ctx.Response, or returns an error, which the router maps to a response.
type HandlerFunc func(ctx *RequestContext) error

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
//
//	type Middleware struct {
//		Name   string
//		Handle func(rc *RequestContext, next HandlerFunc) error
//	}
type Middleware func(next HandlerFunc) HandlerFunc

// Route describes a single HTTP endpoint a plugin wants to expose.
// The Handler receives a framework-agnostic RequestContext and writes its
// response into rc.Response
type Route struct {
	Method      string       // "GET", "POST", "PUT", "DELETE" ...
	Path        string       // "/plugin-name/some-action"
	Handler     HandlerFunc  // the core logic for this route
	Middlewares []Middleware // optional, run left-to-right before Handler
}

type requestContextKey struct{}

// ContextWithRequest returns ctx carrying rc, the request being handled. The
// router sets it once per request (Router.Build), so code reached while
// handling it — including layers that never see rc, like the store's data
// hooks — can still attribute work to the request (IP, user agent, headers).
// Outside a request (a CLI, a job) there is none, and RequestFrom says so.
//
// Only the request travels this way: it is request-scoped by definition.
// Anything else a callee needs is passed explicitly.
func ContextWithRequest(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, rc)
}

// RequestFrom returns the request ctx carries, or nil outside one.
func RequestFrom(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(requestContextKey{}).(*RequestContext)
	return rc
}
