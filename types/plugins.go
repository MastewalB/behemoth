package types

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// PluginContext is injected into every plugin's Init method.
// It gives plugins access to behemoth's core services without leaking
// internal implementation details.
//
// All fields are interfaces - plugins are decoupled from concrete adapters.
type PluginContext struct {

	// Logger is always non-nil. If no logger was provided to the core,
	// a silent no-op implementation is used so plugins never need nil checks.
	Logger Logger

	// A unique identifier of the plugin
	PluginName string
}

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

	Auth *AuthContext

	// Per request map to store data (user ID, claims etc...)
	Values M
}

func (rc *RequestContext) Set(key string, val any) {
	rc.Values[key] = val
}

func (rc *RequestContext) Get(key string) (any, bool) {
	v, ok := rc.Values[key]
	return v, ok
}

// ResponseRecorder buffers status code, headers, and body so the plugin
// handler can write a complete response without ever touching a framework type.
// The framework adapter calls Flush() once the handler returns, copying
// everything onto the real http.ResponseWriter and sending it over the wire.
type ResponseRecorder struct {
	Code    int
	Headers http.Header
	body    *bytes.Buffer
}

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
