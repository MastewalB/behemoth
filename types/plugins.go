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

type HookPoint string
type HookPhase string

// HookContext is the normalized context passed to every lifecycle hook handler
// (both Tier 1 data hooks and Tier 2 semantic flow hooks). Unlike RequestContext,
// it makes no assumption about transport — a hook may fire from an HTTP request,
// a CLI command, a background job, or a plugin calling another plugin's service
// method directly.
type HookContext struct {
	Ctx context.Context

	Point HookPoint
	Phase HookPhase

	Auth *AuthContext

	// Values is scratch space scoped to this single dispatch chain — lets one
	// handler leave a note for a later handler in the same chain (e.g. "password
	// strength already checked by plugin X"). Distinct from the payload itself,
	// same idiom as RequestContext.Values but chain-scoped rather than request-scoped.
	Values M

	// Request is set only when this lifecycle was triggered from within an HTTP
	// request — i.e. some plugin endpoint handler called into a service that fired
	// this hook. Nil for CLI-triggered, job-triggered, or internal plugin-to-plugin calls.
	// Handlers that don't care about transport (the common case) should never need to touch this.
	Request *RequestContext
}

// BeforeHookFunc: pre-persistence, validate-and-prepare only.
// Contract: return (mutatedPayload, nil) to continue the chain with that payload,
// or (nil, err) to ABORT. There is no separate "abort" flag — a non-nil error IS
// the abort signal. err must be one of the existing behemotherr domain error types
// (ValidationError, DomainError, etc.) so it maps cleanly to an HTTP status later.
// Handlers MUST return the full payload to proceed with, even if unchanged —
// never rely on nil meaning "no change," since that's ambiguous with an empty M.
type BeforeHookFunc func(hctx *HookContext, payload M) (M, error)

// AfterHookFunc: strictly post-commit, read-only with respect to the operation's
// outcome. result is the already-persisted entity. A returned error does NOT roll
// anything back (nothing left to roll back) — the dispatcher captures it and hands
// it to a configurable failure reporter/retry policy instead of propagating it as
// the parent operation's error.
type AfterHookFunc func(hctx *HookContext, result Model) error

// FailedHookFunc: notification-only, fired for business-rejected operations
// (bad password, TOTP mismatch, banned domain) — NOT for system errors like a
// DB timeout, which just propagate as ordinary errors and never reach here.
type FailedHookFunc func(hctx *HookContext, reason FailureReason) error

type FailureReason struct {
	Code  string // "invalidCredentials", "userNotFound", "secondFactorRejected", ...
	Cause error  // underlying error, if any — nil for pure business rejections
}
