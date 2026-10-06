package types

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"sort"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types/schema"
)

type Plugin interface {

	// Meta returns the Plugin metadata
	Meta() PluginMeta

	// Version is the plugin version. e.g. "1.0.0"
	Version() string

	// Init is called once when behemoth starts up, with the AuthContext
	// that holds behemoth's services. A plugin that logs takes its logger
	// from it: telemetry.Named(ctx.Telemetry.Logger, <plugin name>).
	Init(ctx *AuthContext) error

	// Routes returns the HTTP endpoints this plugin wants to register.
	// Returning an empty slice is valid (the plugin may only use hooks).
	Routes() []Route

	// Middlewares() returns middleware functions that the plugin wants to register.
	Middlewares() []Middleware

	// Declare lets the plugins declare hooks, tokens, and ratelimit rules it wants to get registered.
	Declare(ic *PluginInitContext) error

	Register(reg HookRegistry) error
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
	Values behemoth.M

	Params map[string]string // path params, populated by the driver before Handler runs
}

func (rc *RequestContext) Set(key string, val any) {
	rc.Values[key] = val
}

func (rc *RequestContext) Get(key string) (any, bool) {
	v, ok := rc.Values[key]
	return v, ok
}

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

type HookPoint string
type HookPhase string

const (
	BeforeHookPhase HookPhase = "before"
	AfterHookPhase  HookPhase = "after"
	FailedHookPhase HookPhase = "failed"
)

type HookRegistry interface {
	OnBefore(point HookPoint, fn BeforeHookFunc, opts *HookOptions) error
	OnAfter(point HookPoint, fn AfterHookFunc, opts *HookOptions) error
	OnFailed(point HookPoint, fn FailedHookFunc, opts *HookOptions) error
}

// HookContext is the normalized context passed to every lifecycle hook handler
// (both Tier 1 data hooks and Tier 2 semantic flow hooks). Unlike RequestContext,
// it makes no assumption about transport; a hook may fire from an HTTP request,
// a CLI command, a background job, or a plugin calling another plugin's service
// method directly.
type HookContext struct {
	Ctx context.Context

	Point HookPoint
	Phase HookPhase

	Auth *AuthContext

	// Tx is set on Tier 1 data hooks only: the store bound to the transaction
	// of the write that fired the hook. A handler's writes through Tx commit
	// or roll back with that write, and its reads see the row being written.
	// Tx.DB() is the database adapter bound to the same transaction, for
	// tables the store has no operations for (a plugin's own); use it with
	// Ctx. Auth.Store and Auth.DB are a different connection: their writes
	// survive a rollback and their reads don't see the uncommitted row. Nil
	// on Tier 2 hooks, which don't run inside a store transaction.
	Tx *store.Store

	// Values is scratch space for handlers, scoped to one operation: the
	// before, after and failed points a firing site fires for one call (a
	// sign-in, a session create, a write to users) share one map. A handler
	// on the before point can leave a note for a later handler on the same
	// point or on the operation's after or failed point, e.g. an invite id
	// it resolved from the input.
	//
	// An operation started inside another one (the user write inside a
	// sign-up) begins with a copy of the outer operation's Values: its
	// handlers read the outer notes, and what they write stays their own.
	// See ContextWithHookValues. It is distinct from the payload, which the
	// firing site reads back, and from RequestContext.Values, which lasts
	// for the HTTP request and exists only when there is one.
	Values behemoth.M

	// Request is set only when this lifecycle was triggered from within an HTTP
	// request; i.e. some plugin endpoint handler called into a service that fired
	// this hook. Nil for CLI-triggered, job-triggered, or internal plugin-to-plugin calls.
	// Handlers that don't care about transport (the common case) should never need to touch this.
	Request *RequestContext
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

type hookValuesKey struct{}

// ContextWithHookValues returns ctx carrying values, the HookContext.Values
// of the operation being run. Hook dispatches made under ctx for the same
// operation use the map itself; an operation started under ctx begins with a
// copy of it (NestedHookValues). This is how the data hooks of a user write
// see what a sign-up's handlers left, without the store knowing about hooks.
//
// Like the request (ContextWithRequest), the values travel in the context
// because the code in between, the store and the managers, takes only a
// context. A callee that is handed a fresh context starts without them.
func ContextWithHookValues(ctx context.Context, values behemoth.M) context.Context {
	return context.WithValue(ctx, hookValuesKey{}, values)
}

// HookValuesFrom returns the Values of the operation ctx belongs to, or nil
// when ctx belongs to none.
func HookValuesFrom(ctx context.Context) behemoth.M {
	values, _ := ctx.Value(hookValuesKey{}).(behemoth.M)
	return values
}

// NestedHookValues returns the Values a new operation started under ctx
// begins with: a copy of the enclosing operation's, or an empty map when
// there is none. The copy is shallow.
func NestedHookValues(ctx context.Context) behemoth.M {
	values := behemoth.M{}
	maps.Copy(values, HookValuesFrom(ctx))
	return values
}

// BeginOperation returns ctx for a new operation nested under the one ctx
// belongs to, if any. A firing site calls it once per call and builds the
// HookContext of each of its dispatches with HookValuesFrom, so that its
// points share one Values map.
func BeginOperation(ctx context.Context) context.Context {
	return ContextWithHookValues(ctx, NestedHookValues(ctx))
}

// AsOperation returns a copy of hctx set up as one operation: Values is
// never nil, and Ctx carries it, so the store writes and manager calls the
// operation makes with Ctx nest under it. A flow that receives a HookContext
// from its caller (WithLifecycle, emailpassword.SignOut) calls it first and
// uses the result for every dispatch. Values that are nil start as a copy of
// the enclosing operation's.
func AsOperation(hctx *HookContext) *HookContext {
	op := *hctx
	if op.Values == nil {
		op.Values = NestedHookValues(op.Ctx)
	}
	op.Ctx = ContextWithHookValues(op.Ctx, op.Values)
	return &op
}

type HookCatalog interface {
	Declare(def HookPointDef) error // errors if Point already declared by a different owner
	Lookup(point HookPoint) (HookPointDef, bool)
	All() []HookPointDef
}

type PluginInitContext struct {
	Hooks      HookCatalog
	Tokens     TokenCatalog
	RateLimits RateLimitCatalog
	Schemas    schema.Registry
}

// BeforeHookFunc: pre-persistence, validate-and-prepare only.
// Contract: return (mutatedPayload, nil) to continue the chain with that payload,
// or (nil, err) to ABORT. There is no separate "abort" flag; a non-nil error IS
// the abort signal. err must be one of the existing behemotherr domain error types
// (ValidationError, DomainError, etc.) so it maps cleanly to an HTTP status later.
// Handlers MUST return the full payload to proceed with, even if unchanged —
// never rely on nil meaning "no change," since that's ambiguous with an empty M.
type BeforeHookFunc func(hctx *HookContext, payload behemoth.M) (behemoth.M, error)

// AfterHookFunc runs after the operation its point belongs to. result is the
// entity the operation produced. What a returned error does depends on the tier:
//
// Tier 2 (flow points such as auth.signUp.after, dispatched with RunAfter): the
// operation has already succeeded and committed. The error is logged and does
// not become the operation's error. This is the place for side effects that
// can't be undone: emails, webhooks, calls to other systems.
//
// Tier 1 (data points such as data.user.afterCreate, dispatched with
// RunAfterTx): the handler runs inside the write's transaction, before commit.
// The error fails the write and rolls it back, and no later handler runs.
// result may still be rolled back after the handler returns, so the handler
// should only do work the rollback undoes: database writes through
// HookContext.Tx. Writes through Auth.Store, key-value storage writes and
// outside side effects are not undone.
type AfterHookFunc func(hctx *HookContext, result any) error

// FailedHookFunc: notification-only, fired for business-rejected operations
// (bad password, TOTP mismatch, banned domain)
// system errors like a DB timeout, should just propagate as ordinary errors.
type FailedHookFunc func(hctx *HookContext, reason FailureReason) error

type FailureReason struct {
	Code  string // "invalidCredentials", "userNotFound", "secondFactorRejected", ...
	Cause error  // underlying error, if any. nil for pure business rejections

	// SubjectType and SubjectID name what the rejected operation targeted,
	// for the audit event of an audited failed point: the account a failed
	// sign-in was for. Optional. Without them the event's subject is the
	// operation's user (HookContext.Values[HookValueUserID]), if any.
	SubjectType string
	SubjectID   string

	// Metadata is added to that audit event's metadata: what was attempted
	// when there is no subject to name, such as the email address of a
	// sign-in for an account that doesn't exist. Optional.
	Metadata behemoth.M
}

// Dispatcher runs the handler chains of hook points.
//
// Handlers receive a copy of hctx with Point and Phase set to the point being
// dispatched, so a firing site may leave both empty. The copy shares hctx's
// Values map.
//
// Every method returns a configuration error, and runs no handler, when point
// was never declared or is declared with a different phase than the method
// dispatches. That is a mistake in the code firing the point, so callers
// return it like any other error instead of treating it as a handler's.
type Dispatcher interface {
	// RunBefore executes the frozen before-hook chain for a given hook point.
	// It passes the payload through the hooks in registration order, returning
	// the mutated payload or aborting on the first non-nil error.
	RunBefore(hctx *HookContext, point HookPoint, payload behemoth.M) (behemoth.M, error)

	// RunAfter executes the frozen after-chain for a Tier 2 point, once the
	// flow has succeeded. It never surfaces a handler's error to the caller:
	// a failed handler is logged and the rest of the chain still runs. The
	// flow has already succeeded; a handler cannot change that. The returned
	// error is non-nil only when point can't be dispatched (see below).
	RunAfter(hctx *HookContext, point HookPoint, result any) error

	// RunAfterTx executes the frozen after-chain for a Tier 1 data point,
	// inside the write's transaction. Unlike RunAfter it stops at the first
	// handler error (or panic) and returns it, so the store can roll the
	// write back. A point declared with an AuditSpec has its audit event
	// written in the same transaction, once the chain has passed; a failure
	// to write it is returned like a handler's error.
	RunAfterTx(hctx *HookContext, point HookPoint, result any) error

	// Fail dispatches the frozen failed-chain for point with reason.
	// No-op if point == ""; this is what lets Tier 1 CRUD skip cascading entirely.
	// Handler errors are logged. The returned error is non-nil only when
	// point can't be dispatched (see below).
	Fail(hctx *HookContext, point HookPoint, reason FailureReason) error
}

// AuditSpec marks a hook point as audited: every dispatch of the point
// records one audit event. See HookPointDef.Audit for when and how reliably.
type AuditSpec struct {
	Type string // audit event Type; defaults to the HookPoint string if empty
}

// AuditSubject is implemented by a hook result that is not a behemoth.Model
// and still names what the operation was about, so the audit event of its
// point has a subject. A Model needs no method: its table and primary key
// are used.
type AuditSubject interface {
	// AuditSubject returns the subject's type, a table's canonical name for
	// a row ("users"), and its id.
	AuditSubject() (subjectType, subjectID string)
}

// HookPointDef declares one hook point, e.g. "data.user.beforeCreate", owned
// by "core", phase before.
type HookPointDef struct {
	Point HookPoint
	Owner string // who declared it: "core" or a plugin's name. Set by the catalog the declarer receives.
	// Phase is the point's one phase. It decides the handler type and the
	// Dispatcher method the point is fired with. An operation with a before
	// and an after side declares two points.
	Phase HookPhase
	// Audit, when set, records one audit event per dispatch, after the
	// chain. RunAfter and Fail record best effort: a failed write is logged.
	// RunAfterTx records inside the write's transaction, so the event
	// commits or rolls back with the row, and a failed write fails the row's
	// write too. A before point is never audited.
	Audit *AuditSpec
}

type HookOptions struct {
	Priority HookPriority // default: PriorityNormal
	Before   []string     // plugin names this handler must run before, on this point
	After    []string     // plugin names this handler must run after, on this point
}

type HookPriority int

const (
	PriorityHighest HookPriority = -100 // gatekeepers: validation, security checks that should see raw input first
	PriorityHigh    HookPriority = -50
	PriorityNormal  HookPriority = 0
	PriorityLow     HookPriority = 50
	PriorityLowest  HookPriority = 100 // observers: logging, analytics; should see the final mutated state
)

// WithLifecycle wraps fn, the body of a flow, with the flow's three points:
// before runs on the input and may rewrite it or stop the flow, success runs
// on fn's result, and failed fires when a before handler stopped the flow.
// fn fires failed itself for its own business rejections.
//
// The wrapped call is one operation (AsOperation): all three points and fn
// share the HookContext's Values, and what fn does with hctx.Ctx nests under
// it.
func WithLifecycle[TIn, TOut any](
	dispatcher Dispatcher,
	before, success, failed HookPoint,
	fn func(hctx *HookContext, in TIn) (TOut, error),
) func(hctx *HookContext, in TIn) (TOut, error) {
	return func(hctx *HookContext, in TIn) (TOut, error) {
		var zero TOut
		hctx = AsOperation(hctx)

		payload, err := structToM(&in)
		if err != nil {
			return zero, err
		}

		mutated, err := dispatcher.RunBefore(hctx, before, payload)
		if err != nil {
			if failErr := dispatcher.Fail(hctx, failed, FailureReason{Code: "rejectedByHook", Cause: err}); failErr != nil {
				return zero, failErr
			}
			return zero, err
		}

		if err := mFromStruct(mutated, &in); err != nil {
			return zero, err
		}

		out, err := fn(hctx, in)
		if err != nil {
			return zero, err // flow's own business-rejection Fail() calls already happened inside fn
		}
		if err := dispatcher.RunAfter(hctx, success, out); err != nil {
			return zero, err
		}
		return out, nil
	}
}

// structToM converts any struct to M. If T implements Serializable, that's used
// directly (predictable, no reflection, lets a type customize - e.g. excluding a
// field, or handling a type json can't round-trip cleanly). Otherwise falls back
// to a generic json marshal/unmarshal roundtrip, which works for any exported,
// json-taggable struct with zero boilerplate.
func structToM[T any](v *T) (behemoth.M, error) {
	if s, ok := any(v).(behemoth.Serializable); ok {
		mp, err := s.ToMap()
		return mp, err
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m behemoth.M
	return m, json.Unmarshal(b, &m)
}

func mFromStruct[T any](m behemoth.M, v *T) error {
	if s, ok := any(v).(behemoth.Serializable); ok {
		return s.FromMap(m)
	}

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// KahnSort performs topological sorting on a given Directed Acyclic Graph.
// The graph map should have nodes as keys and their dependants as lists.
// For eg. If A and C depend on B,
// B: {A, C}
// Ties among nodes with in-degree zero at the same step are broken by name, ascending
func KahnSort(graph map[string][]string, less func(a, b string) bool) (order []string, cyclePath []string, ok bool) {

	// Collect every node
	allNodes := make(map[string]bool)
	for node, dependants := range graph {
		allNodes[node] = true
		for _, d := range dependants {
			allNodes[d] = true
		}
	}

	// Use len(allNodes) instead of N since some nodes might only be listed as dependants
	N := len(allNodes)
	indegree := make(map[string]int, N)
	for n := range allNodes {
		indegree[n] = 0
	}
	for _, dependants := range graph {
		for _, dep := range dependants {
			indegree[dep]++
		}
	}

	queue := make([]string, 0)
	for node := range graph {
		if indegree[node] == 0 {
			queue = append(queue, node)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return less(queue[i], queue[j]) })

	order = make([]string, 0, N)

	front := 0
	for len(queue) > 0 {
		// Pop the alphabetically-first ready node
		curr := queue[front]
		queue = queue[1:]
		order = append(order, curr)

		// new eligible nodes
		var newEntries []string
		for _, dep := range graph[curr] {
			indegree[dep]--
			if indegree[dep] == 0 {
				newEntries = append(newEntries, dep)
			}
		}

		sort.Strings(newEntries)
		sort.Slice(newEntries, func(i, j int) bool { return less(newEntries[i], newEntries[j]) })
		queue = mergeSorted(queue, newEntries, less) // keep 'queue' sorted as new nodes join
	}

	if len(order) != N {
		// return remaining indegree nodes as cycles
		return nil, findCyclePath(graph, indegree), false
	}

	return order, nil, true
}

func mergeSorted(a, b []string, less func(a, b string) bool) []string {
	if len(b) == 0 {
		return a
	}
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if !less(b[j], a[i]) { // a[i] <= b[j]
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	return append(append(out, a[i:]...), b[j:]...)
}

// findCyclePath walks from any node that still has unresolved in-degree
// (proof it's part of, or downstream of, a cycle) following one dependency
// edge at a time until a node repeats, which marks the actual cycle,
// trimmed out of the full walk for a concise, readable report.
func findCyclePath(graph map[string][]string, remainingInDegree map[string]int) []string {
	// Build the reverse (dependency-direction) map once, for walking;
	// since the graph i sin dependant-direction
	dependsOn := make(map[string][]string)
	for node, dependants := range graph {
		for _, d := range dependants {
			dependsOn[d] = append(dependsOn[d], node)
		}
	}

	var start string
	for n, deg := range remainingInDegree {
		if deg > 0 {
			start = n
			break
		}
	}

	if start == "" {
		return nil // defensive: shouldn't happen if the caller already confirmed a cycle exists
	}

	visited := map[string]bool{}
	path := []string{start}
	current := start
	for {
		next := dependsOn[current]
		if len(next) == 0 {
			return path // dead end without a repeat. shouldn't occur in a genuine cycle
		}
		sort.Strings(next) // deterministic even when a node has multiple unresolved dependencies
		current = next[0]
		if visited[current] {
			path = append(path, current)
			// Trim everything before the repeat's first occurrence,
			// so the reported path is exactly the cycle.
			for i, n := range path {
				if n == current {
					return path[i:]
				}
			}
		}
		visited[current] = true
		path = append(path, current)
	}
}

type PluginDependency struct {
	Name     string
	Optional bool // if true, missing dependency is fine and edge is just skipped
}

type PluginMeta struct {
	// Name returns a unique, human-readable identifier, e.g. "two-factor".
	Name         string
	Dependencies []PluginDependency
	MountPath    string // optional; "" mounts flat under basePath
}
