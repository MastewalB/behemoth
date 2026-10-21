// Package core holds Behemoth's plugin contracts: the Plugin interface, the
// AuthContext a plugin receives, the hook system's types and the helpers flows
// call over them, the interfaces of the managers, and the configuration
// they take. The implementations live in other packages, and engine wires
// them together. core knows no transport: the HTTP types are in httpapi.
package core

import (
	"context"
	"encoding/json"
	"maps"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/schema"
	"github.com/MastewalB/behemoth/store"
)

// Plugin is what every plugin implements: it declares what it adds at
// Prepare (Declare), registers its hook handlers, and receives behemoth's
// services at Boot (Init). It knows no transport. A plugin that serves HTTP
// routes also implements httpapi.Plugin, and one with route rate-limit
// rules httpapi.RouteRulesPlugin.
type Plugin interface {

	// Meta returns the Plugin metadata
	Meta() PluginMeta

	// Version is the plugin version. e.g. "1.0.0"
	Version() string

	// Init is called once when behemoth starts up, with the AuthContext
	// that holds behemoth's services. A plugin that logs takes its logger
	// from it: telemetry.Named(ctx.Telemetry.Logger, <plugin name>).
	Init(ctx *AuthContext) error

	// Declare lets the plugins declare hooks, tokens, and ratelimit rules it wants to get registered.
	Declare(ic *PluginInitContext) error

	Register(reg HookRegistry) error
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
// (both Tier 1 data hooks and Tier 2 semantic flow hooks). Unlike httpapi.RequestContext,
// it makes no assumption about transport; a hook may fire from an HTTP request,
// a CLI command, a background job, or a plugin calling another plugin's service
// method directly. What a handler may know about where the call came from is
// on the caller (Caller): its transport, address and user agent. A handler
// that needs the HTTP request itself reads it with httpapi.RequestFrom(Ctx), which
// returns nil outside a request.
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
	// Some firing sites also publish what they were called with before
	// their first dispatch (the normalized email of a sign-in, the user of
	// a session create), under the HookValue keys of core/hooks. That is
	// what a rate-limit rule's KeyFunc keys on, since it does not get the
	// payload.
	//
	// An operation started inside another one (the user write inside a
	// sign-up) begins with a copy of the outer operation's Values: its
	// handlers read the outer notes, and what they write stays their own.
	// See ContextWithHookValues. It is distinct from the payload, which the
	// firing site reads back, and from httpapi.RequestContext.Values, which lasts
	// for the HTTP request and exists only when there is one.
	Values behemoth.M
}

// Caller returns the caller of the operation, identity.CallerFrom(h.Ctx): who
// it runs for, and where the call came from. It reads the context and keeps
// no copy, so a handler always sees the caller the dispatch runs with.
func (h *HookContext) Caller() identity.Caller { return identity.CallerFrom(h.Ctx) }

type hookValuesKey struct{}

// ContextWithHookValues returns ctx carrying values, the HookContext.Values
// of the operation being run. Hook dispatches made under ctx for the same
// operation use the map itself; an operation started under ctx begins with a
// copy of it (NestedHookValues). This is how the data hooks of a user write
// see what a sign-up's handlers left, without the store knowing about hooks.
//
// Like the request (httpapi.ContextWithRequest), the values travel in the context
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
	// Permissions is where a plugin declares the permissions its flows
	// require (Access).
	Permissions PermissionCatalog
}

// BeforeHookFunc: pre-persistence, validate-and-prepare only.
// Contract: return (mutatedPayload, nil) to continue the chain with that payload,
// or (nil, err) to ABORT. There is no separate "abort" flag; a non-nil error IS
// the abort signal. err must be one of the existing errs domain error types
// (ValidationError, DomainError, etc.) so it maps cleanly to an HTTP status later.
// A nil payload with a nil error means "no change": the chain continues with
// the payload the handler received, including what it changed in place. To
// continue with an empty payload, return an empty M.
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

// FailureRejectedByHook is the FailureReason code of an operation that a
// before handler, a data hook handler or a rate limit refused. The firing
// site can't know which handler refused or why, so it says only that one
// did. The handler's error is the reason's Cause. FailIfRejected sets it.
const FailureRejectedByHook = "rejected_by_hook"

type FailureReason struct {
	// Code names the rejection, in snake case like a DomainError's code:
	// "invalid_credentials", "user_not_found", FailureRejectedByHook. The
	// firing site chooses it. It is the audit event's "code" and the
	// metric's reason attribute, so keep the set of values small.
	Code  string
	Cause error // underlying error, if any. nil for pure business rejections

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
	// the mutated payload or aborting on the first non-nil error. A handler
	// that returns a nil payload leaves it unchanged, and the returned payload
	// is never nil when the error is.
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

// AuditConfig configures the audit events behemoth records. It is
// BootConfig.Audit. The zero value records every event in full.
type AuditConfig struct {
	// OmitIPAndAgent leaves the client's IP address and user agent out of
	// the audit events behemoth records. False, the default, records both.
	// It is separate from SessionConfig.CaptureIPAndAgent, which decides
	// the same for session rows: the audit log serves an investigation, a
	// session row a user's list of devices, and an application may keep
	// the address in one and not the other.
	OmitIPAndAgent bool
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

// FailIfRejected reports an error that came out of a hook chain: the error
// of RunBefore, or of a write whose data hooks may have refused it. Every
// place that runs such a chain inside a flow calls it, so that the flows
// agree on what a refusal is and how it is named.
//
// When err is a rejection (errs.IsRejection), it fires failed with
// reason, after setting reason's Code to FailureRejectedByHook and its Cause
// to err. The caller fills in what only it knows: the subject and the
// metadata. Any other error is a failure of the system and fires nothing, so
// an outage inside a handler is not counted or audited as a refused request.
//
// It returns the error the flow should return: err, or the error of firing
// failed.
func FailIfRejected(dispatcher Dispatcher, hctx *HookContext, failed HookPoint, err error, reason FailureReason) error {
	if !errs.IsRejection(err) {
		return err
	}
	reason.Code, reason.Cause = FailureRejectedByHook, err
	if failErr := dispatcher.Fail(hctx, failed, reason); failErr != nil {
		return failErr
	}
	return err
}

// WithLifecycle wraps fn, the body of a flow, with the flow's three points:
// before runs on the input and may rewrite it or stop the flow, success runs
// on fn's result, and failed fires when a before handler refused the flow
// (FailIfRejected). fn fires failed itself for its own business rejections.
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
			return zero, FailIfRejected(dispatcher, hctx, failed, err, FailureReason{})
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
