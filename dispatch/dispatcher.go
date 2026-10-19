// Package dispatch runs hook points: the catalog they are declared in, the
// registry handlers are attached through, the dispatcher that runs each
// point's chain with its rate limits, metrics, and audit events, and the data
// hooks the store fires around writes. The contracts it implements are in
// package core.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
)

type DefaultDispatcher struct {
	catalog      core.HookCatalog
	frozenChains Chains
	rateLimiter  core.RateLimiter // nil-safe; a deployment with no declared point rules simply skips this
	tel          *telemetry.Telemetry
	audit        core.AuditConfig // what the audit events of audited points record
}

// NewDefaultDispatcher returns the dispatcher of chains, which FreezeChains
// froze for the points of catalog. rateLimiter checks the hook rules of a
// point before its chain runs, and may be nil. audit says what the events of
// audited points record; its zero value records them in full.
func NewDefaultDispatcher(
	catalog core.HookCatalog,
	chains Chains,
	rateLimiter core.RateLimiter,
	audit core.AuditConfig,
	tel *telemetry.Telemetry,
) *DefaultDispatcher {
	return &DefaultDispatcher{catalog: catalog, frozenChains: chains, rateLimiter: rateLimiter, audit: audit, tel: telemetry.OrDefault(tel).Named("hooks")}
}

// checkPhase is the single check that point exists and is declared with the
// expected phase. Either failure is a mistake in the code that fires the
// point, not in a handler, and is returned as a configuration error like the
// ones Prepare and Boot return. op names the dispatching method.
func (d *DefaultDispatcher) checkPhase(op string, point core.HookPoint, expected core.HookPhase) (core.HookPointDef, error) {
	def, ok := d.catalog.Lookup(point)
	if !ok {
		return core.HookPointDef{}, errs.NewConfigurationError(op, fmt.Sprintf("point %q was never declared", point), nil)
	}
	if def.Phase != expected {
		return core.HookPointDef{}, errs.NewConfigurationError(op,
			fmt.Sprintf("point %q is phase %q, cannot dispatch as %q", point, def.Phase, expected), nil)
	}
	return def, nil
}

// forPoint returns the context the handlers of point receive: a shallow copy
// of the firing site's with Point and Phase set, so a site can't dispatch one
// point with a context that names another, and a site that leaves them empty
// (a flow reusing one context for all its points) still gives handlers the
// right ones. The copy shares the Values map. A nil map is replaced, so a
// handler's write can't panic; such notes last for this dispatch only.
func forPoint(hctx *core.HookContext, point core.HookPoint, phase core.HookPhase) *core.HookContext {
	c := *hctx
	c.Point, c.Phase = point, phase
	if c.Values == nil {
		c.Values = behemoth.M{}
	}
	return &c
}

func (d *DefaultDispatcher) safeInvokeBefore(hctx *core.HookContext, fn core.BeforeHookFunc, payload behemoth.M, point core.HookPoint, plugin string) (m behemoth.M, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.NewInternalError("Dispatcher.RunBefore", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
			d.logError(hctx.Ctx, "before-hook panicked", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: plugin})
		}
	}()
	return fn(hctx, payload)
}

// safeInvokeAfter calls an after handler and turns a panic into an internal
// error. It does not log: the caller decides what an error means. RunAfter
// logs it and goes on, RunAfterTx returns it. op names the calling method.
func (d *DefaultDispatcher) safeInvokeAfter(op string, hctx *core.HookContext, fn core.AfterHookFunc, result any, point core.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.NewInternalError(op, fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, result)
}

// RunBefore implements [Dispatcher]. A handler never receives a nil payload
// and the caller never gets one back: a nil input starts the chain as an empty
// map, and a handler that returns a nil map leaves the payload as it was.
func (d *DefaultDispatcher) RunBefore(hctx *core.HookContext, point core.HookPoint, payload behemoth.M) (behemoth.M, error) {
	if _, err := d.checkPhase("Dispatcher.RunBefore", point, core.BeforeHookPhase); err != nil {
		return nil, err
	}
	hctx = forPoint(hctx, point, core.BeforeHookPhase)
	defer d.chainSpan(hctx, point, core.BeforeHookPhase).End()

	// rate-limiting, evaluated before any registered before-hook handler runs
	// rate limiter will handle auditing
	if d.rateLimiter != nil {
		if err := d.rateLimiter.CheckHookLimit(hctx.Ctx, point, hctx); err != nil {
			return nil, err // CategoryRateLimited: indistinguishable, to every existing caller, from a before-hook abort
		}
	}

	mutated := payload
	if mutated == nil {
		mutated = behemoth.M{}
	}
	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(core.BeforeHookFunc)
		if !ok {
			// Should be structurally impossible. HookRegistry.OnBefore only
			// ever stores a BeforeHookFunc under a Before-phase point. If this
			// fires, it's a bug in the registry itself
			err := errs.NewInternalError("Dispatcher.RunBefore",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Before", point, h.plugin))

			d.logError(hctx.Ctx, "before-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			return nil, err
		}

		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		result, err := d.safeInvokeBefore(handlerCtx, fn, mutated, point, h.plugin)
		d.observeHandler(hctx, point, core.BeforeHookPhase, h.plugin, start, span, err)
		if err != nil {
			return nil, err // abort and propagate error (caller decides whether/how to Fail)
		}
		// A nil map means "no change", so a handler that only validates can
		// return nil, nil. Changes it made to the map in place are kept.
		if result != nil {
			mutated = result
		}
	}
	return mutated, nil
}

// RunAfter implements [Dispatcher]. The only error it returns is checkPhase's;
// handler errors are logged.
func (d *DefaultDispatcher) RunAfter(hctx *core.HookContext, point core.HookPoint, result any) error {
	def, err := d.checkPhase("Dispatcher.RunAfter", point, core.AfterHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, core.AfterHookPhase)
	defer d.chainSpan(hctx, point, core.AfterHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(core.AfterHookFunc)
		if !ok {
			err := errs.NewInternalError("Dispatcher.RunAfter",
				fmt.Errorf("point %q: handler from %q has wrong type for phase After", point, h.plugin))
			d.logError(hctx.Ctx, "after-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			continue // execution continues since one bad registration must not stop the rest
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeAfter("Dispatcher.RunAfter", handlerCtx, fn, result, point, h.plugin)
		d.observeHandler(hctx, point, core.AfterHookPhase, h.plugin, start, span, err)
		if err != nil {
			// Errors in AfterHookPhase are not propagated
			d.logError(hctx.Ctx, "after-hook failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
		}
	}

	d.countPoint(hctx, point, result, nil)
	d.recordAudit(hctx, point, def, result, nil)
	return nil
}

// RunAfterTx implements [Dispatcher]. It mirrors RunBefore rather than
// RunAfter: the first failing handler ends the chain and its error is
// returned as-is, because the caller (the store) rolls the write back on it.
func (d *DefaultDispatcher) RunAfterTx(hctx *core.HookContext, point core.HookPoint, result any) error {
	def, err := d.checkPhase("Dispatcher.RunAfterTx", point, core.AfterHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, core.AfterHookPhase)
	defer d.chainSpan(hctx, point, core.AfterHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(core.AfterHookFunc)
		if !ok {
			err := errs.NewInternalError("Dispatcher.RunAfterTx",
				fmt.Errorf("point %q: handler from %q has wrong type for phase After", point, h.plugin))
			d.logError(hctx.Ctx, "after-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			return err
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeAfter("Dispatcher.RunAfterTx", handlerCtx, fn, result, point, h.plugin)
		d.observeHandler(hctx, point, core.AfterHookPhase, h.plugin, start, span, err)
		if err != nil {
			return err // abort and propagate; the write is rolled back
		}
	}
	// The event is written through the write's transaction, so it can't
	// describe a row that was rolled back.
	return d.recordAuditTx(hctx, point, def, result)
}

// Fail implements [Dispatcher]. The only error it returns is checkPhase's;
// handler errors are logged.
func (d *DefaultDispatcher) Fail(hctx *core.HookContext, point core.HookPoint, reason core.FailureReason) error {
	if point == "" {
		return nil // Tier 1 CRUD paths have no Failed-phase point to cascade to (hook taxonomy round)
	}
	def, err := d.checkPhase("Dispatcher.Fail", point, core.FailedHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, core.FailedHookPhase)
	defer d.chainSpan(hctx, point, core.FailedHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(core.FailedHookFunc)
		if !ok {
			err := errs.NewInternalError("Dispatcher.Fail",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Failed", point, h.plugin))
			d.logError(hctx.Ctx, "failed-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			continue
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeFailed(handlerCtx, fn, reason, point, h.plugin)
		d.observeHandler(hctx, point, core.FailedHookPhase, h.plugin, start, span, err)
		if err != nil {
			d.logError(hctx.Ctx, "failed-hook handler errored", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
		}
	}

	d.countPoint(hctx, point, nil, &reason)
	d.recordAudit(hctx, point, def, nil, &reason)
	return nil
}

func (d *DefaultDispatcher) safeInvokeFailed(hctx *core.HookContext, fn core.FailedHookFunc, reason core.FailureReason, point core.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.NewInternalError("Dispatcher.Fail", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, reason)
}

// chainSpan starts the span of one dispatch and makes hctx, the dispatch's
// own copy of the hook context (forPoint), carry it, so that the handlers,
// the rate-limit check and the audit record nest under it. A point without
// handlers gets no span: most dispatches have none, and an empty span per
// point would bury a trace. The caller ends the span.
func (d *DefaultDispatcher) chainSpan(hctx *core.HookContext, point core.HookPoint, phase core.HookPhase) telemetry.Span {
	if len(d.frozenChains[point]) == 0 || !d.tel.TracingEnabled() {
		return telemetry.SpanFrom(context.Background()) // records nothing
	}
	ctx, span := d.tel.StartSpan(hctx.Ctx, telemetry.SpanHookChain,
		behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPhase: string(phase)})
	hctx.Ctx = ctx
	return span
}

// handlerSpan starts the span of one handler call and returns the hook
// context the handler receives: a copy of hctx carrying the span, so what
// the handler does with HookContext.Ctx nests under it. The copy shares
// hctx's Values. observeHandler ends the span.
func (d *DefaultDispatcher) handlerSpan(hctx *core.HookContext, point core.HookPoint, plugin string) (*core.HookContext, telemetry.Span) {
	if !d.tel.TracingEnabled() {
		return hctx, telemetry.SpanFrom(context.Background())
	}
	ctx, span := d.tel.StartSpan(hctx.Ctx, telemetry.SpanHookHandler,
		behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPlugin: plugin})
	c := *hctx
	c.Ctx = ctx
	return &c, span
}

// observeHandler measures one handler call: its duration, and an error
// count when it returned an error or panicked. On a before point a returned
// error is a veto, which is how a handler refuses an operation; the phase
// attribute tells those apart from the failures of after and failed
// handlers.
func (d *DefaultDispatcher) observeHandler(hctx *core.HookContext, point core.HookPoint, phase core.HookPhase, plugin string, start time.Time, span telemetry.Span, err error) {
	telemetry.FinishSpan(span, err) // a veto is not marked as a failed span; see FinishSpan
	if !d.tel.MetricsEnabled() {
		return
	}
	attrs := behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPhase: string(phase), telemetry.AttrPlugin: plugin}
	d.tel.ObserveSince(hctx.Ctx, telemetry.MetricHookDuration, start, attrs)
	if err != nil {
		d.tel.Count(hctx.Ctx, telemetry.MetricHookErrors, attrs)
	}
}

// pointMetric is the counter a core point increments when it is dispatched,
// with the outcome it stands for.
type pointMetric struct {
	name    string
	outcome telemetry.AuditOutcome // "" for a counter that has no outcome attribute
}

// corePointMetrics maps core's after and failed points to the counters of
// the metric catalog, so that the flows and managers firing them are counted
// without reporting anything themselves. A point declared by a plugin has no
// entry: the plugin counts what it needs through AuthContext.Telemetry.
var corePointMetrics = map[core.HookPoint]pointMetric{
	hooks.HookSignInAfter:  {telemetry.MetricSignIn, telemetry.OutcomeSuccess},
	hooks.HookSignInFailed: {telemetry.MetricSignIn, telemetry.OutcomeFailure},
	hooks.HookSignUpAfter:  {telemetry.MetricSignUp, telemetry.OutcomeSuccess},
	hooks.HookSignUpFailed: {telemetry.MetricSignUp, telemetry.OutcomeFailure},

	hooks.HookSessionAfterCreate: {name: telemetry.MetricSessionCreated},
	hooks.HookSessionAfterRevoke: {name: telemetry.MetricSessionRevoked},

	hooks.HookTokenAfterIssue: {name: telemetry.MetricTokenIssued},
	hooks.HookTokenConsumed:   {name: telemetry.MetricTokenConsumed},
	hooks.HookTokenFailed:     {name: telemetry.MetricTokenFailed},
}

// countPoint increments the counter of a core point, if it has one. A
// failure adds its code as the reason, and a token result its kind.
func (d *DefaultDispatcher) countPoint(hctx *core.HookContext, point core.HookPoint, result any, reason *core.FailureReason) {
	metric, ok := corePointMetrics[point]
	if !ok || !d.tel.MetricsEnabled() {
		return
	}
	attrs := behemoth.M{}
	if metric.outcome != "" {
		attrs[telemetry.AttrOutcome] = string(metric.outcome)
	}
	if reason != nil {
		attrs[telemetry.AttrReason] = reason.Code
	}
	if tok, ok := result.(*models.Token); ok {
		attrs[telemetry.AttrKind] = string(tok.Kind)
	}
	d.tel.Count(hctx.Ctx, metric.name, attrs)
}

func (d *DefaultDispatcher) logError(ctx context.Context, msg string, err error, fields behemoth.M) {
	d.tel.Logger.Error(ctx, msg, telemetry.ErrorFields(err, fields))
}

// recordAudit records the audit event of a point dispatched with RunAfter or
// Fail, best effort: the operation is over, so a failed write is logged
// (Telemetry.RecordAudit) and changes nothing.
func (d *DefaultDispatcher) recordAudit(hctx *core.HookContext, point core.HookPoint, def core.HookPointDef, result any, reason *core.FailureReason) {
	if def.Audit == nil {
		return
	}
	d.tel.RecordAudit(hctx.Ctx, d.auditEvent(hctx, point, def, result, reason))
}

// recordAuditTx records the audit event of a data point dispatched with
// RunAfterTx. A recorder that can write through a transaction
// (telemetry.TxAuditRecorder, the database recorder) gets the write's own,
// so the event commits or rolls back with the row, and its error is
// returned to fail the write. Any other recorder can't take part in the
// transaction: it is called once the transaction has committed, best
// effort.
func (d *DefaultDispatcher) recordAuditTx(hctx *core.HookContext, point core.HookPoint, def core.HookPointDef, result any) error {
	if def.Audit == nil {
		return nil
	}
	event := d.auditEvent(hctx, point, def, result, nil)
	if hctx.Tx == nil {
		// Not fired by the store: there is no transaction to join.
		d.tel.RecordAudit(hctx.Ctx, event)
		return nil
	}
	event = telemetry.NormalizeAuditEvent(hctx.Ctx, event)
	inTx, rest := telemetry.SplitAuditRecorders(d.tel.Audit)
	for _, rec := range inTx {
		if err := rec.RecordTx(hctx.Ctx, hctx.Tx.DB(), event); err != nil {
			d.tel.AuditFailed(hctx.Ctx, event.Type, err)
			return fmt.Errorf("audit event %q could not be recorded with the write: %w", event.Type, err)
		}
	}
	if len(rest) > 0 {
		hctx.Tx.AfterCommit(hctx.Ctx, func(ctx context.Context) {
			for _, rec := range rest {
				if err := rec.Record(ctx, event); err != nil {
					d.tel.AuditFailed(ctx, event.Type, err)
				}
			}
		})
	}
	return nil
}

// auditEvent builds the event of one dispatch from what the dispatcher can
// see: the point, its result or failure reason, the operation's Values and
// the caller on the context.
//
// Metadata of a failure: the reason's Metadata, its Code as "code", and for
// a reason with a Cause the error's text as "cause" and, when it is a typed
// error with a code, that code as "causeCode".
//
// Subject, first match: the failure reason's, the result's (auditSubject),
// the operation's user (Values[HookValueUserID]).
//
// Actor, first match: the caller's principal, with its delegate
// (telemetry.AuditActor); for a successful operation of an anonymous caller
// that a transport authenticated, the user the subject belongs to, which
// covers sign-up and sign-in, where no session exists yet. Otherwise the
// actor is anonymous when a transport authenticated the caller, and the
// system when no transport did: code in the process that did not name
// itself. A failed operation is never attributed to its subject: a wrong
// password for an account was not typed by its owner as far as behemoth
// knows.
//
// The address and the user agent are the caller's (identity.Peer), unless
// AuditConfig.OmitIPAndAgent leaves them out. The session is the one the
// caller signed in with.
func (d *DefaultDispatcher) auditEvent(hctx *core.HookContext, point core.HookPoint, def core.HookPointDef, result any, reason *core.FailureReason) telemetry.AuditEvent {
	event := telemetry.AuditEvent{Type: coalesce(def.Audit.Type, string(point)), Metadata: behemoth.M{}}

	subjectType, subjectID, subjectUser, sessionID := auditSubject(result)
	if reason != nil {
		event.Outcome = telemetry.OutcomeFailure
		maps.Copy(event.Metadata, reason.Metadata)
		event.Metadata["code"] = reason.Code
		if reason.Cause != nil {
			event.Metadata["cause"] = reason.Cause.Error()
			// The cause's own code says why, where the reason's code only
			// says that a hook refused (core.FailureRejectedByHook). It is
			// not a metric attribute: any plugin can define one. See ADR-0001.
			if de, ok := errors.AsType[*errs.DomainError](reason.Cause); ok && de.Code != "" {
				event.Metadata["causeCode"] = de.Code
			}
		}
		if reason.SubjectID != "" {
			subjectType, subjectID, subjectUser = reason.SubjectType, reason.SubjectID, ""
			if subjectType == models.UserTable {
				subjectUser = subjectID
			}
		}
	}
	if subjectID == "" {
		if id := valueString(hctx.Values, hooks.HookValueUserID); id != "" {
			subjectType, subjectID, subjectUser = models.UserTable, id, id
		}
	}
	event.SubjectType, event.SubjectID = subjectType, subjectID

	if tok, ok := result.(*models.Token); ok {
		event.Metadata[hooks.HookValueTokenKind] = string(tok.Kind)
	}

	caller := hctx.Caller()
	peer := caller.Peer()
	if !d.audit.OmitIPAndAgent {
		event.IPAddress, event.UserAgent = peer.IPAddress, peer.UserAgent
	}
	if sess, ok := caller.Session(); ok && !caller.IsAnonymous() {
		event.SessionID = sess.ID
	}
	if event.SessionID == "" {
		event.SessionID = coalesce(sessionID, valueString(hctx.Values, hooks.HookValueSessionID))
	}
	event.ActorType, event.ActorID, event.DelegateType, event.DelegateID = telemetry.AuditActor(caller)
	if event.ActorType == "" {
		overTransport := peer.Transport != ""
		switch {
		case overTransport && reason == nil && subjectUser != "":
			event.ActorType, event.ActorID = telemetry.ActorUser, subjectUser
		case overTransport:
			event.ActorType = telemetry.ActorAnonymous
		default:
			event.ActorType = telemetry.ActorSystem
		}
	}
	return event
}

func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// valueString reads a string from an operation's Values. Ids are stored as
// strings; any other non-nil value is formatted.
func valueString(values behemoth.M, key string) string {
	switch v := values[key].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

// auditSubject reads the subject of an audit event from a hook result:
// its type and id, the user it belongs to (userID, "" when unknown), and
// the session it is or carries (sessionID).
//
// A result that is not a Model says what it is about by implementing
// core.AuditSubject, as the email/password plugin's SignInResult does.
func auditSubject(result any) (subjectType, subjectID, userID, sessionID string) {
	switch r := result.(type) {
	case nil:
		return "", "", "", ""
	case *models.Session:
		return models.SessionTable, r.ID, r.UserID, r.ID
	case core.AuditSubject:
		subjectType, subjectID = r.AuditSubject()
	case behemoth.Model:
		subjectType, subjectID = r.SchemaName(), fmt.Sprint(r.PrimaryKeyField())
	}
	if subjectType == models.UserTable {
		userID = subjectID
	}
	return subjectType, subjectID, userID, ""
}

var _ core.Dispatcher = (*DefaultDispatcher)(nil)
