package types

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

type countingAudit struct{ events int }

func (a *countingAudit) Record(context.Context, telemetry.AuditEvent) error { a.events++; return nil }

// afterDispatcher builds a dispatcher with one audited after-phase point and
// the given handlers on it, in order.
func afterDispatcher(t *testing.T, audit telemetry.AuditRecorder, handlers ...types.AfterHookFunc) (*DefaultDispatcher, types.HookPoint) {
	t.Helper()
	const point types.HookPoint = "data.test.afterCreate"
	catalog := NewDefaultHookCatalog()
	def := types.HookPointDef{Point: point, Owner: "core", Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}}
	if err := catalog.Declare(def); err != nil {
		t.Fatal(err)
	}
	chain := make([]registeredHandler, len(handlers))
	for i, h := range handlers {
		chain[i] = registeredHandler{plugin: "test", handler: h}
	}
	chains := map[types.HookPoint][]registeredHandler{point: chain}
	return NewDefaultDispatcher(catalog, chains, nil, telemetry.New(nil, audit, nil)), point
}

// A data-level after hook runs inside the write's transaction: the first
// failing handler ends the chain and its error reaches the caller, and no
// audit event is recorded for a write that is about to be rolled back.
func TestRunAfterTxStopsAtTheFirstError(t *testing.T) {
	rejected := errors.New("rejected by hook")
	var ran []int
	audit := &countingAudit{}
	d, point := afterDispatcher(t, audit,
		func(*types.HookContext, any) error { ran = append(ran, 1); return nil },
		func(*types.HookContext, any) error { ran = append(ran, 2); return rejected },
		func(*types.HookContext, any) error { ran = append(ran, 3); return nil },
	)
	hctx := &types.HookContext{Ctx: context.Background()}

	err := d.RunAfterTx(hctx, point, nil)
	if !errors.Is(err, rejected) {
		t.Fatalf("RunAfterTx error = %v, want the handler's error", err)
	}
	if len(ran) != 2 {
		t.Errorf("handlers run = %v, want the chain to stop after the failing one", ran)
	}
	if audit.events != 0 {
		t.Errorf("RunAfterTx recorded %d audit events, want none", audit.events)
	}

	// The Tier 2 dispatch of the same chain keeps going and audits.
	ran = nil
	d.RunAfter(hctx, point, nil)
	if len(ran) != 3 {
		t.Errorf("RunAfter handlers run = %v, want all three", ran)
	}
	if audit.events != 1 {
		t.Errorf("RunAfter recorded %d audit events, want 1", audit.events)
	}
}

func TestRunAfterTxSucceedsAndTurnsPanicsIntoErrors(t *testing.T) {
	hctx := &types.HookContext{Ctx: context.Background()}

	audit := &countingAudit{}
	d, point := afterDispatcher(t, audit, func(*types.HookContext, any) error { return nil })
	if err := d.RunAfterTx(hctx, point, nil); err != nil {
		t.Fatalf("RunAfterTx = %v, want nil", err)
	}
	// hctx has no Tx, so there is no transaction to write the event in and
	// it is recorded directly. Under the store it is written through the
	// write's transaction; tests/plugins covers that against a database.
	if audit.events != 1 {
		t.Errorf("a successful RunAfterTx recorded %d audit events, want 1", audit.events)
	}

	d, point = afterDispatcher(t, nil, func(*types.HookContext, any) error { panic("boom") })
	err := d.RunAfterTx(hctx, point, nil)
	if !behemotherr.Is(err, behemotherr.CategoryInternal) {
		t.Errorf("a panicking handler returned %v, want an internal error", err)
	}
}

// Dispatching a point that was never declared, or in a phase it was not
// declared with, is a configuration error from every method. No handler runs.
func TestDispatchOfUndeclaredOrWrongPhasePointIsAConfigurationError(t *testing.T) {
	ran := false
	d, afterPoint := afterDispatcher(t, nil, func(*types.HookContext, any) error { ran = true; return nil })
	hctx := &types.HookContext{Ctx: context.Background()}
	const undeclared types.HookPoint = "data.test.undeclared"

	for _, point := range []types.HookPoint{undeclared, afterPoint} {
		if _, err := d.RunBefore(hctx, point, nil); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
			t.Errorf("RunBefore(%q) = %v, want a configuration error", point, err)
		}
		if err := d.Fail(hctx, point, types.FailureReason{}); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
			t.Errorf("Fail(%q) = %v, want a configuration error", point, err)
		}
	}
	if err := d.RunAfter(hctx, undeclared, nil); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Errorf("RunAfter(undeclared) = %v, want a configuration error", err)
	}
	if err := d.RunAfterTx(hctx, undeclared, nil); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Errorf("RunAfterTx(undeclared) = %v, want a configuration error", err)
	}
	if ran {
		t.Error("a handler ran on a dispatch that should have been rejected")
	}
	if err := d.Fail(hctx, "", types.FailureReason{}); err != nil {
		t.Errorf("Fail with no point = %v, want nil", err)
	}
}

// Core declares every point its own code fires, each in the phase it is
// fired in, and the data points the store fires pass the Boot check.
func TestCoreDeclaresTheHookPointsItFires(t *testing.T) {
	catalog := NewDefaultHookCatalog()
	ic := newScopedInitContext(catalog, nil, nil, nil, coreOwner)
	if err := CoreDeclareHookPoints(ic); err != nil {
		t.Fatal(err)
	}
	want := map[types.HookPoint]types.HookPhase{
		hooks.HookSignUpBefore: types.BeforeHookPhase, hooks.HookSignUpAfter: types.AfterHookPhase, hooks.HookSignUpFailed: types.FailedHookPhase,
		hooks.HookSignInBefore: types.BeforeHookPhase, hooks.HookSignInCredentialsVerified: types.BeforeHookPhase,
		hooks.HookSignInAfter: types.AfterHookPhase, hooks.HookSignInFailed: types.FailedHookPhase,
		hooks.HookSignOutBefore: types.BeforeHookPhase, hooks.HookSignOutAfter: types.AfterHookPhase,
		hooks.HookSessionBeforeCreate: types.BeforeHookPhase, hooks.HookSessionAfterCreate: types.AfterHookPhase,
		hooks.HookSessionBeforeRevoke: types.BeforeHookPhase, hooks.HookSessionAfterRevoke: types.AfterHookPhase,
		hooks.HookTokenBeforeIssue: types.BeforeHookPhase, hooks.HookTokenAfterIssue: types.AfterHookPhase,
		hooks.HookTokenConsumed: types.AfterHookPhase, hooks.HookTokenFailed: types.FailedHookPhase,
		hooks.HookUserBeforeCreate: types.BeforeHookPhase, hooks.HookUserAfterCreate: types.AfterHookPhase,
		hooks.HookUserBeforeUpdate: types.BeforeHookPhase, hooks.HookUserAfterUpdate: types.AfterHookPhase,
		hooks.HookUserCreated: types.AfterHookPhase, hooks.HookUserUpdated: types.AfterHookPhase,
	}
	for point, phase := range want {
		def, ok := catalog.Lookup(point)
		if !ok {
			t.Errorf("%q is not declared", point)
		} else if def.Phase != phase || def.Owner != coreOwner {
			t.Errorf("%q declared as phase %q by %q, want %q by %q", point, def.Phase, def.Owner, phase, coreOwner)
		}
	}
	if got := len(catalog.All()); got != len(want) {
		t.Errorf("core declares %d points, the test knows %d", got, len(want))
	}

	if err := checkDataHookPoints(catalog, coreDataHookPoints); err != nil {
		t.Errorf("checkDataHookPoints(core) = %v", err)
	}
}

func TestCheckDataHookPointsRejectsUndeclaredAndWrongPhase(t *testing.T) {
	catalog := NewDefaultHookCatalog()
	for _, def := range []types.HookPointDef{
		{Point: "data.t.beforeCreate", Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: "data.t.afterCreate", Owner: coreOwner, Phase: types.AfterHookPhase},
		{Point: "data.t.beforeUpdate", Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: "data.t.afterUpdate", Owner: coreOwner, Phase: types.BeforeHookPhase}, // wrong phase
		{Point: "data.t.created", Owner: coreOwner, Phase: types.AfterHookPhase},
		{Point: "data.t.updated", Owner: coreOwner, Phase: types.AfterHookPhase},
	} {
		if err := catalog.Declare(def); err != nil {
			t.Fatal(err)
		}
	}
	points := tableHookPoints{
		beforeCreate: "data.t.beforeCreate", afterCreate: "data.t.afterCreate",
		beforeUpdate: "data.t.beforeUpdate", afterUpdate: "data.t.afterUpdate",
		created: "data.t.created", updated: "data.t.updated",
	}
	if err := checkDataHookPoints(catalog, map[string]tableHookPoints{"t": points}); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Errorf("wrong phase: %v, want a configuration error", err)
	}
	points.afterUpdate = "data.t.missing"
	if err := checkDataHookPoints(catalog, map[string]tableHookPoints{"t": points}); !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Errorf("undeclared point: %v, want a configuration error", err)
	}
}

// Handlers get the point and phase being dispatched even when the firing
// site left them empty, on a copy: the site's context is not changed, and
// the copy shares its Values.
func TestDispatcherSetsPointAndPhaseOnACopy(t *testing.T) {
	var seen *types.HookContext
	d, point := afterDispatcher(t, nil, func(hctx *types.HookContext, _ any) error {
		seen = hctx
		hctx.Values["note"] = "from the handler"
		return nil
	})

	site := &types.HookContext{Ctx: context.Background(), Values: behemoth.M{}}
	if err := d.RunAfter(site, point, nil); err != nil {
		t.Fatal(err)
	}
	if seen.Point != point || seen.Phase != types.AfterHookPhase {
		t.Errorf("handler saw point %q phase %q", seen.Point, seen.Phase)
	}
	if site.Point != "" || site.Phase != "" {
		t.Errorf("the firing site's context was changed: %q %q", site.Point, site.Phase)
	}
	if site.Values["note"] != "from the handler" {
		t.Error("the handler's note did not reach the firing site's Values")
	}

	// A context without Values must not make a handler's write panic.
	if err := d.RunAfterTx(&types.HookContext{Ctx: context.Background()}, point, nil); err != nil {
		t.Fatalf("a nil Values map reached the handler: %v", err)
	}
}

// Every handler call is timed, a failing one is counted, and a core point
// increments its counter in the metric catalog.
func TestDispatcherMetrics(t *testing.T) {
	tel, rec := telemetrytest.New()
	catalog := NewDefaultHookCatalog()
	for _, def := range []types.HookPointDef{
		{Point: hooks.HookSignInAfter, Owner: "core", Phase: types.AfterHookPhase},
		{Point: hooks.HookSignInFailed, Owner: "core", Phase: types.FailedHookPhase},
		{Point: hooks.HookTokenAfterIssue, Owner: "core", Phase: types.AfterHookPhase},
	} {
		if err := catalog.Declare(def); err != nil {
			t.Fatal(err)
		}
	}
	chains := map[types.HookPoint][]registeredHandler{
		hooks.HookSignInAfter: {
			{plugin: "mailer", handler: types.AfterHookFunc(func(*types.HookContext, any) error { return errors.New("smtp down") })},
			{plugin: "analytics", handler: types.AfterHookFunc(func(*types.HookContext, any) error { return nil })},
		},
	}
	d := NewDefaultDispatcher(catalog, chains, nil, tel)
	hctx := &types.HookContext{Ctx: context.Background()}

	if err := d.RunAfter(hctx, hooks.HookSignInAfter, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "invalidCredentials"}); err != nil {
		t.Fatal(err)
	}
	if err := d.RunAfter(hctx, hooks.HookTokenAfterIssue, &models.Token{Kind: "password_reset"}); err != nil {
		t.Fatal(err)
	}

	m := rec.Metrics
	point := string(hooks.HookSignInAfter)
	if n := len(m.Observations(telemetry.MetricHookDuration, behemoth.M{telemetry.AttrPoint: point})); n != 2 {
		t.Errorf("handler durations = %d, want one per handler", n)
	}
	if n := m.Count(telemetry.MetricHookErrors, behemoth.M{telemetry.AttrPoint: point, telemetry.AttrPlugin: "mailer", telemetry.AttrPhase: "after"}); n != 1 {
		t.Errorf("mailer errors = %d, want 1", n)
	}
	if n := m.Count(telemetry.MetricHookErrors, nil); n != 1 {
		t.Errorf("hook errors = %d, want only the mailer's", n)
	}
	if n := m.Count(telemetry.MetricSignIn, behemoth.M{telemetry.AttrOutcome: "success"}); n != 1 {
		t.Errorf("successful sign-ins = %d, want 1", n)
	}
	if n := m.Count(telemetry.MetricSignIn, behemoth.M{telemetry.AttrOutcome: "failure", telemetry.AttrReason: "invalidCredentials"}); n != 1 {
		t.Errorf("failed sign-ins = %d, want 1 with its reason", n)
	}
	if n := m.Count(telemetry.MetricTokenIssued, behemoth.M{telemetry.AttrKind: "password_reset"}); n != 1 {
		t.Errorf("tokens issued = %d, want 1 with its kind", n)
	}
}

// fixedLimiter answers every check the same way.
type fixedLimiter struct {
	allowed bool
	err     error
}

func (l fixedLimiter) Allow(context.Context, string, types.Limit) (bool, time.Duration, error) {
	return l.allowed, time.Second, l.err
}

// Each evaluated rule is counted once with how it ended, and a rejection is
// also an audit event with the outcome "denied".
func TestRateLimiterMetrics(t *testing.T) {
	tel, rec := telemetrytest.New()
	rl := &DefaultRateLimiter{tel: tel}
	ctx := context.Background()
	check := func(l types.Limiter) error {
		return rl.evaluate(ctx, "signin", "signin:203.0.113.7", "203.0.113.7", l, types.Limit{}, "", 0)
	}

	if err := check(fixedLimiter{allowed: true}); err != nil {
		t.Fatal(err)
	}
	if err := check(fixedLimiter{allowed: false}); !behemotherr.Is(err, behemotherr.CategoryRateLimited) {
		t.Fatalf("a rejected check returned %v", err)
	}
	if err := check(fixedLimiter{err: errors.New("redis down")}); err != nil {
		t.Fatalf("a store failure with fail-open returned %v", err)
	}

	for result, want := range map[string]int64{"allowed": 1, "limited": 1, "error": 1} {
		if n := rec.Metrics.Count(telemetry.MetricRateLimitChecks, behemoth.M{telemetry.AttrRule: "signin", telemetry.AttrResult: result}); n != want {
			t.Errorf("checks with result %q = %d, want %d", result, n, want)
		}
	}
	events := rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	if len(events) != 1 || events[0].Outcome != telemetry.OutcomeDenied || events[0].IPAddress != "203.0.113.7" {
		t.Errorf("audit events = %+v, want one denied event with the address", events)
	}
}
