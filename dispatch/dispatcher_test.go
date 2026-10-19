package dispatch

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
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
	return NewDefaultDispatcher(catalog, chains, nil, nil, telemetry.New(nil, audit, nil)), point
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
	if !errs.IsCategory(err, errs.CategoryInternal) {
		t.Errorf("a panicking handler returned %v, want an internal error", err)
	}
}

// beforeDispatcher builds a dispatcher with one before-phase point and the
// given handlers on it, in order.
func beforeDispatcher(t *testing.T, handlers ...types.BeforeHookFunc) (*DefaultDispatcher, types.HookPoint) {
	t.Helper()
	const point types.HookPoint = "data.test.beforeCreate"
	catalog := NewDefaultHookCatalog()
	if err := catalog.Declare(types.HookPointDef{Point: point, Owner: "core", Phase: types.BeforeHookPhase}); err != nil {
		t.Fatal(err)
	}
	chain := make([]registeredHandler, len(handlers))
	for i, h := range handlers {
		chain[i] = registeredHandler{plugin: "test", handler: h}
	}
	chains := map[types.HookPoint][]registeredHandler{point: chain}
	return NewDefaultDispatcher(catalog, chains, nil, nil, telemetry.New(nil, nil, nil)), point
}

// A before handler that returns a nil payload leaves the payload unchanged,
// wherever it sits in the chain. The next handler and the caller get a map
// they can write to, and a rewrite made before or after the nil is kept.
func TestRunBeforeTreatsANilPayloadAsUnchanged(t *testing.T) {
	validate := func(*types.HookContext, behemoth.M) (behemoth.M, error) { return nil, nil }
	set := func(key string) types.BeforeHookFunc {
		return func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) {
			p[key] = true // panics on a nil map
			return p, nil
		}
	}
	replace := func(*types.HookContext, behemoth.M) (behemoth.M, error) {
		return behemoth.M{"replaced": true}, nil
	}
	inPlace := func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) {
		p["inPlace"] = true
		return nil, nil
	}
	empty := func(*types.HookContext, behemoth.M) (behemoth.M, error) { return behemoth.M{}, nil }

	tests := []struct {
		name     string
		handlers []types.BeforeHookFunc
		input    behemoth.M
		want     behemoth.M
	}{
		{"only handler", []types.BeforeHookFunc{validate}, behemoth.M{"email": "a@b.c"}, behemoth.M{"email": "a@b.c"}},
		{"first handler", []types.BeforeHookFunc{validate, set("second")}, behemoth.M{"email": "a@b.c"}, behemoth.M{"email": "a@b.c", "second": true}},
		{"middle handler", []types.BeforeHookFunc{set("first"), validate, set("third")}, behemoth.M{}, behemoth.M{"first": true, "third": true}},
		{"last handler keeps an earlier replacement", []types.BeforeHookFunc{replace, validate}, behemoth.M{"email": "a@b.c"}, behemoth.M{"replaced": true}},
		{"a change made in place is kept", []types.BeforeHookFunc{inPlace}, behemoth.M{}, behemoth.M{"inPlace": true}},
		{"an empty map is a rewrite", []types.BeforeHookFunc{empty}, behemoth.M{"email": "a@b.c"}, behemoth.M{}},
		{"nil input, no handlers", nil, nil, behemoth.M{}},
		{"nil input reaches a handler as an empty map", []types.BeforeHookFunc{set("first")}, nil, behemoth.M{"first": true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, point := beforeDispatcher(t, tc.handlers...)
			got, err := d.RunBefore(&types.HookContext{Ctx: context.Background()}, point, tc.input)
			if err != nil {
				t.Fatalf("RunBefore = %v, want nil", err)
			}
			if got == nil {
				t.Fatal("RunBefore returned a nil payload")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RunBefore payload = %v, want %v", got, tc.want)
			}
		})
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
		if _, err := d.RunBefore(hctx, point, nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
			t.Errorf("RunBefore(%q) = %v, want a configuration error", point, err)
		}
		if err := d.Fail(hctx, point, types.FailureReason{}); !errs.IsCategory(err, errs.CategoryConfiguration) {
			t.Errorf("Fail(%q) = %v, want a configuration error", point, err)
		}
	}
	if err := d.RunAfter(hctx, undeclared, nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
		t.Errorf("RunAfter(undeclared) = %v, want a configuration error", err)
	}
	if err := d.RunAfterTx(hctx, undeclared, nil); !errs.IsCategory(err, errs.CategoryConfiguration) {
		t.Errorf("RunAfterTx(undeclared) = %v, want a configuration error", err)
	}
	if ran {
		t.Error("a handler ran on a dispatch that should have been rejected")
	}
	if err := d.Fail(hctx, "", types.FailureReason{}); err != nil {
		t.Errorf("Fail with no point = %v, want nil", err)
	}
}

// coreOwner is the owner Boot declares core's points with.
const coreOwner = "core"

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
	if err := checkDataHookPoints(catalog, map[string]tableHookPoints{"t": points}); !errs.IsCategory(err, errs.CategoryConfiguration) {
		t.Errorf("wrong phase: %v, want a configuration error", err)
	}
	points.afterUpdate = "data.t.missing"
	if err := checkDataHookPoints(catalog, map[string]tableHookPoints{"t": points}); !errs.IsCategory(err, errs.CategoryConfiguration) {
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
	d := NewDefaultDispatcher(catalog, chains, nil, nil, tel)
	hctx := &types.HookContext{Ctx: context.Background()}

	if err := d.RunAfter(hctx, hooks.HookSignInAfter, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "invalid_credentials"}); err != nil {
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
	if n := m.Count(telemetry.MetricSignIn, behemoth.M{telemetry.AttrOutcome: "failure", telemetry.AttrReason: "invalid_credentials"}); n != 1 {
		t.Errorf("failed sign-ins = %d, want 1 with its reason", n)
	}
	if n := m.Count(telemetry.MetricTokenIssued, behemoth.M{telemetry.AttrKind: "password_reset"}); n != 1 {
		t.Errorf("tokens issued = %d, want 1 with its kind", n)
	}
}
