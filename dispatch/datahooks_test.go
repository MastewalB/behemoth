package dispatch

import (
	"context"
	"errors"
	"testing"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/core/hooks"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/store"
)

type recordingDispatcher struct {
	before, after []*core.HookContext
	committed     []*core.HookContext // dispatched with RunAfter
	rewrite       behemoth.M
	afterErr      error
}

func (d *recordingDispatcher) RunBefore(hctx *core.HookContext, point core.HookPoint, payload behemoth.M) (behemoth.M, error) {
	d.before = append(d.before, hctx)
	for k, v := range d.rewrite {
		payload[k] = v
	}
	return payload, nil
}
func (d *recordingDispatcher) RunAfter(hctx *core.HookContext, point core.HookPoint, result any) error {
	d.committed = append(d.committed, hctx)
	return nil
}
func (d *recordingDispatcher) RunAfterTx(hctx *core.HookContext, point core.HookPoint, result any) error {
	d.after = append(d.after, hctx)
	return d.afterErr
}
func (d *recordingDispatcher) Fail(*core.HookContext, core.HookPoint, core.FailureReason) error {
	return nil
}

func TestDataHooksDispatchMappedTablesOnly(t *testing.T) {
	d := &recordingDispatcher{rewrite: behemoth.M{models.UserFirstname: "from-hook"}}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()

	row, err := h.BeforeCreate(ctx, nil, "users", behemoth.M{models.UserEmail: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if row[models.UserFirstname] != "from-hook" {
		t.Errorf("BeforeCreate did not return the dispatcher's rewrite: %v", row)
	}
	h.AfterCreate(ctx, store.New(nil), "users", &models.User{})
	if len(d.before) != 1 || d.before[0].Point != hooks.HookUserBeforeCreate || d.before[0].Phase != core.BeforeHookPhase {
		t.Fatalf("before dispatch = %+v", d.before)
	}
	if len(d.after) != 1 || d.after[0].Point != hooks.HookUserAfterCreate {
		t.Fatalf("after dispatch = %+v", d.after)
	}

	// A table without hook points: untouched, nothing dispatched.
	in := behemoth.M{"x": 1}
	out, err := h.BeforeCreate(ctx, nil, "audit_events", in)
	if err != nil || out["x"] != 1 {
		t.Errorf("unmapped table: row %v, err %v", out, err)
	}
	h.AfterCreate(ctx, store.New(nil), "audit_events", &models.User{})
	if len(d.before) != 1 || len(d.after) != 1 || len(d.committed) != 1 {
		t.Error("an unmapped table dispatched a hook")
	}
}

func TestDataHooksUpdatePublishesTheID(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()

	if _, err := h.BeforeUpdate(ctx, nil, "users", "u1", behemoth.M{models.UserFirstname: "Ada"}); err != nil {
		t.Fatal(err)
	}
	h.AfterUpdate(ctx, store.New(nil), "users", &models.User{ID: "u1"})
	if len(d.before) != 1 || d.before[0].Point != hooks.HookUserBeforeUpdate || d.before[0].Values[hooks.HookValueUserID] != "u1" {
		t.Fatalf("before update dispatch = %+v", d.before)
	}
	if len(d.after) != 1 || d.after[0].Point != hooks.HookUserAfterUpdate || d.after[0].Values[hooks.HookValueUserID] != "u1" {
		t.Fatalf("after update dispatch = %+v", d.after)
	}

	out, err := h.BeforeUpdate(ctx, nil, "audit_events", 1, behemoth.M{"x": 1})
	if err != nil || out["x"] != 1 || len(d.before) != 1 {
		t.Errorf("unmapped table: changes %v, err %v, dispatched %d", out, err, len(d.before))
	}
}

// A write dispatches with the write's context, so a handler finds what the
// context carries, such as the request being handled (httpapi.RequestFrom),
// and with the AuthContext and Values of its own.
func TestDataHooksCarryTheContext(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}

	type requestKey struct{}
	ctx := context.WithValue(context.Background(), requestKey{}, "the request")
	if _, err := h.BeforeCreate(ctx, nil, "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	got := d.before[0]
	if got.Ctx.Value(requestKey{}) != "the request" {
		t.Error("the write's context was not carried into the data hook")
	}
	if got.Values == nil {
		t.Error("the data hook has no Values")
	}
	if got.Auth == nil {
		t.Error("the data hook has no AuthContext")
	}
}

// Data hooks dispatch with the store that made the write, and an after
// hook's error goes back to that store.
func TestDataHooksPublishTheStoreAndReturnAfterErrors(t *testing.T) {
	d := &recordingDispatcher{afterErr: errors.New("rejected by hook")}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()
	tx := store.New(nil)

	if !h.Fires("users") || h.Fires("audit_events") {
		t.Error("Fires should report exactly the tables with hook points")
	}
	if _, err := h.BeforeCreate(ctx, tx, "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	if err := h.AfterCreate(ctx, tx, "users", &models.User{}); !errors.Is(err, d.afterErr) {
		t.Errorf("AfterCreate = %v, want the dispatcher's error", err)
	}
	if err := h.AfterUpdate(ctx, tx, "users", &models.User{ID: "u1"}); !errors.Is(err, d.afterErr) {
		t.Errorf("AfterUpdate = %v, want the dispatcher's error", err)
	}
	for _, hctx := range append(d.before, d.after...) {
		if hctx.Tx != tx {
			t.Errorf("%s: HookContext.Tx is not the store that made the write", hctx.Point)
		}
	}
	if err := h.AfterCreate(ctx, tx, "audit_events", &models.User{}); err != nil {
		t.Errorf("unmapped table: AfterCreate = %v", err)
	}
}

// The after-commit points are queued on the write's store by the after
// hooks and dispatched with RunAfter: no transaction is published, an update
// carries the row's id, and a failed after hook queues nothing.
func TestDataHooksDispatchCommittedPoints(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()
	// A store that is not bound to a transaction runs AfterCommit callbacks
	// at once, which stands in for the commit here.
	tx := store.New(nil)

	if err := h.AfterCreate(ctx, tx, "users", &models.User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := h.AfterUpdate(ctx, tx, "users", &models.User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	h.AfterCreate(ctx, tx, "audit_events", &models.User{})
	if len(d.committed) != 2 || len(d.after) != 2 {
		t.Fatalf("dispatched %d with RunAfter and %d with RunAfterTx, want 2 and 2", len(d.committed), len(d.after))
	}
	created, updated := d.committed[0], d.committed[1]
	if created.Point != hooks.HookUserCreated || updated.Point != hooks.HookUserUpdated {
		t.Errorf("points = %q, %q", created.Point, updated.Point)
	}
	if created.Tx != nil || updated.Tx != nil {
		t.Error("an after-commit point has no transaction to publish")
	}
	if updated.Values[hooks.HookValueUserID] != "u1" {
		t.Errorf("the updated point should carry the row's id: %v", updated.Values)
	}

	d.afterErr = errors.New("rejected by hook")
	h.AfterCreate(ctx, tx, "users", &models.User{ID: "u2"})
	if len(d.committed) != 2 {
		t.Error("a write whose after hook failed was reported as committed")
	}
}

// One write is one operation: Begin gives it a Values map that its before,
// after and after-commit points share. The map starts as a copy of the
// enclosing operation's, and what the write's handlers add stays out of it.
func TestDataHooksShareValuesAcrossOneWrite(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &core.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	tx := store.New(nil)

	flow := behemoth.M{"invite.id": "inv-1"}
	outer := core.ContextWithHookValues(context.Background(), flow)
	ctx := h.Begin(outer, "users")

	if _, err := h.BeforeCreate(ctx, tx, "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	d.before[0].Values["note"] = "from beforeCreate"
	if err := h.AfterCreate(ctx, tx, "users", &models.User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	for _, hctx := range []*core.HookContext{d.before[0], d.after[0], d.committed[0]} {
		if hctx.Values["invite.id"] != "inv-1" {
			t.Errorf("%s does not see the enclosing operation's values: %v", hctx.Point, hctx.Values)
		}
		if hctx.Values["note"] != "from beforeCreate" {
			t.Errorf("%s does not see the note left on the write's before point: %v", hctx.Point, hctx.Values)
		}
	}
	if _, leaked := flow["note"]; leaked {
		t.Error("the write's note leaked into the enclosing operation's values")
	}

	// A second write under the same flow starts from the flow's values again.
	second := h.Begin(outer, "users")
	if _, err := h.BeforeCreate(second, tx, "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	if _, inherited := d.before[1].Values["note"]; inherited || d.before[1].Values["invite.id"] != "inv-1" {
		t.Errorf("a second write should start from the flow's values only: %v", d.before[1].Values)
	}

	// A table without hook points opens no operation.
	if got := h.Begin(outer, "audit_events"); got != outer {
		t.Error("Begin changed the context of a table that fires no hooks")
	}
	// Outside any operation a write starts empty.
	if got := core.HookValuesFrom(h.Begin(context.Background(), "users")); got == nil || len(got) != 0 {
		t.Errorf("a write outside any operation should start with empty values: %v", got)
	}
}
