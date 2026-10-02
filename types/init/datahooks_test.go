package types

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

type recordingDispatcher struct {
	before, after []*types.HookContext
	rewrite       behemoth.M
}

func (d *recordingDispatcher) RunBefore(hctx *types.HookContext, point types.HookPoint, payload behemoth.M) (behemoth.M, error) {
	d.before = append(d.before, hctx)
	for k, v := range d.rewrite {
		payload[k] = v
	}
	return payload, nil
}
func (d *recordingDispatcher) RunAfter(hctx *types.HookContext, point types.HookPoint, result any) {
	d.after = append(d.after, hctx)
}
func (d *recordingDispatcher) Fail(*types.HookContext, types.HookPoint, types.FailureReason) {}

func TestDataHooksDispatchMappedTablesOnly(t *testing.T) {
	d := &recordingDispatcher{rewrite: behemoth.M{models.UserUsername: "from-hook"}}
	h := dataHooks{ac: &types.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()

	row, err := h.BeforeCreate(ctx, "users", behemoth.M{models.UserEmail: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if row[models.UserUsername] != "from-hook" {
		t.Errorf("BeforeCreate did not return the dispatcher's rewrite: %v", row)
	}
	h.AfterCreate(ctx, "users", &models.User{})
	if len(d.before) != 1 || d.before[0].Point != hooks.HookUserBeforeCreate || d.before[0].Phase != types.BeforeHookPhase {
		t.Fatalf("before dispatch = %+v", d.before)
	}
	if len(d.after) != 1 || d.after[0].Point != hooks.HookUserAfterCreate {
		t.Fatalf("after dispatch = %+v", d.after)
	}

	// A table without hook points: untouched, nothing dispatched.
	in := behemoth.M{"x": 1}
	out, err := h.BeforeCreate(ctx, "audit_events", in)
	if err != nil || out["x"] != 1 {
		t.Errorf("unmapped table: row %v, err %v", out, err)
	}
	h.AfterCreate(ctx, "audit_events", &models.User{})
	if len(d.before) != 1 || len(d.after) != 1 {
		t.Error("an unmapped table dispatched a hook")
	}
}

func TestDataHooksUpdatePublishesTheID(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &types.AuthContext{Dispatcher: d}, points: coreDataHookPoints}
	ctx := context.Background()

	if _, err := h.BeforeUpdate(ctx, "users", "u1", behemoth.M{models.UserFirstname: "Ada"}); err != nil {
		t.Fatal(err)
	}
	h.AfterUpdate(ctx, "users", &models.User{ID: "u1"})
	if len(d.before) != 1 || d.before[0].Point != hooks.HookUserBeforeUpdate || d.before[0].Values[hooks.HookValueUserID] != "u1" {
		t.Fatalf("before update dispatch = %+v", d.before)
	}
	if len(d.after) != 1 || d.after[0].Point != hooks.HookUserAfterUpdate || d.after[0].Values[hooks.HookValueUserID] != "u1" {
		t.Fatalf("after update dispatch = %+v", d.after)
	}

	out, err := h.BeforeUpdate(ctx, "audit_events", 1, behemoth.M{"x": 1})
	if err != nil || out["x"] != 1 || len(d.before) != 1 {
		t.Errorf("unmapped table: changes %v, err %v, dispatched %d", out, err, len(d.before))
	}
}

// A write made while handling a request dispatches with that request, and
// its own chain-scoped Values; one made outside a request has none.
func TestDataHooksCarryTheRequest(t *testing.T) {
	d := &recordingDispatcher{}
	h := dataHooks{ac: &types.AuthContext{Dispatcher: d}, points: coreDataHookPoints}

	rc := &types.RequestContext{Request: httptest.NewRequest("POST", "/sign-up", nil), Values: behemoth.M{"request-only": true}}
	ctx := types.ContextWithRequest(context.Background(), rc)
	if _, err := h.BeforeCreate(ctx, "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	got := d.before[0]
	if got.Request != rc {
		t.Error("the request was not carried into the data hook")
	}
	if _, leaked := got.Values["request-only"]; leaked {
		t.Error("request Values leaked into the data hook's chain")
	}
	if got.Auth == nil {
		t.Error("the data hook has no AuthContext")
	}

	if _, err := h.BeforeCreate(context.Background(), "users", behemoth.M{}); err != nil {
		t.Fatal(err)
	}
	if d.before[1].Request != nil {
		t.Error("a write outside any request must not have one")
	}
}
