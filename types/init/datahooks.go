package types

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

// tableHookPoints are the data hook points fired around writes to one table.
// idValue is the HookContext.Values key an update's target id is published
// under (the payload carries only the changes).
type tableHookPoints struct {
	beforeCreate, afterCreate types.HookPoint
	beforeUpdate, afterUpdate types.HookPoint
	idValue                   string
}

// coreDataHookPoints maps core tables to the data hook points core declares
// for them (CoreDeclareHookPoints). A table without an entry fires no hooks.
//
// Only Tier 1 points belong here. The auth.session.* and token.* points are
// Tier 2: the session and token managers fire them around a whole operation
// (a revoke, a consume), outside any store transaction. Listing "sessions" or
// "tokens" here would fire those points a second time from the store, and
// would open a transaction around every session and token write.
//
// Boot checks each entry against the catalog (checkDataHookPoints), so an
// entry whose point is missing from CoreDeclareHookPoints fails Boot instead
// of the first write to the table.
var coreDataHookPoints = map[string]tableHookPoints{
	"users": {
		beforeCreate: hooks.HookUserBeforeCreate, afterCreate: hooks.HookUserAfterCreate,
		beforeUpdate: hooks.HookUserBeforeUpdate, afterUpdate: hooks.HookUserAfterUpdate,
		idValue: hooks.HookValueUserID,
	},
}

// checkDataHookPoints reports a configuration error when a point in points
// was never declared, or was declared with a phase other than the one the
// store fires it in.
func checkDataHookPoints(catalog types.HookCatalog, points map[string]tableHookPoints) error {
	for table, p := range points {
		for _, want := range []struct {
			point types.HookPoint
			phase types.HookPhase
		}{
			{p.beforeCreate, types.BeforeHookPhase}, {p.afterCreate, types.AfterHookPhase},
			{p.beforeUpdate, types.BeforeHookPhase}, {p.afterUpdate, types.AfterHookPhase},
		} {
			def, ok := catalog.Lookup(want.point)
			if !ok {
				return behemotherr.NewConfigurationError("Boot",
					fmt.Sprintf("data hook point %q of table %q was never declared", want.point, table), nil)
			}
			if def.Phase != want.phase {
				return behemotherr.NewConfigurationError("Boot",
					fmt.Sprintf("data hook point %q of table %q is declared as phase %q, the store fires it as %q", want.point, table, def.Phase, want.phase), nil)
			}
		}
	}
	return nil
}

// dataHooks implements store.Hooks on top of the hook Dispatcher: the store
// reports table writes, this turns them into hook points and HookContexts.
// It lives here, not in store, because store must not import types.
//
// Data hooks run inside the write's transaction. After hooks are dispatched
// with RunAfterTx, so a handler's error reaches the store and rolls the write
// back; Tier 2 after hooks use RunAfter and can't.
type dataHooks struct {
	ac     *types.AuthContext
	points map[string]tableHookPoints
}

var _ store.Hooks = dataHooks{}

func (h dataHooks) Fires(table string) bool {
	_, ok := h.points[table]
	return ok
}

func (h dataHooks) BeforeCreate(ctx context.Context, tx *store.Store, table string, row behemoth.M) (behemoth.M, error) {
	p, ok := h.points[table]
	if !ok {
		return row, nil
	}
	return h.ac.Dispatcher.RunBefore(h.hookContext(ctx, tx, p.beforeCreate, types.BeforeHookPhase), p.beforeCreate, row)
}

func (h dataHooks) AfterCreate(ctx context.Context, tx *store.Store, table string, created behemoth.Model) error {
	p, ok := h.points[table]
	if !ok {
		return nil
	}
	return h.ac.Dispatcher.RunAfterTx(h.hookContext(ctx, tx, p.afterCreate, types.AfterHookPhase), p.afterCreate, created)
}

func (h dataHooks) BeforeUpdate(ctx context.Context, tx *store.Store, table string, id any, changes behemoth.M) (behemoth.M, error) {
	p, ok := h.points[table]
	if !ok {
		return changes, nil
	}
	hctx := h.hookContext(ctx, tx, p.beforeUpdate, types.BeforeHookPhase)
	hctx.Values[p.idValue] = id
	return h.ac.Dispatcher.RunBefore(hctx, p.beforeUpdate, changes)
}

func (h dataHooks) AfterUpdate(ctx context.Context, tx *store.Store, table string, updated behemoth.Model) error {
	p, ok := h.points[table]
	if !ok {
		return nil
	}
	hctx := h.hookContext(ctx, tx, p.afterUpdate, types.AfterHookPhase)
	hctx.Values[p.idValue] = updated.PrimaryKeyField()
	return h.ac.Dispatcher.RunAfterTx(hctx, p.afterUpdate, updated)
}

// hookContext builds the context a data hook dispatches with. tx is the
// store bound to the write's transaction, published as HookContext.Tx. A
// write made while handling a request (the router put it on ctx) carries that
// request; one made outside any request (a CLI, a job) has none. Values are
// always fresh: they are scoped to one hook chain.
func (h dataHooks) hookContext(ctx context.Context, tx *store.Store, point types.HookPoint, phase types.HookPhase) *types.HookContext {
	return &types.HookContext{
		Ctx: ctx, Point: point, Phase: phase,
		Auth:    h.ac,
		Tx:      tx,
		Values:  behemoth.M{},
		Request: types.RequestFrom(ctx),
	}
}
