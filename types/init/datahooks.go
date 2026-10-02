package types

import (
	"context"

	"github.com/MastewalB/behemoth"
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
var coreDataHookPoints = map[string]tableHookPoints{
	"users": {
		beforeCreate: hooks.HookUserBeforeCreate, afterCreate: hooks.HookUserAfterCreate,
		beforeUpdate: hooks.HookUserBeforeUpdate, afterUpdate: hooks.HookUserAfterUpdate,
		idValue: hooks.HookValueUserID,
	},
}

// dataHooks implements store.Hooks on top of the hook Dispatcher: the store
// reports table writes, this turns them into hook points and HookContexts.
// It lives here, not in store, because store must not import types.
type dataHooks struct {
	ac     *types.AuthContext
	points map[string]tableHookPoints
}

var _ store.Hooks = dataHooks{}

func (h dataHooks) BeforeCreate(ctx context.Context, table string, row behemoth.M) (behemoth.M, error) {
	p, ok := h.points[table]
	if !ok {
		return row, nil
	}
	return h.ac.Dispatcher.RunBefore(h.hookContext(ctx, p.beforeCreate, types.BeforeHookPhase), p.beforeCreate, row)
}

func (h dataHooks) AfterCreate(ctx context.Context, table string, created behemoth.Model) {
	if p, ok := h.points[table]; ok {
		h.ac.Dispatcher.RunAfter(h.hookContext(ctx, p.afterCreate, types.AfterHookPhase), p.afterCreate, created)
	}
}

func (h dataHooks) BeforeUpdate(ctx context.Context, table string, id any, changes behemoth.M) (behemoth.M, error) {
	p, ok := h.points[table]
	if !ok {
		return changes, nil
	}
	hctx := h.hookContext(ctx, p.beforeUpdate, types.BeforeHookPhase)
	hctx.Values[p.idValue] = id
	return h.ac.Dispatcher.RunBefore(hctx, p.beforeUpdate, changes)
}

func (h dataHooks) AfterUpdate(ctx context.Context, table string, updated behemoth.Model) {
	if p, ok := h.points[table]; ok {
		hctx := h.hookContext(ctx, p.afterUpdate, types.AfterHookPhase)
		hctx.Values[p.idValue] = updated.PrimaryKeyField()
		h.ac.Dispatcher.RunAfter(hctx, p.afterUpdate, updated)
	}
}

// hookContext builds the context a data hook dispatches with. A write made
// while handling a request (the router put it on ctx) carries that request;
// one made outside any request (a CLI, a job) has none. Values are always
// fresh: they are scoped to one hook chain.
func (h dataHooks) hookContext(ctx context.Context, point types.HookPoint, phase types.HookPhase) *types.HookContext {
	return &types.HookContext{
		Ctx: ctx, Point: point, Phase: phase,
		Auth:    h.ac,
		Values:  behemoth.M{},
		Request: types.RequestFrom(ctx),
	}
}
