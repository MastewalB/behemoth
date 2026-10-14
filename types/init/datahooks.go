package types

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

// tableHookPoints are the data hook points fired around writes to one table.
// idValue is the HookContext.Values key an update's target id is published
// under (the payload carries only the changes).
//
// created, updated and deleted are the after-commit points: they fire once
// the transaction the write ran in has committed, not for a write that was
// rolled back.
type tableHookPoints struct {
	beforeCreate, afterCreate types.HookPoint
	beforeUpdate, afterUpdate types.HookPoint
	beforeDelete, afterDelete types.HookPoint
	created, updated, deleted types.HookPoint
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
		beforeDelete: hooks.HookUserBeforeDelete, afterDelete: hooks.HookUserAfterDelete,
		created: hooks.HookUserCreated, updated: hooks.HookUserUpdated, deleted: hooks.HookUserDeleted,
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
			{p.beforeDelete, types.BeforeHookPhase}, {p.afterDelete, types.AfterHookPhase},
			{p.created, types.AfterHookPhase}, {p.updated, types.AfterHookPhase}, {p.deleted, types.AfterHookPhase},
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
//
// The after-commit points (created, updated) are the exception. The store
// has no call for them: AfterCreate and AfterUpdate queue their dispatch on
// the transaction (Store.AfterCommit), so it runs once the outermost
// transaction has committed and never for a write that was rolled back. They
// are dispatched with RunAfter like a Tier 2 after hook: a handler's error
// is logged, an audit event is recorded if the point declares one, and
// HookContext.Tx is nil.
//
// One write is one operation: its before, after and after-commit points
// share one HookContext.Values (Begin).
type dataHooks struct {
	ac     *types.AuthContext
	points map[string]tableHookPoints
}

var _ store.Hooks = dataHooks{}

func (h dataHooks) Fires(table string) bool {
	_, ok := h.points[table]
	return ok
}

// Begin opens the operation of one write to table. Its Values start as a
// copy of the enclosing operation's (a sign-up's, when the flow passed its
// context to the store), or empty. On a retried transaction the store calls
// Begin again, so each attempt starts from the enclosing values.
func (h dataHooks) Begin(ctx context.Context, table string) context.Context {
	if _, ok := h.points[table]; !ok {
		return ctx
	}
	return types.BeginOperation(ctx)
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
	hctx := h.hookContext(ctx, tx, p.afterCreate, types.AfterHookPhase)
	if err := h.ac.Dispatcher.RunAfterTx(hctx, p.afterCreate, created); err != nil {
		return err
	}
	h.onCommit(ctx, tx, hctx.Values, p.created, created)
	return nil
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
	if err := h.ac.Dispatcher.RunAfterTx(hctx, p.afterUpdate, updated); err != nil {
		return err
	}
	h.onCommit(ctx, tx, hctx.Values, p.updated, updated)
	return nil
}

// BeforeDelete fires the table's beforeDelete point with the row as its
// payload. The returned payload is not read: a handler can stop the delete,
// but it can't change what is deleted.
func (h dataHooks) BeforeDelete(ctx context.Context, tx *store.Store, table string, row behemoth.Model) error {
	p, ok := h.points[table]
	if !ok {
		return nil
	}
	payload := behemoth.M{}
	if ser, ok := row.(behemoth.Serializable); ok {
		m, err := ser.ToMap()
		if err != nil {
			return err
		}
		payload = m
	}
	hctx := h.hookContext(ctx, tx, p.beforeDelete, types.BeforeHookPhase)
	hctx.Values[p.idValue] = row.PrimaryKeyField()
	_, err := h.ac.Dispatcher.RunBefore(hctx, p.beforeDelete, payload)
	return err
}

// AfterDelete fires the table's afterDelete point inside the transaction,
// then sees to the sessions that were deleted with the row, which the store
// can't: their cache entries and their hook point belong to the session
// manager.
//
// The cache entries are removed twice. Before the commit, so that a process
// that stops right after it leaves no cached session behind: a cached session
// is served without a read of the database, until it expires. After the
// commit again, because a request can put a session back in the cache between
// the first removal and the commit. That second pass is SessionManager.Discard,
// which also fires auth.session.afterRevoke for each session that was live.
// The table's deleted point fires last.
func (h dataHooks) AfterDelete(ctx context.Context, tx *store.Store, table string, deleted behemoth.Model, sessions []*models.Session) error {
	p, ok := h.points[table]
	if !ok {
		return nil
	}
	hctx := h.hookContext(ctx, tx, p.afterDelete, types.AfterHookPhase)
	hctx.Values[p.idValue] = deleted.PrimaryKeyField()
	if err := h.ac.Dispatcher.RunAfterTx(hctx, p.afterDelete, deleted); err != nil {
		return err
	}

	sm, values := h.ac.SessionManager, hctx.Values
	if sm != nil && len(sessions) > 0 {
		sm.Evict(ctx, sessions)
		tx.AfterCommit(ctx, func(ctx context.Context) {
			ctx = types.ContextWithHookValues(ctx, values)
			if err := sm.Discard(ctx, sessions, types.SessionRevokedUserDeleted); err != nil && h.ac.Telemetry != nil {
				telemetry.Named(h.ac.Telemetry.Logger, "hooks").Error(ctx, "sessions deleted with their user could not be reported",
					telemetry.ErrorFields(err, behemoth.M{telemetry.FieldPoint: string(hooks.HookSessionAfterRevoke)}))
			}
		})
	}
	h.onCommit(ctx, tx, values, p.deleted, deleted)
	return nil
}

// onCommit queues the dispatch of point, an after-commit point of the write
// ctx belongs to, on tx's transaction. The write can't be undone any more
// when it runs, so the only error RunAfter returns (the point can't be
// dispatched, which Boot's checkDataHookPoints rules out) is logged.
//
// The dispatch keeps values, the write's Values as its after hook left them,
// but runs with the callback's context: ctx is the transaction's, which has
// ended by then (on MongoDB it carries the closed session).
func (h dataHooks) onCommit(ctx context.Context, tx *store.Store, values behemoth.M, point types.HookPoint, row behemoth.Model) {
	tx.AfterCommit(ctx, func(ctx context.Context) {
		hctx := h.hookContext(types.ContextWithHookValues(ctx, values), nil, point, types.AfterHookPhase)
		if err := h.ac.Dispatcher.RunAfter(hctx, point, row); err != nil && h.ac.Telemetry != nil {
			telemetry.Named(h.ac.Telemetry.Logger, "hooks").Error(hctx.Ctx, "after-commit data hook could not be dispatched",
				telemetry.ErrorFields(err, behemoth.M{telemetry.FieldPoint: string(point)}))
		}
	})
}

// hookContext builds the context a data hook dispatches with. tx is the
// store bound to the write's transaction, published as HookContext.Tx; it is
// nil for the after-commit points. A write made while handling a request
// (the router put it on ctx) carries that request; one made outside any
// request (a CLI, a job) has none. Values are the write's (Begin), shared by
// all of its points.
func (h dataHooks) hookContext(ctx context.Context, tx *store.Store, point types.HookPoint, phase types.HookPhase) *types.HookContext {
	values := types.HookValuesFrom(ctx)
	if values == nil {
		// Begin was not called: a caller other than the store.
		values = behemoth.M{}
	}
	return &types.HookContext{
		Ctx: ctx, Point: point, Phase: phase,
		Auth:    h.ac,
		Tx:      tx,
		Values:  values,
		Request: types.RequestFrom(ctx),
	}
}
