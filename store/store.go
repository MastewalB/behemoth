// Package store is behemoth's data layer above the raw database adapters:
// typed operations on behemoth's own models, with ids, timestamps and data
// hooks handled in one place. Plugins read and write behemoth's tables
// through it (AuthContext.Store). For their own tables they use the adapter
// directly: AuthContext.DB, or Store.DB inside a transaction or a data hook.
//
// It must not import github.com/MastewalB/behemoth/types: types imports store
// (AuthContext holds a *Store). Anything store needs from above — today, the
// hook dispatcher — it declares as its own small interface (Hooks), and Boot
// supplies the implementation. Contracts that live below types
// (types/cryptotypes) it uses directly.
package store

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types/cryptotypes"
	"github.com/MastewalB/behemoth/utils"
)

// Hooks are the data-level (Tier 1) hooks the store fires around writes.
// Boot implements them on top of the hook Dispatcher; store only knows tables
// and rows, never hook points or hook contexts.
//
// A write to a table that fires hooks runs in one database transaction with
// its before and after hooks. Each method receives tx, the Store bound to that
// transaction: what a hook writes through tx commits or rolls back with the
// row. A hook's writes through any other Store, to a key-value storage or to
// an outside system are not undone by a rollback.
type Hooks interface {
	// Fires reports whether writes to table fire hooks. The store opens a
	// transaction around a write only when it does, so tables without hooks
	// (sessions, tokens, rate-limit counters) keep writing directly.
	Fires(table string) bool

	// BeforeCreate may inspect and rewrite the row about to be inserted into
	// table (canonical column names), or abort the write by returning an error.
	BeforeCreate(ctx context.Context, tx *Store, table string, row behemoth.M) (behemoth.M, error)
	// AfterCreate runs once the row is inserted, before the transaction
	// commits. The row can still be rolled back: by AfterCreate's own error,
	// which fails the create, or by a later write in a transaction the caller
	// opened.
	AfterCreate(ctx context.Context, tx *Store, table string, created behemoth.Model) error

	// BeforeUpdate may inspect and rewrite the changes (canonical column
	// names, only the columns being changed) about to be applied to the row
	// of table whose primary key is id, or abort the write. id is not part of
	// changes: a hook can't redirect an update to another row.
	BeforeUpdate(ctx context.Context, tx *Store, table string, id any, changes behemoth.M) (behemoth.M, error)
	// AfterUpdate runs once the update is applied, before the transaction
	// commits, with the stored row. Its error fails the update and rolls it
	// back.
	AfterUpdate(ctx context.Context, tx *Store, table string, updated behemoth.Model) error
}

// Store is the single implementation of behemoth's data layer.
type Store struct {
	db        behemoth.Database
	hooks     Hooks
	schema    behemoth.SchemaResolver // which columns each table has, contributions included
	encryptor cryptotypes.Encryptor   // seals at-rest secrets; see WithEncryptor
	newID     func() string
	now       func() time.Time
	inTx      bool // db is a transaction; see Transaction
}

// Option configures a Store.
type Option func(*Store)

// WithHooks fires h around writes. Without it, no data hooks run and no write
// opens a transaction of its own.
func WithHooks(h Hooks) Option { return func(s *Store) { s.hooks = h } }

// WithSchema tells the store which columns each table has — the resolver
// built from the frozen schema registry, so columns other declarers
// contributed (ExtendColumn) can be written and updated. Without it, only a
// model's own columns are accepted.
func WithSchema(r behemoth.SchemaResolver) Option { return func(s *Store) { s.schema = r } }

// WithClock replaces the timestamp source, for tests.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// WithIDs replaces the id generator, for tests.
func WithIDs(newID func() string) Option { return func(s *Store) { s.newID = newID } }

func New(db behemoth.Database, opts ...Option) *Store {
	s := &Store{
		db:     db,
		hooks:  noHooks{},
		schema: behemoth.IdentityResolver{},
		newID:  utils.GenerateUUID,
		now:    func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type noHooks struct{}

func (noHooks) Fires(string) bool { return false }
func (noHooks) BeforeCreate(_ context.Context, _ *Store, _ string, row behemoth.M) (behemoth.M, error) {
	return row, nil
}
func (noHooks) AfterCreate(context.Context, *Store, string, behemoth.Model) error { return nil }
func (noHooks) BeforeUpdate(_ context.Context, _ *Store, _ string, _ any, changes behemoth.M) (behemoth.M, error) {
	return changes, nil
}
func (noHooks) AfterUpdate(context.Context, *Store, string, behemoth.Model) error { return nil }

// DB returns the database adapter the Store writes through. On a Store bound
// to a transaction (the tx Transaction hands to fn, or HookContext.Tx in a
// data hook) it is the adapter bound to that transaction, so what a caller
// writes through it commits or rolls back with the Store's own writes.
//
// It exists for tables the Store has no operations for: a plugin's or the
// application's own. Writes to behemoth's tables (users, accounts, sessions,
// tokens) belong on the Store's methods; the adapter skips everything they
// add: data hooks, ids and timestamps, email normalization, the column
// check, and the sealing of account tokens.
//
// Use the adapter with the context that came with the Store (fn's ctx,
// HookContext.Ctx): on MongoDB the transaction travels in the context. Don't
// keep a transaction-bound adapter after fn or the hook returns.
func (s *Store) DB() behemoth.Database { return s.db }

// Transaction runs fn with a Store bound to one database transaction: every
// write fn makes through tx commits or rolls back together. fn's error rolls
// the transaction back and is returned as-is.
//
// Called on a Store that is already bound to a transaction, it runs fn in
// that same transaction: there are no nested transactions, and a helper that
// wants atomicity can call Transaction whether or not its caller already did.
//
// Data hooks fired by writes inside fn run inside the transaction too; see
// Hooks. There is no after-commit hook: work that should only happen once the
// transaction has committed belongs after Transaction returns.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context, tx *Store) error) error {
	if s.inTx {
		return fn(ctx, s)
	}
	return s.db.Transaction(ctx, func(ctx context.Context, db behemoth.Database) (any, error) {
		tx := *s
		tx.db, tx.inTx = db, true
		return nil, fn(ctx, &tx)
	})
}
