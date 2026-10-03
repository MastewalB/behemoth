// Package store is behemoth's data layer above the raw database adapters:
// typed operations on behemoth's models, with ids, timestamps and data hooks
// handled in one place. Plugins reach the database through it
// (AuthContext.Store), never through a raw behemoth.Database.
//
// It must not import github.com/MastewalB/behemoth/types: types imports store
// (AuthContext holds a *Store). Anything store needs from above — today, the
// hook dispatcher — it declares as its own small interface (Hooks), and Boot
// supplies the implementation.
package store

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
)

// Hooks are the data-level (Tier 1) hooks the store fires around writes.
// Boot implements them on top of the hook Dispatcher; store only knows tables
// and rows, never hook points or hook contexts.
type Hooks interface {
	// BeforeCreate may inspect and rewrite the row about to be inserted into
	// table (canonical column names), or abort the write by returning an error.
	BeforeCreate(ctx context.Context, table string, row behemoth.M) (behemoth.M, error)
	// AfterCreate runs once the row is committed. It can't fail the write.
	AfterCreate(ctx context.Context, table string, created behemoth.Model)

	// BeforeUpdate may inspect and rewrite the changes (canonical column
	// names, only the columns being changed) about to be applied to the row
	// of table whose primary key is id, or abort the write. id is not part of
	// changes: a hook can't redirect an update to another row.
	BeforeUpdate(ctx context.Context, table string, id any, changes behemoth.M) (behemoth.M, error)
	// AfterUpdate runs once the update is committed, with the stored row.
	AfterUpdate(ctx context.Context, table string, updated behemoth.Model)
}

// Store is the single implementation of behemoth's data layer.
type Store struct {
	db     behemoth.Database
	hooks  Hooks
	schema behemoth.SchemaResolver // which columns each table has, contributions included
	newID  func() string
	now    func() time.Time
	inTx   bool // db is a transaction; see Transaction
}

// Option configures a Store.
type Option func(*Store)

// WithHooks fires h around writes. Without it, no data hooks run.
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

func (noHooks) BeforeCreate(_ context.Context, _ string, row behemoth.M) (behemoth.M, error) {
	return row, nil
}
func (noHooks) AfterCreate(context.Context, string, behemoth.Model) {}
func (noHooks) BeforeUpdate(_ context.Context, _ string, _ any, changes behemoth.M) (behemoth.M, error) {
	return changes, nil
}
func (noHooks) AfterUpdate(context.Context, string, behemoth.Model) {}

// Transaction runs fn with a Store bound to one database transaction: every
// write fn makes through tx commits or rolls back together. fn's error rolls
// the transaction back and is returned as-is.
//
// Called on a Store that is already bound to a transaction, it runs fn in
// that same transaction: there are no nested transactions, and a helper that
// wants atomicity can call Transaction whether or not its caller already did.
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
