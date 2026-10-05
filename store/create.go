package store

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

// create runs BeforeCreate on m's row, inserts the (possibly rewritten) row
// and runs AfterCreate. Hooks see and return canonical rows (behemoth.M), so
// m must be Serializable; the hook's rewrite is read back into m before the
// insert, and m holds exactly what was stored afterwards.
//
// The three steps share one transaction (see hooked): an error from either
// hook or from the insert leaves nothing written. m is not restored on
// failure, so it may hold an id and a hook's rewrite for a row that doesn't
// exist.
func (s *Store) create(ctx context.Context, m behemoth.Model) error {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}
	return s.hooked(ctx, m.SchemaName(), func(ctx context.Context, tx *Store) error {
		row, err := ser.ToMap()
		if err != nil {
			return err
		}
		row, err = tx.hooks.BeforeCreate(ctx, tx, m.SchemaName(), row)
		if err != nil {
			return err // the hook's error is the abort; returned as-is
		}
		// FromMap ignores keys the model doesn't have; a hook setting one would
		// otherwise believe it was stored.
		if err := tx.checkColumns(m, row, "Store.Create"); err != nil {
			return err
		}
		if err := ser.FromMap(row); err != nil {
			return behemotherr.NewValidationError("Store.Create", m.SchemaName(), fmt.Errorf("row rewritten by a before-create hook: %w", err))
		}
		if err := tx.db.Create(ctx, m); err != nil {
			return err
		}
		// The hook's error rolls the insert back; returned as-is.
		if err := tx.hooks.AfterCreate(ctx, tx, m.SchemaName(), m); err != nil {
			return err
		}
		tx.committed(ctx, m.SchemaName(), func(ctx context.Context) { tx.hooks.CreateCommitted(ctx, m.SchemaName(), m) })
		return nil
	})
}

// update runs BeforeUpdate on changes, applies the (possibly rewritten)
// changes to the row of m's table whose primary key is id, stamps updated_at
// when stamp names that column, reads the row back into a fresh model and
// runs AfterUpdate. prepare, if set, normalizes the final changes (after
// hooks, so a hook's values are normalized too).
//
// Like create, the steps share one transaction: an error from either hook
// leaves the row unchanged.
func (s *Store) update(ctx context.Context, m behemoth.Model, id any, changes behemoth.M, stamp string, prepare func(behemoth.M)) (behemoth.Model, error) {
	const op = "Store.Update"
	if err := s.checkUpdate(m, changes, op); err != nil {
		return nil, err
	}
	var updated behemoth.Model
	err := s.hooked(ctx, m.SchemaName(), func(ctx context.Context, tx *Store) error {
		changes, err := tx.hooks.BeforeUpdate(ctx, tx, m.SchemaName(), id, copyRow(changes))
		if err != nil {
			return err // the hook's error is the abort; returned as-is
		}
		if err := tx.checkUpdate(m, changes, op); err != nil {
			return err
		}
		if prepare != nil {
			prepare(changes)
		}
		if stamp != "" {
			changes[stamp] = tx.now()
		}

		byKey := eq(m.PrimaryKeyName(), id)
		if err := tx.db.UpdateOne(ctx, m, byKey, changes); err != nil {
			return err
		}
		updated, err = tx.db.FindOne(ctx, m, byKey)
		if err != nil {
			return err
		}
		// The hook's error rolls the update back; returned as-is.
		if err := tx.hooks.AfterUpdate(ctx, tx, m.SchemaName(), updated); err != nil {
			return err
		}
		row := updated
		tx.committed(ctx, m.SchemaName(), func(ctx context.Context) { tx.hooks.UpdateCommitted(ctx, m.SchemaName(), row) })
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// hooked runs write, a write to table together with its data hooks. When the
// table fires hooks, write runs in a transaction (the one s is already bound
// to, or a new one), so the hooks' own writes through tx and the row commit
// or roll back together. A table without hooks writes directly through s:
// opening a transaction there would cost a round trip for nothing, and some
// callers must stay outside one (the rate limiter's counter store).
//
// The database may run write more than once: MongoDB retries a transaction on
// a transient error. Hooks that only write through tx are unaffected.
func (s *Store) hooked(ctx context.Context, table string, write func(ctx context.Context, tx *Store) error) error {
	if !s.hooks.Fires(table) {
		return write(ctx, s)
	}
	return s.Transaction(ctx, write)
}

// committed queues notify, a table's committed notification, to run once the
// write's transaction has committed. A table without hooks has nobody to
// notify and may be written outside any transaction, so nothing is queued.
func (s *Store) committed(ctx context.Context, table string, notify func(ctx context.Context)) {
	if s.hooks.Fires(table) {
		s.AfterCommit(ctx, notify)
	}
}

// checkUpdate rejects changes that touch the primary key or name a column m's
// table doesn't have.
func (s *Store) checkUpdate(m behemoth.Model, changes behemoth.M, op string) error {
	if _, ok := changes[m.PrimaryKeyName()]; ok {
		return behemotherr.NewValidationError(op, m.SchemaName(), fmt.Errorf("primary key %q can't be updated", m.PrimaryKeyName()))
	}
	return s.checkColumns(m, changes, op)
}

// checkColumns rejects keys that aren't columns of m's table — m's own (as
// its ToMap reports them) or contributed (as the schema lists them): a typo
// in an update map, or a key a hook made up, is an error rather than a
// silently ignored write.
func (s *Store) checkColumns(m behemoth.Model, row behemoth.M, op string) error {
	ser, ok := m.New().(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}
	columns, err := ser.ToMap()
	if err != nil {
		return err
	}
	for _, c := range s.schema.Columns(m.SchemaName()) {
		columns[c] = nil
	}
	for k := range row {
		if _, ok := columns[k]; !ok {
			return behemotherr.NewValidationError(op, m.SchemaName(), fmt.Errorf("unknown column %q", k))
		}
	}
	return nil
}

func copyRow(row behemoth.M) behemoth.M {
	out := make(behemoth.M, len(row))
	for k, v := range row {
		out[k] = v
	}
	return out
}
