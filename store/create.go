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
func (s *Store) create(ctx context.Context, m behemoth.Model) error {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}
	row, err := ser.ToMap()
	if err != nil {
		return err
	}
	row, err = s.hooks.BeforeCreate(ctx, m.SchemaName(), row)
	if err != nil {
		return err // the hook's error is the abort; returned as-is
	}
	// FromMap ignores keys the model doesn't have; a hook setting one would
	// otherwise believe it was stored.
	if err := s.checkColumns(m, row, "Store.Create"); err != nil {
		return err
	}
	if err := ser.FromMap(row); err != nil {
		return behemotherr.NewValidationError("Store.Create", m.SchemaName(), fmt.Errorf("row rewritten by a before-create hook: %w", err))
	}
	if err := s.db.Create(ctx, m); err != nil {
		return err
	}
	s.hooks.AfterCreate(ctx, m.SchemaName(), m)
	return nil
}

// update runs BeforeUpdate on changes, applies the (possibly rewritten)
// changes to the row of m's table whose primary key is id, stamps updated_at
// when stamp names that column, reads the row back into a fresh model and
// runs AfterUpdate. prepare, if set, normalizes the final changes (after
// hooks, so a hook's values are normalized too).
func (s *Store) update(ctx context.Context, m behemoth.Model, id any, changes behemoth.M, stamp string, prepare func(behemoth.M)) (behemoth.Model, error) {
	const op = "Store.Update"
	if err := s.checkUpdate(m, changes, op); err != nil {
		return nil, err
	}
	changes, err := s.hooks.BeforeUpdate(ctx, m.SchemaName(), id, copyRow(changes))
	if err != nil {
		return nil, err // the hook's error is the abort; returned as-is
	}
	if err := s.checkUpdate(m, changes, op); err != nil {
		return nil, err
	}
	if prepare != nil {
		prepare(changes)
	}
	if stamp != "" {
		changes[stamp] = s.now()
	}

	byKey := eq(m.PrimaryKeyName(), id)
	if err := s.db.UpdateOne(ctx, m, byKey, changes); err != nil {
		return nil, err
	}
	updated, err := s.db.FindOne(ctx, m, byKey)
	if err != nil {
		return nil, err
	}
	s.hooks.AfterUpdate(ctx, m.SchemaName(), updated)
	return updated, nil
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
