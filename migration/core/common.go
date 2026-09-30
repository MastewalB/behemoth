package core

import (
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

// snapshotAsRegistry adapts a persisted SchemaSnapshot into the
// SchemaRegistry interface FromSnapshotDiff expects as "previous" — a
// read-only, pre-populated registry; Declare/ExtendColumn are unreachable
// here since this is never a live registration surface, only a value
// carrier for a diff.
type snapshotRegistry struct {
	tables map[string]TableSchema
}

// LookupModel implements [SchemaRegistry].
func (r *snapshotRegistry) LookupModel(name string) (behemoth.Model, bool) {
	return nil, false
}

// Freeze implements [SchemaRegistry].
func (r *snapshotRegistry) Freeze() error {
	return behemotherr.NewInternalError("snapshotRegistry.Freeze", fmt.Errorf("read-only registry"))
}

func snapshotAsRegistry(s SchemaSnapshot) SchemaRegistry {
	return &snapshotRegistry{tables: s.Tables}
}

func (r *snapshotRegistry) Declare(behemoth.Model, TableSchema) error {
	return behemotherr.NewInternalError("snapshotRegistry.Declare", fmt.Errorf("read-only registry: snapshots are never declared into"))
}
func (r *snapshotRegistry) ExtendColumn(ColumnContribution) error {
	return behemotherr.NewInternalError("snapshotRegistry.ExtendColumn", fmt.Errorf("read-only registry")) // TODO - Classify read-only as const error type?
}
func (r *snapshotRegistry) ExtendIndex(IndexContribution) error {
	return behemotherr.NewInternalError("snapshotRegistry.ExtendIndex", fmt.Errorf("read-only registry"))
}
func (r *snapshotRegistry) ExtendForeignKey(ForeignKeyContribution) error {
	return behemotherr.NewInternalError("snapshotRegistry.ExtendForeignKey", fmt.Errorf("read-only registry"))
}
func (r *snapshotRegistry) Lookup(name string) (TableSchema, bool) {
	t, ok := r.tables[name]
	return t, ok
}
func (r *snapshotRegistry) All() []TableSchema {
	out := make([]TableSchema, 0, len(r.tables))
	for _, t := range r.tables {
		out = append(out, t)
	}
	return out
}
