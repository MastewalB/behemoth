package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/schema"
)

type DefaultMigrationRunner struct {
	db     behemoth.Database
	driver SchemaDriver
	cfg    MigrationConfig
	tel    *types.Telemetry
}

func NewMigrationRunner(db behemoth.Database, driver SchemaDriver, cfg MigrationConfig, tel *types.Telemetry) *DefaultMigrationRunner {
	return &DefaultMigrationRunner{db: db, driver: driver, cfg: cfg, tel: tel}
}

// Apply implements [MigrationRunner].
func (r *DefaultMigrationRunner) Apply(ctx context.Context, migrations []Migration) error {
	if r.driver.AtomicityLevel() != AtomicityFull {
		r.tel.Logger.Warn(ctx, "driver atomicity level is not 'full'; a failure mid-migration may leave schema, ledger, or snapshot out of sync",
			behemoth.M{"level": string(r.driver.AtomicityLevel())})
	}

	currentSnapshot, err := r.LoadSnapshot(ctx)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if err := r.applyOne(ctx, m, &currentSnapshot); err != nil {
			return behemotherr.WrapOp("MigrationRunner.Apply", "migration:"+m.ID, err)
		}
	}
	return nil

}

func (r *DefaultMigrationRunner) applyOne(ctx context.Context, m Migration, snapshot *SchemaSnapshot) error {
	nextTables, err := applyOperationsToSnapshot(snapshot.Tables, m.Up)
	if err != nil {
		return behemotherr.NewMigrationError("MigrationRunner.applyOne", behemotherr.ErrorCodeMigrationSnapshotProjectionFailed, err)
	}

	req := MigrationRequest{
		Migration:      m,
		LedgerEntry:    MigrationLedgerEntry{ID: m.ID, AppliedAt: time.Now()},
		SnapshotUpdate: SchemaSnapshot{Version: m.ID, Tables: nextTables},
		LedgerTable:    r.cfg.TableName,
		SnapshotTable:  r.cfg.snapshotTableName(),
	}

	var applyErr error
	if m.IsBaseline {
		applyErr = r.driver.RecordBaseline(ctx, req)
	} else {
		applyErr = r.driver.ApplyMigration(ctx, req)
	}
	if applyErr != nil {
		return behemotherr.NewMigrationError("MigrationRunner.applyOne", behemotherr.ErrorCodeMigrationApplyFailed, applyErr)
	}

	snapshot.Version, snapshot.Tables = m.ID, nextTables
	r.tel.Audit.Record(ctx, types.AuditEvent{Type: "migration.applied", SubjectID: m.ID, Metadata: behemoth.M{"baseline": m.IsBaseline}, Timestamp: time.Now()})
	return nil
}

func applyOperationsToSnapshot(tables map[string]schema.Table, ops []SchemaOperation) (map[string]schema.Table, error) {
	next := deepCopyTables(tables) // never mutate the caller's map in place — a failure partway through must not corrupt what's still the last-good snapshot
	for _, op := range ops {
		if err := applyOneToSnapshot(next, op); err != nil {
			return nil, err
		}
	}
	return next, nil
}

func applyOneToSnapshot(tables map[string]schema.Table, op SchemaOperation) error {
	switch op.Kind {
	case OpCreateTable:
		if op.NewTable == nil {
			return fmt.Errorf("operation %q: OpCreateTable missing NewTable", op.ID)
		}
		tables[op.Table] = *op.NewTable
	case OpDropTable:
		delete(tables, op.Table)
	case OpAddColumn:
		t := tables[op.Table]
		t.Columns = append(t.Columns, *op.Column)
		tables[op.Table] = t
	case OpDropColumn:
		t := tables[op.Table]
		t.Columns = removeColumn(t.Columns, op.ColumnName)
		tables[op.Table] = t
	case OpRenameColumn:
		t := tables[op.Table]
		for i, c := range t.Columns {
			if c.Name == op.ColumnName {
				t.Columns[i].Name = op.NewColumnName
			}
		}
		tables[op.Table] = t
	case OpAlterColumn:
		t := tables[op.Table]
		for i, c := range t.Columns {
			if c.Name == op.Column.Name {
				t.Columns[i] = *op.Column
			}
		}
		tables[op.Table] = t

	case OpAddIndex:
		t := tables[op.Table]
		t.Indexes = append(t.Indexes, *op.Index)
		tables[op.Table] = t
	case OpDropIndex:
		t := tables[op.Table]
		t.Indexes = removeIndex(t.Indexes, op.IndexName)
		tables[op.Table] = t

	case OpAddForeignKey:
		t := tables[op.Table]
		t.ForeignKeys = append(t.ForeignKeys, *op.ForeignKey)
		tables[op.Table] = t
	case OpDropForeignKey:
		t := tables[op.Table]
		t.ForeignKeys = removeFK(t.ForeignKeys, op.ForeignKeyName)
		tables[op.Table] = t

	default:
		return fmt.Errorf("operation %q: unknown kind %q", op.ID, op.Kind)
	}
	return nil
}

// Pending implements [MigrationRunner].
func (r *DefaultMigrationRunner) Pending(ctx context.Context, onDisk []Migration) ([]Migration, error) {
	applied, err := r.loadLedger(ctx)
	if err != nil {
		return nil, err
	}
	appliedSet := make(map[string]bool, len(applied))
	for _, e := range applied {
		appliedSet[e.ID] = true
	}

	byID := make(map[string]Migration, len(onDisk))
	graphMap := make(map[string][]string, len(onDisk))
	var pendingIDs []string
	for _, m := range onDisk {
		if appliedSet[m.ID] {
			continue // already run
		}
		byID[m.ID] = m
		graphMap[m.ID] = nil
		pendingIDs = append(pendingIDs, m.ID)
	}

	// Edges from each pending migration's DependsOn list
	for _, m := range onDisk {
		if !appliedSet[m.ID] {
			for _, dep := range m.DependsOn {
				// A dependency that's not yet applied
				if _, stillPending := byID[dep]; stillPending {
					graphMap[dep] = append(graphMap[dep], m.ID)
				}
			}
		}
	}

	alphabetical := func(a, b string) bool { return a < b } // alphabetical is chronological here since migration IDs are timestamp/sequence-prefixed
	sortedIDs, cyclePath, ok := types.KahnSort(graphMap, alphabetical)
	if !ok {
		return nil, behemotherr.NewMigrationError("MigrationRunner.Pending", behemotherr.ErrorCodeMigrationDependencyCycle,
			fmt.Errorf("circular migration dependency: %s", strings.Join(cyclePath, " -> ")))
	}

	result := make([]Migration, len(sortedIDs))
	for i, id := range sortedIDs {
		result[i] = byID[id]
	}
	return result, nil
}

func (r *DefaultMigrationRunner) loadLedger(ctx context.Context) ([]MigrationLedgerEntry, error) {
	found, err := r.db.FindMany(ctx, &MigrationLedgerEntry{}, clause.Expression{}, nil)
	if behemotherr.IsUndefinedTable(err) {
		// The driver creates the ledger with the first migration it records:
		// no table means nothing applied yet — the same reading
		// DetermineRunState gives a missing ledger table.
		return nil, nil
	}
	if err != nil {
		return nil, behemotherr.WrapOp("MigrationRunner.loadLedger", "migration_ledger", err)
	}
	out := make([]MigrationLedgerEntry, len(found))
	for i, f := range found {
		out[i] = *f.(*MigrationLedgerEntry)
	}
	return out, nil
}

func (r *DefaultMigrationRunner) LoadSnapshot(ctx context.Context) (SchemaSnapshot, error) {
	m := &SchemaSnapshot{}
	found, err := r.db.FindOne(ctx, m, byPrimaryKey(m))
	if err != nil {
		// No snapshot row, or no snapshot table at all (the driver creates it
		// with the first migration it records): nothing applied yet.
		if behemotherr.IsNotFound(err) || behemotherr.IsUndefinedTable(err) {
			return SchemaSnapshot{Tables: map[string]schema.Table{}}, nil
		}
		return SchemaSnapshot{}, behemotherr.WrapOp("MigrationRunner.LoadSnapshot", "schema_snapshot", err)
	}
	return *found.(*SchemaSnapshot), nil
}

// byPrimaryKey selects the one row of m's table whose primary key is
// m.PrimaryKeyField() — for the snapshot, its singleton row.
func byPrimaryKey(m behemoth.Model) clause.Expression {
	return clause.Expression{
		Logic:      clause.OpAnd,
		Conditions: []clause.Condition{{Field: m.PrimaryKeyName(), Operator: clause.OpEqual, Value: m.PrimaryKeyField()}},
	}
}

func removeFn[T any](l []T, fn func(T) bool) []T {
	for i, other := range l {
		if fn(other) {
			return append(l[:i], l[i+1:]...)
		}
	}
	return l
}

func removeIndex(l []schema.Index, indexName string) []schema.Index {
	return removeFn(l, func(i schema.Index) bool {
		return i.Name == indexName
	})
}

func removeFK(l []schema.ForeignKey, fkName string) []schema.ForeignKey {
	return removeFn(l, func(fk schema.ForeignKey) bool {
		return fk.Name == fkName
	})
}

func removeColumn(l []schema.Column, colName string) []schema.Column {
	return removeFn(l, func(fk schema.Column) bool {
		return fk.Name == colName
	})
}

func deepCopyTables(tables map[string]schema.Table) map[string]schema.Table {
	copy := make(map[string]schema.Table)

	for k, v := range tables {
		copy[k] = schema.Table{
			Name:         v.Name,
			PhysicalName: v.PhysicalName,
			Columns:      append([]schema.Column(nil), v.Columns...),
			Indexes:      append([]schema.Index(nil), v.Indexes...),
			ForeignKeys:  append([]schema.ForeignKey(nil), v.ForeignKeys...),
			Owner:        v.Owner,
		}
	}

	return copy
}

var _ MigrationRunner = (*DefaultMigrationRunner)(nil)
