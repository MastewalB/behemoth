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
		return behemotherr.NewMigrationError("MigrationRunner.applyOne", "snapshot_projection_failed", err)
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
		return behemotherr.NewMigrationError("MigrationRunner.applyOne", "apply_failed", applyErr)
	}

	snapshot.Version, snapshot.Tables = m.ID, nextTables
	r.tel.Audit.Record(ctx, types.AuditEvent{Type: "migration.applied", SubjectID: m.ID, Metadata: behemoth.M{"baseline": m.IsBaseline}, Timestamp: time.Now()})
	return nil
}

func applyOperationsToSnapshot(tables map[string]TableSchema, ops []SchemaOperation) (map[string]TableSchema, error) {
	next := deepCopyTables(tables) // never mutate the caller's map in place — a failure partway through must not corrupt what's still the last-good snapshot
	for _, op := range ops {
		if err := applyOneToSnapshot(next, op); err != nil {
			return nil, err
		}
	}
	return next, nil
}

func applyOneToSnapshot(tables map[string]TableSchema, op SchemaOperation) error {
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
		return nil, behemotherr.NewMigrationError("MigrationRunner.Pending", "dependency_cycle",
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
		if behemotherr.IsNotFound(err) {
			return SchemaSnapshot{Tables: map[string]TableSchema{}}, nil // no snapshot yet — greenfield
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

func removeIndex(l []Index, indexName string) []Index {
	return removeFn(l, func(i Index) bool {
		return i.Name == indexName
	})
}

func removeFK(l []ForeignKey, fkName string) []ForeignKey {
	return removeFn(l, func(fk ForeignKey) bool {
		return fk.Name == fkName
	})
}

func removeColumn(l []Column, colName string) []Column {
	return removeFn(l, func(fk Column) bool {
		return fk.Name == colName
	})
}

func deepCopyTables(tables map[string]TableSchema) map[string]TableSchema {
	copy := make(map[string]TableSchema)

	for k, v := range tables {
		copy[k] = TableSchema{
			Name:         v.Name,
			PhysicalName: v.PhysicalName,
			Columns:      append([]Column(nil), v.Columns...),
			Indexes:      append([]Index(nil), v.Indexes...),
			ForeignKeys:  append([]ForeignKey(nil), v.ForeignKeys...),
			Owner:        v.Owner,
		}
	}

	return copy
}

var _ MigrationRunner = (*DefaultMigrationRunner)(nil)

// func BuildBaselineIssues(report *IntrospectionReport) (map[string]TableSchema, []BaselineIssue, error) {
// 	autoResolved := map[string]TableSchema{}
// 	var issues []BaselineIssue

// 	for table, ti := range report.Tables {
// 		if !ti.ExistsLive {
// 			continue //
// 		}

// 		if ti.IncompatibleObject {
// 			return nil, nil, behemotherr.NewMigrationError("Baseline.BuildIssues", "incompatible_object",
// 				fmt.Errorf("table %q exists live as a non-table object; resolve manually before baselining", table))
// 		}

// 		var cols []Column
// 		for _, f := range ti.Columns {
// 			if f.Live == nil {
// 				continue // ColMissingLive at baseline time simply isn't part of the live shape being recorded
// 			}

// 			if f.TypeAmbiguity == nil {
// 				cols = append(cols, *f.Live)
// 				continue
// 			}

// 			live := *f.Live
// 			issues = append(issues, BaselineIssue{
// 				ID:          "baseline_type_" + table + "_" + f.Name,
// 				Table:       table,
// 				Description: fmt.Sprintf("Column %q: %s", f.Name, f.TypeAmbiguity.Reason),
// 				Options: []BaselineFieldOption{
// 					{Label: "Accept guessed type (" + fmt.Sprint(live.Type) + ")", Column: &live},
// 					// [Deferred] "Override with a specified type" needs a
// 					// free-text field the current option-index draft format
// 					// can't carry — same deferred note as the ordinary
// 					// type-ambiguity issue in planColumns. Intent: add once
// 					// the draft format supports free-text entries.
// 				},
// 				Default: 0,
// 			})
// 			cols = append(cols, live) // provisional; ResolveBaselineIssues overwrites with the chosen option below
// 		}
// 		autoResolved[table] = TableSchema{
// 			Name:        table,
// 			Columns:     cols,
// 			Indexes:     liveIndexesOf(ti),
// 			ForeignKeys: liveForeignKeysOf(ti),
// 		}
// 	}

// 	return autoResolved, issues, nil
// }

// ResolveBaselineIssues is the direct structural counterpart to
// ResolveIssues — same Present/Collect/fail-closed shape, over
// BaselineIssue instead of PlanIssue.
// func ResolveBaselineIssues(
// 	ctx context.Context,
// 	provisional map[string]TableSchema,
// 	issues []BaselineIssue,
// 	presenter ResolutionPresenter,
// 	interactive bool,
// ) (*ResolvedBaseline, error) {

// 	planIssues := make([]PlanIssue, len(issues)) // adapted only for reuse of the existing Presenter wire format — see note below
// 	for i, bi := range issues {
// 		var opts []ResolutionOption
// 		for _, o := range bi.Options {
// 			opts = append(opts, ResolutionOption{Label: o.Label}) // Operations intentionally left nil. Presenter only serializes labels, per draftEntry's shape from the FilePresenter round
// 		}
// 		planIssues[i] = PlanIssue{
// 			ID:          bi.ID,
// 			Table:       bi.Table,
// 			Description: bi.Description,
// 			Options:     opts,
// 			Default:     bi.Default,
// 		}
// 	}

// 	prior, _ := presenter.Collect(ctx)
// 	if err := presenter.Present(ctx, planIssues, prior); err != nil {
// 		return nil, err
// 	}
// 	if interactive {
// 		// same pause-for-editor contract as ResolveIssues — CLI-layer concern
// 	}
// 	decisions, err := presenter.Collect(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	result := &ResolvedBaseline{Tables: map[string]TableSchema{}}
// 	// tables with zero issues pass through untouched
// 	maps.Copy(result.Tables, provisional)

// 	byID := map[string]BaselineIssue{}
// 	for _, i := range issues {
// 		byID[i.ID] = i
// 	}

// 	var unresolved []string
// 	for _, i := range issues {
// 		idx, ok := decisions[i.ID]
// 		if !ok {
// 			unresolved = append(unresolved, i.ID)
// 			continue
// 		}
// 		chosen := i.Options[idx]
// 		t := result.Tables[i.Table]
// 		replaceColumn(&t, chosen.Column) // overwrites the provisional entry with the developer's actual choice
// 		result.Tables[i.Table] = t
// 	}

// 	if len(unresolved) > 0 {
// 		return nil, behemotherr.NewMigrationError("Baseline.ResolveIssues", "unresolved_issues",
// 			fmt.Errorf("unresolved: %s", strings.Join(unresolved, ", ")))
// 	}
// 	return result, nil

// }

// func liveIndexesOf(t TableIntrospection) []Index {
// 	var indexes []Index
// 	for _, ind := range t.Indexes {
// 		indexes = append(indexes, *ind.Live)
// 	}

// 	return indexes
// }

// func liveForeignKeysOf(t TableIntrospection) []ForeignKey {
// 	var foreignKeys []ForeignKey
// 	for _, fk := range t.ForeignKeys {
// 		foreignKeys = append(foreignKeys, *fk.Live)
// 	}

// 	return foreignKeys
// }

// func remove[T comparable](l []T, item T) []T {
// 	for i, other := range l {
// 		if other == item {
// 			return append(l[:i], l[i+1:]...)
// 		}
// 	}
// 	return l
// }

// func replaceColumn(schema *TableSchema, col *Column) {
// 	for i, c := range schema.Columns {
// 		if c.Name == col.Name {
// 			schema.Columns[i] = *col
// 			break
// 		}
// 	}
// }
