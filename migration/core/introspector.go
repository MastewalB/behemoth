package core

import (
	"context"
	"fmt"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

func RunIntrospection(
	ctx context.Context,
	current schema.Registry,
	introspector SchemaIntrospector,
	trackExtraColumns bool,
) (*IntrospectionReport, error) {
	report := &IntrospectionReport{Tables: map[string]TableIntrospection{}}
	names := newCanonicalNames(current.All())

	for _, declared := range current.All() {
		exists, err := introspector.TableExists(ctx, declared.Name)
		if err != nil {
			return nil, behemotherr.NewMigrationError("Introspection.TableExists", behemotherr.ErrorCodeMigrationExistenceCheckFailed, err)
		}
		if !exists {
			report.Tables[declared.Name] = TableIntrospection{Table: declared.Name, ExistsLive: false}
			continue // "Declared table missing" branch, no per-column comparison possible or needed
		}

		live, err := introspector.Introspect(ctx, declared.Name)
		if err != nil {
			return nil, behemotherr.NewMigrationError("Introspection.Introspect", behemotherr.ErrorCodeMigrationIntrospectionFailed,
				fmt.Errorf("table %q: %w", declared.Name, err))
		}

		if live.Kind != ObjectTable {
			// "Table found live as incompatible object" branch,
			// no column/index/FK comparison attempted for this table.
			report.Tables[declared.Name] = TableIntrospection{Table: declared.Name, ExistsLive: true, IncompatibleObject: true}
			continue
		}

		live = names.canonicalize(declared.Name, live)
		cols, renames := diffColumns(declared.Columns, live.Schema.Columns, live.Ambiguities, trackExtraColumns)
		report.Tables[declared.Name] = TableIntrospection{
			Table:       declared.Name,
			ExistsLive:  true,
			Columns:     cols,
			Renames:     renames,
			Indexes:     diffIndexes(declared.Indexes, live.Schema.Indexes, trackExtraColumns),
			ForeignKeys: diffForeignKeys(declared.ForeignKeys, live.Schema.ForeignKeys, trackExtraColumns),
		}
	}
	return report, nil
}

// canonicalNames maps physical names back to canonical ones.
//
// An introspector only sees the live database, i.e. physical names, and
// SchemaResolver maps canonical -> physical only. Without translating back,
// a column declared {Name: "email", PhysicalName: "email_address"} would be
// diffed as a missing "email" plus an extra "email_address" — a spurious
// rename (or a destructive drop+add). The mapping comes from the declared
// schema's own PhysicalName fields, the same source BuildSchemaResolverTable
// derives the forward mapping from, so every driver gets this for free.
type canonicalNames struct {
	tables  map[string]string            // physical table -> canonical table
	columns map[string]map[string]string // canonical table -> physical column -> canonical column
}

func newCanonicalNames(declared []schema.Table) canonicalNames {
	n := canonicalNames{tables: map[string]string{}, columns: map[string]map[string]string{}}
	for _, t := range declared {
		n.tables[orDefault(t.PhysicalName, t.Name)] = t.Name
		cols := map[string]string{}
		for _, c := range t.Columns {
			if c.PhysicalName != "" && c.PhysicalName != c.Name {
				cols[c.PhysicalName] = c.Name
			}
		}
		n.columns[t.Name] = cols
	}
	return n
}

func (n canonicalNames) table(physical string) string {
	if canonical, ok := n.tables[physical]; ok {
		return canonical
	}
	return physical // not a declared table — nothing to map back to
}

func (n canonicalNames) column(canonicalTable, physical string) string {
	if canonical, ok := n.columns[canonicalTable][physical]; ok {
		return canonical
	}
	return physical
}

func (n canonicalNames) columnList(canonicalTable string, physical []string) []string {
	out := make([]string, len(physical))
	for i, c := range physical {
		out[i] = n.column(canonicalTable, c)
	}
	return out
}

// canonicalize rewrites every name in an introspected table (whose own name
// is canonicalTable) from physical to canonical. A renamed column keeps its
// live name in PhysicalName, so nothing is lost. live is never mutated in place.
func (n canonicalNames) canonicalize(canonicalTable string, live IntrospectedTable) IntrospectedTable {
	out := live
	out.Schema.Columns = make([]schema.Column, len(live.Schema.Columns))
	for i, c := range live.Schema.Columns {
		if canonical := n.column(canonicalTable, c.Name); canonical != c.Name {
			c.PhysicalName, c.Name = c.Name, canonical // only set when it differs, matching how columns are declared
		}
		out.Schema.Columns[i] = c
	}

	out.Ambiguities = make([]ColumnAmbiguity, len(live.Ambiguities))
	for i, a := range live.Ambiguities {
		a.Column = n.column(canonicalTable, a.Column)
		out.Ambiguities[i] = a
	}

	out.Schema.Indexes = make([]schema.Index, len(live.Schema.Indexes))
	for i, idx := range live.Schema.Indexes {
		idx.Columns = n.columnList(canonicalTable, idx.Columns)
		out.Schema.Indexes[i] = idx
	}

	out.Schema.ForeignKeys = make([]schema.ForeignKey, len(live.Schema.ForeignKeys))
	for i, fk := range live.Schema.ForeignKeys {
		fk.Columns = n.columnList(canonicalTable, fk.Columns)
		fk.RefTable = n.table(fk.RefTable)
		fk.RefColumns = n.columnList(fk.RefTable, fk.RefColumns)
		out.Schema.ForeignKeys[i] = fk
	}
	return out
}

// PartitionForBaseline splits current's declared tables into ones that
// already exist live (baseline candidates) and ones that don't (handled by
// the ordinary Diff/Generate/Apply pipeline, completely untouched by
// anything below).
func PartitionForBaseline(
	ctx context.Context,
	current schema.Registry,
	introspector SchemaIntrospector,
) (candidates []BaselineCandidate, freshTables []string, err error) {
	for _, table := range current.All() {
		exists, err := introspector.TableExists(ctx, table.Name)
		if err != nil {
			return nil, nil, behemotherr.NewMigrationError("Baseline.Partition", behemotherr.ErrorCodeMigrationExistenceCheckFailed, err)
		}
		if exists {
			candidates = append(candidates, BaselineCandidate{Table: table.Name, Current: table})
		} else {
			freshTables = append(freshTables, table.Name)
		}
	}
	return candidates, freshTables, nil
}

// RunIntrospectionFromSnapshotDiff implements behemoth-owned migration mechanism.
// Only the current and previous snaphosts are compared, without a live DB introspection
// It returns IntrospectionReport shape RunIntrospection produces.
// This lets Planning have one implementation regardless of source i.e. whether "previous" came from a live
// database or from behemoth's own snapshot,
// No ambiguities are produced here since both registries are canonical.
func RunIntrospectionFromSnapshotDiff(previous, current schema.Registry) *IntrospectionReport {
	report := &IntrospectionReport{Tables: map[string]TableIntrospection{}}
	for _, declared := range current.All() {
		prevTable, existed := previous.Lookup(declared.Name)
		if !existed {
			report.Tables[declared.Name] = TableIntrospection{Table: declared.Name, ExistsLive: false}
			continue
		}
		cols, renames := diffColumns(declared.Columns, prevTable.Columns, nil, true) // trackExtraColumns=true for behemoth owned migration flow
		report.Tables[declared.Name] = TableIntrospection{
			Table: declared.Name, ExistsLive: true,
			Columns: cols, Renames: renames,
			Indexes:     diffIndexes(declared.Indexes, prevTable.Indexes, true),
			ForeignKeys: diffForeignKeys(declared.ForeignKeys, prevTable.ForeignKeys, true),
		}
	}
	return report
}

// diffColumns is the shared comparison core for both types of migrations(behemoth owned & external).
//
// trackExtraColumns controls the "extra live column" convention from the
// In cases of migrations executed by behemoth's engine, a snapshot is used to record declarations
// and a live column missing in the snapshot should be dropped.
func diffColumns(declared, other []schema.Column, ambiguities []ColumnAmbiguity, trackExtraColumns bool) ([]ColumnFinding, []RenameCandidate) {
	declaredByName := indexColumnsByName(declared)
	otherByName := indexColumnsByName(other)
	ambigByCol := make(map[string]ColumnAmbiguity, len(ambiguities))

	for _, a := range ambiguities {
		ambigByCol[a.Column] = a
	}
	ambiguityOf := func(name string) *ColumnAmbiguity {
		if a, ok := ambigByCol[name]; ok {
			return &a
		}
		return nil
	}

	var findings []ColumnFinding
	var otherOnly, declaredOnly []schema.Column

	for name, d := range declaredByName {
		o, ok := otherByName[name]
		if !ok {
			// column is missing in live
			declaredOnly = append(declaredOnly, d)
			continue
		}

		d, o := d, o
		kind := ColMatch
		if !columnsEqual(d, o) {
			kind = ColDiffers
		}

		findings = append(findings,
			ColumnFinding{
				Name:          name,
				Kind:          kind,
				Declared:      &d,
				Live:          &o,
				TypeAmbiguity: ambiguityOf(name),
			})
	}

	// Add columns only in live. A live column whose type couldn't be mapped
	// never takes part in rename matching: its canonical type is only a guess,
	// so pairing it by structural signature would be a guess too — and would
	// move it out of the findings RejectAmbiguousTypes inspects.
	var ambiguousOtherOnly []schema.Column
	for name, o := range otherByName {
		if _, ok := declaredByName[name]; ok {
			continue
		}
		if ambiguityOf(name) != nil {
			ambiguousOtherOnly = append(ambiguousOtherOnly, o)
		} else {
			otherOnly = append(otherOnly, o)
		}
	}

	pairs, ambgGroups, unmatchedDeclared, unmatchedOther := matchRenameCandidates(declaredOnly, otherOnly)

	var renames []RenameCandidate
	for _, p := range pairs {
		renames = append(renames, RenameCandidate{From: p.From, To: p.To})
	}

	for _, g := range ambgGroups {
		for _, d := range g.Declared {
			renames = append(renames, RenameCandidate{To: d, Ambiguous: true, GroupID: g.ID})
		}
		for _, o := range g.Other {
			renames = append(renames, RenameCandidate{From: o, Ambiguous: true, GroupID: g.ID})
		}
	}

	for _, d := range unmatchedDeclared {
		findings = append(findings, ColumnFinding{Name: d.Name, Kind: ColMissingLive, Declared: &d})
	}

	// An undeclared live column is only tracked when trackExtraColumns is set
	// (baseline / managed path, where it becomes part of the recorded schema);
	// an unmappable one then carries its ambiguity so it is rejected like any
	// other. Otherwise behemoth never reads or writes it, so it's ignored.
	if trackExtraColumns {
		for _, o := range append(unmatchedOther, ambiguousOtherOnly...) {
			findings = append(findings, ColumnFinding{Name: o.Name, Kind: ColExtraLive, Live: &o, TypeAmbiguity: ambiguityOf(o.Name)})
		}
	}

	return findings, renames
}

func diffIndexes(declared, other []schema.Index, trackExtra bool) []IndexFinding {
	declaredByName, otherByName := indexIndexesByName(declared), indexIndexesByName(other)
	var findings []IndexFinding

	for name, d := range declaredByName {
		o, ok := otherByName[name]
		if !ok {
			// index is missing live
			findings = append(findings, IndexFinding{
				Name:     name,
				Kind:     IdxMissing,
				Declared: &d,
			})
			continue
		}

		d, o := d, o
		kind := IdxMatch
		if !indexesEqual(d, o) {
			kind = IdxDiffers
		}

		findings = append(findings, IndexFinding{
			Name:     d.Name,
			Kind:     kind,
			Declared: &d,
			Live:     &o,
		})

	}

	if trackExtra {
		for name, o := range otherByName {
			if _, ok := declaredByName[name]; !ok {
				findings = append(findings, IndexFinding{
					Name: o.Name,
					Kind: IdxExtra,
					Live: &o,
				})
			}
		}
	}

	return findings
}

func diffForeignKeys(declared, other []schema.ForeignKey, trackExtra bool) []ForeignKeyFinding {
	declaredByName, otherByName := indexFKsByName(declared), indexFKsByName(other)
	var findings []ForeignKeyFinding

	for name, d := range declaredByName {
		o, ok := otherByName[name]
		if !ok {
			// declared foreign-key missing live
			findings = append(findings, ForeignKeyFinding{
				Name:     d.Name,
				Kind:     FKMissing,
				Declared: &d,
			})
			continue
		}

		d, o := d, o
		kind := FKMatch
		if !fkEqual(d, o) {
			kind = FKDiffers
		}

		findings = append(findings, ForeignKeyFinding{
			Name:     d.Name,
			Kind:     kind,
			Declared: &d,
			Live:     &o,
		})

	}

	if trackExtra {
		for name, o := range otherByName {
			if _, ok := declaredByName[name]; !ok {
				findings = append(findings, ForeignKeyFinding{
					Name: o.Name,
					Kind: FKExtra,
					Live: &o,
				})
			}
		}
	}

	return findings
}
