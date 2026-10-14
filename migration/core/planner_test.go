package core

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

// Two tables as an application declares them: each with an index, one of
// them unique, and a foreign key between them.
var (
	planAuthors = schema.Table{
		Name: "authors",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: "email", Type: schema.ColTypeString, Length: 255},
		},
		Indexes: []schema.Index{{Name: "uq_authors_email", Columns: []string{"email"}, Unique: true}},
	}
	planBooks = schema.Table{
		Name: "books",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: "author_id", Type: schema.ColTypeString, Length: 36},
		},
		Indexes: []schema.Index{{Name: "idx_books_author_id", Columns: []string{"author_id"}}},
		ForeignKeys: []schema.ForeignKey{{
			Name: "fk_books_author", Columns: []string{"author_id"},
			RefTable: "authors", RefColumns: []string{"id"}, OnDelete: schema.FKCascade,
		}},
	}
)

// planFor plans declared against a database that holds live.
func planFor(t *testing.T, declared schema.Registry, live ...schema.Table) *MigrationPlan {
	t.Helper()
	tables := map[string]schema.Table{}
	for _, table := range live {
		tables[table.Name] = table
	}
	report, err := RunIntrospection(context.Background(), declared, fakeIntrospector{tables: tables}, false)
	if err != nil {
		t.Fatal(err)
	}
	plan, issues, err := BuildPlan(report, declared)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %+v, want none", issues)
	}
	return plan
}

// No driver creates indexes or foreign keys in its CREATE TABLE, so the plan
// for a new table has to carry each as an operation of its own.
func TestBuildPlanGivesANewTableItsIndexes(t *testing.T) {
	plan := planFor(t, declaredRegistry(t, planAuthors, planBooks))

	var indexes, foreignKeys []string
	for _, planned := range plan.Operations {
		switch op := planned.Operation; op.Kind {
		case OpCreateTable:
			if len(op.NewTable.Indexes) != 0 || len(op.NewTable.ForeignKeys) != 0 {
				t.Errorf("%s still carries %d index(es) and %d foreign key(s), which no driver creates from there",
					op.ID, len(op.NewTable.Indexes), len(op.NewTable.ForeignKeys))
			}
		case OpAddIndex:
			indexes = append(indexes, op.ID)
		case OpAddForeignKey:
			foreignKeys = append(foreignKeys, op.ID)
		}
	}
	slices.Sort(indexes)
	if want := []string{"add_index_authors_uq_authors_email", "add_index_books_idx_books_author_id"}; !slices.Equal(indexes, want) {
		t.Errorf("index operations = %v, want %v", indexes, want)
	}
	if want := []string{"add_fk_books_fk_books_author"}; !slices.Equal(foreignKeys, want) {
		t.Errorf("foreign key operations = %v, want %v", foreignKeys, want)
	}

	// An index of a new table is planned like a missing index of a table
	// that exists, so the two can't come apart.
	existing := planFor(t, declaredRegistry(t, planAuthors), schema.Table{Name: planAuthors.Name, Columns: planAuthors.Columns})
	for _, planned := range plan.Operations {
		if planned.Operation.ID == "add_index_authors_uq_authors_email" && !reflect.DeepEqual(planned, existing.Operations[0]) {
			t.Errorf("new table: %+v\nexisting table: %+v", planned.Operation, existing.Operations[0].Operation)
		}
	}
}

// The bug this guards against: the first migration of a new database created
// the tables without their indexes, and only a second run added them.
func TestNewTablesConvergeInOneMigration(t *testing.T) {
	ctx := context.Background()
	cfg := MigrationConfig{FolderPath: filepath.Join(t.TempDir(), "migrations")}
	declared := Declared{Schemas: declaredRegistry(t, planAuthors, planBooks)}
	db := newMemoryDatabase()
	backend := Backend{Introspector: db}

	res, err := Generate(ctx, cfg, declared, backend, RunOptions{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}

	// Every operation on a table comes after the table's creation.
	created := map[string]bool{}
	for _, op := range res.Migration.Up {
		if op.Kind == OpCreateTable {
			created[op.Table] = true
		} else if !created[op.Table] {
			t.Errorf("%s runs before its table exists", op.ID)
		}
	}

	// The application's own tool applies the migration.
	if err := db.ApplyMigration(ctx, MigrationRequest{Migration: *res.Migration}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []schema.Table{planAuthors, planBooks} {
		if got := db.live[want.Name]; !reflect.DeepEqual(got.Indexes, want.Indexes) || !reflect.DeepEqual(got.ForeignKeys, want.ForeignKeys) {
			t.Errorf("%s: indexes = %+v, foreign keys = %+v; want %+v and %+v", want.Name, got.Indexes, got.ForeignKeys, want.Indexes, want.ForeignKeys)
		}
	}

	res, err = Generate(ctx, cfg, declared, backend, RunOptions{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNoChanges {
		t.Errorf("second run: status = %s with %d operation(s), want %s", res.Status, len(res.Migration.Up), StatusNoChanges)
	}
}

// On the managed path the snapshot is built from the migration's operations.
// It has to list each index once: a table that kept its indexes next to the
// operations that add them would list them twice.
func TestSnapshotOfNewTablesMatchesTheDeclaration(t *testing.T) {
	declared := declaredRegistry(t, planAuthors, planBooks)
	plan := planFor(t, declared)
	m, err := (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{Operations: opsFromPlanned(plan.Operations)}, "")
	if err != nil {
		t.Fatal(err)
	}

	tables, err := applyOperationsToSnapshot(map[string]schema.Table{}, m.Up)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []schema.Table{planAuthors, planBooks} {
		if got := tables[want.Name]; !reflect.DeepEqual(got.Indexes, want.Indexes) || !reflect.DeepEqual(got.ForeignKeys, want.ForeignKeys) {
			t.Errorf("%s: indexes = %+v, foreign keys = %+v; want %+v and %+v", want.Name, got.Indexes, got.ForeignKeys, want.Indexes, want.ForeignKeys)
		}
	}

	// The next diff of that snapshot against the declaration plans nothing.
	next, issues, err := BuildPlan(RunIntrospectionFromSnapshotDiff(snapshotAsRegistry(SchemaSnapshot{Tables: tables}), declared), declared)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Operations) != 0 || len(issues) != 0 {
		t.Errorf("after the first migration: %d operation(s) and %d issue(s), want none", len(next.Operations), len(issues))
	}
}

func TestBaselineSnapshotListsEachIndexOnce(t *testing.T) {
	m := BuildBaselineMigration(map[string]schema.Table{planAuthors.Name: planAuthors, planBooks.Name: planBooks})

	tables, err := applyOperationsToSnapshot(map[string]schema.Table{}, m.Up)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []schema.Table{planAuthors, planBooks} {
		if got := tables[want.Name]; !reflect.DeepEqual(got.Indexes, want.Indexes) || !reflect.DeepEqual(got.ForeignKeys, want.ForeignKeys) {
			t.Errorf("%s: indexes = %+v, foreign keys = %+v; want %+v and %+v", want.Name, got.Indexes, got.ForeignKeys, want.Indexes, want.ForeignKeys)
		}
	}
}

// A table that reaches the generator with its indexes still on it would lose
// them without an error, so the generator refuses it, as it refuses inline
// foreign keys.
func TestGenerateRejectsInlineIndexes(t *testing.T) {
	inline := SchemaOperation{ID: createTableID(planAuthors.Name), Kind: OpCreateTable, Table: planAuthors.Name, NewTable: &planAuthors}

	for name, resolved := range map[string]*ResolvedOperationSet{
		"generated operation": {Operations: []SchemaOperation{inline}},
		"custom migration":    {Custom: []CustomMigration{{Name: "authors_by_hand", Up: []SchemaOperation{inline}}}},
	} {
		if _, err := (&DefaultMigrationGenerator{}).Generate(resolved, ""); err == nil {
			t.Errorf("%s: a create table with inline indexes was accepted", name)
		}
	}
}
