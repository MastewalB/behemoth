package core

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types/schema"
)

type namedModel string

func (m namedModel) SchemaName() string     { return string(m) }
func (m namedModel) PrimaryKeyName() string { return "id" }
func (m namedModel) PrimaryKeyField() any   { return nil }
func (m namedModel) New() behemoth.Model    { return m }

// fakeIntrospector serves fixed live tables.
type fakeIntrospector struct{ tables map[string]schema.Table }

func (f fakeIntrospector) TableExists(_ context.Context, name string) (bool, error) {
	_, ok := f.tables[name]
	return ok, nil
}

func (f fakeIntrospector) Introspect(_ context.Context, name string) (IntrospectedTable, error) {
	t, ok := f.tables[name]
	return IntrospectedTable{Schema: t, Kind: ObjectTable, Exists: ok}, nil
}

// blobAsBytes is a driver whose DDL stores blob as bytes, like Postgres.
type blobAsBytes struct{ fakeIntrospector }

func (blobAsBytes) NormalizeColumn(_ string, col schema.Column) schema.Column {
	if col.Type == schema.ColTypeBlob {
		col.Type = schema.ColTypeBytes
	}
	return col
}

var (
	normDeclared = schema.Table{Name: "files", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		{Name: "data", Type: schema.ColTypeBlob},
	}}
	normLive = schema.Table{Name: "files", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		{Name: "data", Type: schema.ColTypeBytes},
	}}
)

func declaredRegistry(t *testing.T, tables ...schema.Table) schema.Registry {
	t.Helper()
	reg := schema.NewRegistry()
	for _, table := range tables {
		if err := reg.Declare(namedModel(table.Name), table); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Freeze(); err != nil {
		t.Fatal(err)
	}
	return reg
}

func columnFinding(t *testing.T, report *IntrospectionReport, table, column string) ColumnFinding {
	t.Helper()
	for _, f := range report.Tables[table].Columns {
		if f.Name == column {
			return f
		}
	}
	t.Fatalf("no finding for %s.%s", table, column)
	return ColumnFinding{}
}

func TestNormalizedDeclarationMatchesLive(t *testing.T) {
	ctx := context.Background()
	reg := declaredRegistry(t, normDeclared)
	live := fakeIntrospector{tables: map[string]schema.Table{"files": normLive}}

	plain, err := RunIntrospection(ctx, reg, live, true)
	if err != nil {
		t.Fatal(err)
	}
	if f := columnFinding(t, plain, "files", "data"); f.Kind != ColDiffers {
		t.Errorf("without a normalizer: data = %s, want %s", f.Kind, ColDiffers)
	}

	normalized, err := RunIntrospection(ctx, reg, blobAsBytes{live}, true)
	if err != nil {
		t.Fatal(err)
	}
	f := columnFinding(t, normalized, "files", "data")
	if f.Kind != ColMatch {
		t.Errorf("with a normalizer: data = %s, want %s", f.Kind, ColMatch)
	}
	if f.Declared.Type != schema.ColTypeBlob {
		t.Errorf("finding carries Declared.Type %s, want the original declaration (blob)", f.Declared.Type)
	}
}

func TestNormalizedDeclarationPairsRenames(t *testing.T) {
	ctx := context.Background()
	declared := schema.Table{Name: "files", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		{Name: "payload", Type: schema.ColTypeBlob, Nullable: true},
	}}
	live := fakeIntrospector{tables: map[string]schema.Table{"files": {Name: "files", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		{Name: "content", Type: schema.ColTypeBytes, Nullable: true},
	}}}}
	reg := declaredRegistry(t, declared)

	plain, err := RunIntrospection(ctx, reg, live, true)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(plain.Tables["files"].Renames); n != 0 {
		t.Errorf("without a normalizer: %d rename candidates, want 0 (blob and bytes signatures differ)", n)
	}

	normalized, err := RunIntrospection(ctx, reg, blobAsBytes{live}, true)
	if err != nil {
		t.Fatal(err)
	}
	renames := normalized.Tables["files"].Renames
	if len(renames) != 1 || renames[0].From.Name != "payload" || renames[0].To.Name != "content" {
		t.Errorf("with a normalizer: renames = %+v, want payload paired with content", renames)
	}
}

// A baseline records what later snapshot diffs compare declarations against,
// so a column that only matches after normalization must be recorded as
// declared — otherwise it differs again on the first run after the baseline.
func TestBaselineRecordsDeclarationForNormalizedMatch(t *testing.T) {
	ctx := context.Background()
	deps := MigrationDeps{Introspector: blobAsBytes{fakeIntrospector{tables: map[string]schema.Table{"files": normLive}}}}

	m, err := buildBaselineMigrationOnly(ctx, []BaselineCandidate{{Table: "files", Current: normDeclared}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]schema.Table{}
	for _, op := range m.Up {
		if op.Kind == OpCreateTable {
			recorded[op.Table] = *op.NewTable
		}
	}
	if got := recorded["files"].Columns[1].Type; got != schema.ColTypeBlob {
		t.Fatalf("baseline recorded data as %s, want the declared blob", got)
	}

	// The next snapshot diff — declarations against the baseline — is clean.
	report := RunIntrospectionFromSnapshotDiff(snapshotAsRegistry(SchemaSnapshot{Tables: recorded}), declaredRegistry(t, normDeclared))
	for _, f := range report.Tables["files"].Columns {
		if f.Kind != ColMatch {
			t.Errorf("after baseline: %s = %s, want %s", f.Name, f.Kind, ColMatch)
		}
	}
}
