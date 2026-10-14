package core

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestIsNarrowingChange(t *testing.T) {
	str := func(length int, nullable bool) schema.Column {
		return schema.Column{Name: "c", Type: schema.ColTypeString, Length: length, Nullable: nullable}
	}
	typed := func(ct schema.ColumnType, length int) schema.Column {
		return schema.Column{Name: "c", Type: ct, Length: length}
	}
	serial := func(autoInc bool) schema.Column {
		return schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: autoInc}
	}
	for name, tc := range map[string]struct {
		live, declared schema.Column
		narrowing      bool
	}{
		"adding NOT NULL":              {str(40, true), str(40, false), true},
		"dropping NOT NULL":            {str(40, false), str(40, true), false},
		"shrinking the length":         {str(255, false), str(40, false), true},
		"growing the length":           {str(40, false), str(255, false), false},
		"removing auto-increment":      {serial(true), serial(false), true},
		"adding auto-increment":        {serial(false), serial(true), true},
		"widening on every axis":       {str(40, false), str(255, true), false},
		"one narrowing axis is enough": {str(40, true), str(255, false), true},
		"text to integer":              {typed(schema.ColTypeText, 0), typed(schema.ColTypeInteger, 0), true},
		"text to bounded string":       {typed(schema.ColTypeText, 0), typed(schema.ColTypeString, 40), true},
		"integer to bigint":            {typed(schema.ColTypeInteger, 0), typed(schema.ColTypeBigInt, 0), true},
		"bounded string to text":       {typed(schema.ColTypeString, 40), typed(schema.ColTypeText, 0), true},
	} {
		if got := isNarrowingChange(tc.live, tc.declared); got != tc.narrowing {
			t.Errorf("%s: isNarrowingChange = %v, want %v", name, got, tc.narrowing)
		}
	}
}

// stringDefault255 normalizes like both SQL drivers: a string declared
// without a length is created as VARCHAR(255).
type stringDefault255 struct{ fakeIntrospector }

func (stringDefault255) NormalizeColumn(_ string, col schema.Column) schema.Column {
	if col.Type == schema.ColTypeString && col.Length <= 0 {
		col.Length = 255
	}
	return col
}

// planAlter runs introspection and planning for one table whose "c" column
// differs, and reports whether the alter was planned automatically or raised
// as an issue needing confirmation.
func planAlter(t *testing.T, introspector SchemaIntrospector, declared schema.Table) (auto, issue bool) {
	t.Helper()
	reg := declaredRegistry(t, declared)
	report, err := RunIntrospection(context.Background(), reg, introspector, false)
	if err != nil {
		t.Fatal(err)
	}
	plan, issues, err := BuildPlan(report, reg)
	if err != nil {
		t.Fatal(err)
	}
	id := alterColumnID(declared.Name, "c")
	for _, op := range plan.Operations {
		if op.Operation.ID == id {
			auto = true
		}
	}
	for _, is := range issues {
		if is.ID == id {
			issue = true
		}
	}
	return auto, issue
}

func TestPlanNarrowingNeedsConfirmation(t *testing.T) {
	table := func(c schema.Column) schema.Table {
		return schema.Table{Name: "t", Columns: []schema.Column{{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true}, c}}
	}
	live := func(c schema.Column) fakeIntrospector {
		return fakeIntrospector{tables: map[string]schema.Table{"t": table(c)}}
	}
	col := func(length int, nullable bool) schema.Column {
		return schema.Column{Name: "c", Type: schema.ColTypeString, Length: length, Nullable: nullable}
	}

	for name, tc := range map[string]struct {
		introspector   SchemaIntrospector
		declared       schema.Column
		wantConfirming bool
	}{
		"adding NOT NULL is confirmed":   {live(col(40, true)), col(40, false), true},
		"shrinking length is confirmed":  {live(col(255, false)), col(40, false), true},
		"dropping NOT NULL is automatic": {live(col(40, false)), col(40, true), false},
		"growing length is automatic":    {live(col(40, false)), col(255, false), false},
		// Without normalization a length-less declaration (0) would read as a
		// shrink from the live 255; normalized, only the nullability changes.
		"unspecified length is not a shrink": {stringDefault255{live(col(255, false))}, col(0, true), false},
		"type change is confirmed":           {live(col(40, false)), schema.Column{Name: "c", Type: schema.ColTypeText}, true},
		// columnsEqual compares AutoInc, so a change to it alone is detected,
		// and needs confirmation in either direction.
		"adding auto-increment is confirmed": {
			live(schema.Column{Name: "c", Type: schema.ColTypeInteger}),
			schema.Column{Name: "c", Type: schema.ColTypeInteger, AutoInc: true}, true},
		"removing auto-increment is confirmed": {
			live(schema.Column{Name: "c", Type: schema.ColTypeInteger, AutoInc: true}),
			schema.Column{Name: "c", Type: schema.ColTypeInteger}, true},
		// The driver stores blob as bytes: declared blob against live bytes is
		// not a type change, so dropping NOT NULL stays automatic.
		"type the driver collapses is not a change": {
			blobAsBytes{live(schema.Column{Name: "c", Type: schema.ColTypeBytes})},
			schema.Column{Name: "c", Type: schema.ColTypeBlob, Nullable: true}, false},
	} {
		auto, issue := planAlter(t, tc.introspector, table(tc.declared))
		if tc.wantConfirming && (auto || !issue) {
			t.Errorf("%s: planned automatically = %v, raised as an issue = %v; want an issue only", name, auto, issue)
		}
		if !tc.wantConfirming && (!auto || issue) {
			t.Errorf("%s: planned automatically = %v, raised as an issue = %v; want an automatic alter only", name, auto, issue)
		}
	}
}

// A baseline awaiting confirmation is regenerated and compared with the file
// on disk (migrationsEqual), so building it must give the same migration
// every time — including column, index and foreign key order.
func TestBaselineIsDeterministic(t *testing.T) {
	ctx := context.Background()
	wide := schema.Table{Name: "wide",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "a", Type: schema.ColTypeText}, {Name: "b", Type: schema.ColTypeText}, {Name: "c", Type: schema.ColTypeText},
			{Name: "d", Type: schema.ColTypeText}, {Name: "e", Type: schema.ColTypeText}, {Name: "f", Type: schema.ColTypeInteger},
		},
		Indexes: []schema.Index{
			{Name: "idx_a", Columns: []string{"a"}}, {Name: "idx_b", Columns: []string{"b"}},
			{Name: "idx_c", Columns: []string{"c"}}, {Name: "idx_d", Columns: []string{"d"}},
		},
		ForeignKeys: []schema.ForeignKey{
			{Name: "fk_e", Columns: []string{"e"}, RefTable: "other", RefColumns: []string{"id"}},
			{Name: "fk_f", Columns: []string{"f"}, RefTable: "other", RefColumns: []string{"id"}},
		},
	}
	deps := MigrationDeps{Introspector: fakeIntrospector{tables: map[string]schema.Table{"wide": wide}}}
	candidates := []BaselineCandidate{{Table: "wide", Current: wide}}

	first, err := buildBaselineMigrationOnly(ctx, candidates, deps)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := buildBaselineMigrationOnly(ctx, candidates, deps)
		if err != nil {
			t.Fatal(err)
		}
		if !migrationsEqual(*first, *again) {
			t.Fatalf("run %d produced a different baseline than the first", i+1)
		}
	}
}
