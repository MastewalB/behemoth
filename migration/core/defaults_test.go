package core

import (
	"encoding/json"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestLiteralsEqual(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b  any
		equal bool
	}{
		"int and int64":             {7, int64(7), true},
		"int and float64 from JSON": {7, float64(7), true},
		"int64 and float64":         {int64(-1), float64(-1), true},
		"fractional":                {1.5, float64(1.5), true},
		"different numbers":         {7, int64(8), false},
		"number and numeric string": {7, "7", false},
		"strings":                   {"it's", "it's", true},
		"different strings":         {"a", "b", false},
		"bools":                     {true, true, true},
		"bool and number":           {true, int64(1), false},
		"both nil":                  {nil, nil, true},
		"nil and zero":              {nil, 0, false},
	} {
		if got := literalsEqual(tc.a, tc.b); got != tc.equal {
			t.Errorf("%s: literalsEqual(%#v, %#v) = %v, want %v", name, tc.a, tc.b, got, tc.equal)
		}
	}
}

func TestSameExpression(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b string
		same bool
	}{
		"case":                       {"NOW()", "now()", true},
		"keyword case":               {"current_timestamp", "CURRENT_TIMESTAMP", true},
		"whitespace":                 {"(1+1)", "(1 + 1)", true},
		"enclosing parentheses":      {"1+1", "((1 + 1))", true},
		"inner parentheses are kept": {"(a)+(b)", "a)+(b", false},
		"quoted text is exact":       {"'A'", "'a'", false},
		"quoted spaces are kept":     {"'a b'", "'ab'", false},
		"quoted identifier is exact": {`"Col"`, `"col"`, false},
		"doubled quote stays inside": {"'it''s'", "'it''s'", true},
		"different functions":        {"now()", "clock_timestamp()", false},
		"empty":                      {"", "", true},
		"empty and something":        {"", "now()", false},
	} {
		if got := sameExpression(tc.a, tc.b); got != tc.same {
			t.Errorf("%s: sameExpression(%q, %q) = %v, want %v", name, tc.a, tc.b, got, tc.same)
		}
	}
}

func TestDefaultsEqual(t *testing.T) {
	expr := func(driver, e string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{driver: {Default: e}}
	}
	for name, tc := range map[string]struct {
		a, b  schema.Column
		equal bool
	}{
		"no defaults":                   {schema.Column{}, schema.Column{}, true},
		"same literal":                  {schema.Column{Default: 7}, schema.Column{Default: int64(7)}, true},
		"literal added":                 {schema.Column{}, schema.Column{Default: "x"}, false},
		"same expression":               {schema.Column{Overrides: expr("postgres", "NOW()")}, schema.Column{Overrides: expr("postgres", "now()")}, true},
		"expression for another driver": {schema.Column{Overrides: expr("sqlite", "now()")}, schema.Column{Overrides: expr("postgres", "now()")}, false},
		"override without a default":    {schema.Column{Overrides: map[string]schema.ColumnOverride{"postgres": {Type: schema.ColTypeText}}}, schema.Column{}, true},
	} {
		if got := defaultsEqual(tc.a, tc.b); got != tc.equal {
			t.Errorf("%s: defaultsEqual = %v, want %v", name, got, tc.equal)
		}
	}
}

func TestPlanDefaultChanges(t *testing.T) {
	table := func(c schema.Column) schema.Table {
		return schema.Table{Name: "t", Columns: []schema.Column{{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true}, c}}
	}
	text := func(def any) schema.Column { return schema.Column{Name: "c", Type: schema.ColTypeText, Default: def} }
	live := func(c schema.Column) fakeIntrospector {
		return fakeIntrospector{tables: map[string]schema.Table{"t": table(c)}}
	}

	for name, tc := range map[string]struct {
		live, declared schema.Column
		confirming     bool
	}{
		"adding a default is automatic":   {text(nil), text("x"), false},
		"changing a default is automatic": {text("x"), text("y"), false},
		"removing a default is confirmed": {text("x"), text(nil), true},
		"removing an expression default is confirmed": {
			schema.Column{Name: "c", Type: schema.ColTypeText, Overrides: map[string]schema.ColumnOverride{"postgres": {Default: "now()"}}},
			text(nil), true},
	} {
		auto, issue := planAlter(t, live(tc.live), table(tc.declared))
		if tc.confirming && (auto || !issue) {
			t.Errorf("%s: planned automatically = %v, raised as an issue = %v; want an issue only", name, auto, issue)
		}
		if !tc.confirming && (!auto || issue) {
			t.Errorf("%s: planned automatically = %v, raised as an issue = %v; want an automatic alter only", name, auto, issue)
		}
	}

	// Unchanged: no operation at all.
	if auto, issue := planAlter(t, live(text(int64(7))), table(text(7))); auto || issue {
		t.Errorf("unchanged default: planned automatically = %v, raised as an issue = %v; want neither", auto, issue)
	}
}

// Path I compares declarations against the snapshot, which went through JSON:
// numeric defaults come back as float64 and must still match.
func TestSnapshotDiffMatchesNumericDefaultsAfterJSON(t *testing.T) {
	declared := schema.Table{Name: "t", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		{Name: "n", Type: schema.ColTypeInteger, Default: 7},
		{Name: "neg", Type: schema.ColTypeInteger, Default: int64(-1)},
	}}
	b, err := json.Marshal(map[string]schema.Table{"t": declared})
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string]schema.Table
	if err := json.Unmarshal(b, &snapshot); err != nil {
		t.Fatal(err)
	}
	if _, isFloat := snapshot["t"].Columns[1].Default.(float64); !isFloat {
		t.Fatalf("expected JSON to turn the default into float64, got %T", snapshot["t"].Columns[1].Default)
	}

	report := RunIntrospectionFromSnapshotDiff(snapshotAsRegistry(SchemaSnapshot{Tables: snapshot}), declaredRegistry(t, declared))
	for _, f := range report.Tables["t"].Columns {
		if f.Kind != ColMatch {
			t.Errorf("%s = %s, want %s", f.Name, f.Kind, ColMatch)
		}
	}
}
