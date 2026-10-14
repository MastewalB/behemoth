package schema_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/types/schema"
)

// Public is not a property of the database: it stays out of the JSON that
// schema snapshots and migration files are made of, so marking a column
// changes neither.
func TestColumnPublicIsNotSerialized(t *testing.T) {
	marked, err := json.Marshal(schema.Column{Name: "plan", Type: schema.ColTypeString, Public: true})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(schema.Column{Name: "plan", Type: schema.ColTypeString})
	if err != nil {
		t.Fatal(err)
	}
	if string(marked) != string(plain) || strings.Contains(string(marked), "Public") {
		t.Errorf("a public column serializes as %s, a private one as %s", marked, plain)
	}
	var back schema.Column
	if err := json.Unmarshal([]byte(`{"Name":"plan","Public":true}`), &back); err != nil || back.Public {
		t.Errorf("Public was read back from JSON: %+v, %v", back, err)
	}
}

// Normalize turns what a driver returned into the type the column declares,
// so a view of a row encodes the same on every database.
func TestNormalize(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	col := func(t schema.ColumnType) schema.Column { return schema.Column{Type: t} }
	for name, tc := range map[string]struct {
		col  schema.Column
		raw  any
		want any
	}{
		"a bool as SQLite's 1":        {col(schema.ColTypeBoolean), int64(1), true},
		"a bool as 0":                 {col(schema.ColTypeBoolean), int64(0), false},
		"a bool that is one":          {col(schema.ColTypeBoolean), true, true},
		"text as bytes":               {col(schema.ColTypeText), []byte("pro"), "pro"},
		"a string":                    {col(schema.ColTypeString), "pro", "pro"},
		"an int as a float":           {col(schema.ColTypeInteger), float64(3), int64(3)},
		"a bigint as text":            {col(schema.ColTypeBigInt), []byte("42"), int64(42)},
		"a real as an int":            {col(schema.ColTypeReal), int64(2), float64(2)},
		"a timestamp as text":         {col(schema.ColTypeTimestamp), "2026-10-09T12:00:00Z", at},
		"a timestamp that is one":     {col(schema.ColTypeDateTime), at, at},
		"a numeric as bytes":          {col(schema.ColTypeNumeric), []byte("12.50"), "12.50"},
		"a blob":                      {col(schema.ColTypeBlob), []byte{1, 2}, []byte{1, 2}},
		"NULL":                        {col(schema.ColTypeString), nil, nil},
		"a value it can't convert":    {col(schema.ColTypeBoolean), "maybe", "maybe"},
		"a bool column holding a two": {col(schema.ColTypeBoolean), int64(2), int64(2)},
	} {
		got := schema.Normalize(tc.col, tc.raw)
		if gt, ok := got.(time.Time); ok {
			if wt, ok := tc.want.(time.Time); !ok || !gt.Equal(wt) {
				t.Errorf("%s: got %v, want %v", name, got, tc.want)
			}
			continue
		}
		if gb, ok := got.([]byte); ok {
			if wb, ok := tc.want.([]byte); !ok || string(gb) != string(wb) {
				t.Errorf("%s: got %v, want %v", name, got, tc.want)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %#v, want %#v", name, got, tc.want)
		}
	}

	// A JSON column is embedded as the document, not as a string of it.
	for _, raw := range []any{[]byte(`{"a":1}`), `{"a":1}`} {
		encoded, err := json.Marshal(map[string]any{"prefs": schema.Normalize(col(schema.ColTypeJson), raw)})
		if err != nil || string(encoded) != `{"prefs":{"a":1}}` {
			t.Errorf("a JSON column from %T encodes as %s (%v)", raw, encoded, err)
		}
	}
	if got := schema.Normalize(col(schema.ColTypeJson), "not json"); got != "not json" {
		t.Errorf("text that is not JSON in a JSON column: got %#v", got)
	}
}
