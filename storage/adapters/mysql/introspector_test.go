package mysql

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestNormalizeColumn(t *testing.T) {
	yes := true
	d := NewMySQLDriver(nil, nil)

	for name, tc := range map[string]struct {
		declared, want schema.Column
	}{
		"string without a length is VARCHAR(255)": {
			schema.Column{Name: "s", Type: schema.ColTypeString},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 255},
		},
		"string with a length keeps it": {
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
		},
		"uuid is CHAR(36), read back as a string": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			schema.Column{Name: "u", Type: schema.ColTypeString, Length: 36, Nullable: true},
		},
		"timestamp is DATETIME, read back as datetime": {
			schema.Column{Name: "ts", Type: schema.ColTypeTimestamp},
			schema.Column{Name: "ts", Type: schema.ColTypeDateTime},
		},
		"bytes is LONGBLOB, read back as blob": {
			schema.Column{Name: "b", Type: schema.ColTypeBytes, Nullable: true},
			schema.Column{Name: "b", Type: schema.ColTypeBlob, Nullable: true},
		},
		"only strings carry a length": {
			schema.Column{Name: "t", Type: schema.ColTypeText, Length: 10},
			schema.Column{Name: "t", Type: schema.ColTypeText},
		},
		"primary key is NOT NULL and not separately UNIQUE": {
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, Nullable: true, Unique: true},
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		},
		"override type replaces the declared one": {
			schema.Column{Name: "o", Type: schema.ColTypeString, Length: 40, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}},
			schema.Column{Name: "o", Type: schema.ColTypeText},
		},
		"override AutoInc replaces the declared one": {
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, AutoInc: true},
		},
		"other drivers' overrides are ignored": {
			schema.Column{Name: "j", Type: schema.ColTypeJson, Overrides: map[string]schema.ColumnOverride{"sqlite": {Type: schema.ColTypeText}}},
			schema.Column{Name: "j", Type: schema.ColTypeJson},
		},
		"unchanged column stays unchanged": {
			schema.Column{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true, Nullable: true, Default: "x"},
			schema.Column{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true, Nullable: true, Default: "x"},
		},
	} {
		if got := d.NormalizeColumn("t", tc.declared); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got, tc.want)
		}
	}
}

func TestNormalizeColumnDefaults(t *testing.T) {
	d := NewMySQLDriver(nil, nil)
	my := func(expr string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{DriverName: {Default: expr}}
	}
	for name, tc := range map[string]struct {
		declared     schema.Column
		wantDefault  any
		wantOverride map[string]schema.ColumnOverride
	}{
		"string literal":            {schema.Column{Type: schema.ColTypeString, Default: "it's"}, "it's", nil},
		"empty string":              {schema.Column{Type: schema.ColTypeString, Default: ""}, "", nil},
		"integer literal":           {schema.Column{Type: schema.ColTypeInteger, Default: 7}, int64(7), nil},
		"float64 from JSON":         {schema.Column{Type: schema.ColTypeInteger, Default: float64(7)}, int64(7), nil},
		"negative integer":          {schema.Column{Type: schema.ColTypeInteger, Default: -1}, int64(-1), nil},
		"fraction":                  {schema.Column{Type: schema.ColTypeReal, Default: 1.5}, 1.5, nil},
		"bool":                      {schema.Column{Type: schema.ColTypeBoolean, Default: true}, true, nil},
		"number on a string column": {schema.Column{Type: schema.ColTypeString, Default: 7}, "7", nil},
		"text literal":              {schema.Column{Type: schema.ColTypeText, Default: `it's a\b`}, `it's a\b`, nil},
		"number on a text column":   {schema.Column{Type: schema.ColTypeText, Default: -1}, "-1", nil},
		"json literal":              {schema.Column{Type: schema.ColTypeJson, Default: "{}"}, "{}", nil},
		"no default":                {schema.Column{Type: schema.ColTypeText}, nil, nil},
		"function expression":       {schema.Column{Type: schema.ColTypeString, Overrides: my("uuid()")}, nil, my("uuid()")},
		"CURRENT_TIMESTAMP is now":  {schema.Column{Type: schema.ColTypeTimestamp, Overrides: my("CURRENT_TIMESTAMP(6)")}, nil, my("now(6)")},
		"redundant parentheses":     {schema.Column{Type: schema.ColTypeInteger, Overrides: my("((1+1))")}, nil, my("1+1")},
		"quoted literal as expr":    {schema.Column{Type: schema.ColTypeString, Overrides: my("'x'")}, "x", nil},
		"number as expr":            {schema.Column{Type: schema.ColTypeInteger, Overrides: my("(7)")}, int64(7), nil},
		"NULL expression":           {schema.Column{Type: schema.ColTypeText, Overrides: my("NULL")}, nil, nil},
		"override wins over literal": {
			schema.Column{Type: schema.ColTypeTimestamp, Default: "2020-01-01", Overrides: my("now(6)")}, nil, my("now(6)")},
		"other drivers' expressions don't apply": {
			schema.Column{Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{"postgres": {Default: "now()"}}}, nil, nil},
		"auto-increment has no default": {
			schema.Column{Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true, Default: 1}, nil, nil},
	} {
		got := d.NormalizeColumn("t", tc.declared)
		if !reflect.DeepEqual(got.Default, tc.wantDefault) || !reflect.DeepEqual(got.Overrides, tc.wantOverride) {
			t.Errorf("%s: got Default %#v, Overrides %v; want %#v, %v", name, got.Default, got.Overrides, tc.wantDefault, tc.wantOverride)
		}
	}
}

// The stored forms below were read from information_schema.COLUMNS on MySQL
// 8.0.36 (COLUMN_DEFAULT, and DEFAULT_GENERATED in EXTRA).
func TestMySQLDefaultFromStored(t *testing.T) {
	my := func(expr string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{DriverName: {Default: expr}}
	}
	for name, tc := range map[string]struct {
		stored       string
		generated    bool
		ct           schema.ColumnType
		wantDefault  any
		wantOverride map[string]schema.ColumnOverride
	}{
		"literal string is unquoted":         {`it's`, false, schema.ColTypeString, "it's", nil},
		"the string NULL is a string":        {`NULL`, false, schema.ColTypeString, "NULL", nil},
		"number on an integer column":        {`-1`, false, schema.ColTypeInteger, int64(-1), nil},
		"number on a string column":          {`7`, false, schema.ColTypeString, "7", nil},
		"decimal is padded":                  {`1.500000000000000000000000000000`, false, schema.ColTypeNumeric, 1.5, nil},
		"boolean true":                       {`1`, false, schema.ColTypeBoolean, true, nil},
		"boolean false":                      {`0`, false, schema.ColTypeBoolean, false, nil},
		"1 on an integer column":             {`1`, false, schema.ColTypeInteger, int64(1), nil},
		"datetime literal":                   {`2020-01-01 00:00:00.000000`, false, schema.ColTypeDateTime, "2020-01-01 00:00:00.000000", nil},
		"text literal, escaped twice":        {`_utf8mb4\'it\\\'s\'`, true, schema.ColTypeText, "it's", nil},
		"backslash in a text literal":        {`_utf8mb4\'a\\\\b\'`, true, schema.ColTypeText, `a\b`, nil},
		"introducer names the connection":    {`_latin1\'{}\'`, true, schema.ColTypeJson, "{}", nil},
		"parenthesized number":               {`7`, true, schema.ColTypeInteger, int64(7), nil},
		"parenthesized boolean":              {`true`, true, schema.ColTypeBoolean, true, nil},
		"function":                           {`uuid()`, true, schema.ColTypeString, nil, my("uuid()")},
		"parenthesized now":                  {`now(6)`, true, schema.ColTypeDateTime, nil, my("now(6)")},
		"bare CURRENT_TIMESTAMP":             {`CURRENT_TIMESTAMP(6)`, true, schema.ColTypeDateTime, nil, my("now(6)")},
		"bare CURRENT_TIMESTAMP, no fsp":     {`CURRENT_TIMESTAMP`, true, schema.ColTypeDateTime, nil, my("now()")},
		"arithmetic":                         {`(1 + 1)`, true, schema.ColTypeInteger, nil, my("1 + 1")},
		"introducers inside an expression":   {`concat(_utf8mb4\'a\',_utf8mb4\'b\')`, true, schema.ColTypeString, nil, my("concat('a','b')")},
		"underscore inside a string is kept": {`concat(_utf8mb4\'x _b\',col_a)`, true, schema.ColTypeString, nil, my("concat('x _b',col_a)")},
	} {
		text := tc.stored
		if tc.generated {
			text = unescapeStoredExpression(text)
		}
		gotDefault, gotOverride := mysqlDefaultFromStored(text, tc.generated, tc.ct)
		if !reflect.DeepEqual(gotDefault, tc.wantDefault) || !reflect.DeepEqual(gotOverride, tc.wantOverride) {
			t.Errorf("%s: %q -> Default %#v, Overrides %v; want %#v, %v", name, tc.stored, gotDefault, gotOverride, tc.wantDefault, tc.wantOverride)
		}
	}
}

func TestMapMySQLType(t *testing.T) {
	for _, tc := range []struct {
		dataType, columnType string
		want                 schema.ColumnType
		ambiguous            bool
	}{
		{"varchar", "varchar(40)", schema.ColTypeString, false},
		{"char", "char(36)", schema.ColTypeString, false},
		{"longtext", "longtext", schema.ColTypeText, false},
		{"tinyint", "tinyint(1)", schema.ColTypeBoolean, false},
		{"tinyint", "tinyint", schema.ColTypeInteger, false},
		{"tinyint", "tinyint(1) unsigned", schema.ColTypeBoolean, false},
		{"int", "int", schema.ColTypeInteger, false},
		{"bigint", "bigint unsigned", schema.ColTypeBigInt, false},
		{"double", "double", schema.ColTypeReal, false},
		{"decimal", "decimal(65,30)", schema.ColTypeNumeric, false},
		{"datetime", "datetime(6)", schema.ColTypeDateTime, false},
		{"timestamp", "timestamp", schema.ColTypeDateTime, false},
		{"json", "json", schema.ColTypeJson, false},
		{"longblob", "longblob", schema.ColTypeBlob, false},
		{"varbinary", "varbinary(16)", schema.ColTypeBytes, false},
		{"enum", "enum('a','b')", schema.ColTypeText, true},
		{"date", "date", schema.ColTypeText, true},
		{"bit", "bit(1)", schema.ColTypeText, true},
	} {
		got, ambig := mapMySQLType(tc.dataType, tc.columnType)
		if got != tc.want || (ambig != nil) != tc.ambiguous {
			t.Errorf("mapMySQLType(%q, %q) = %q, ambiguous %v; want %q, %v", tc.dataType, tc.columnType, got, ambig != nil, tc.want, tc.ambiguous)
		}
	}
}

// Every canonical type must survive render -> reverse mapping as the type
// NormalizeColumn predicts, or the column would differ on every run.
func TestRenderedTypesReadBackAsNormalized(t *testing.T) {
	d := NewMySQLDriver(nil, nil)
	for _, ct := range []schema.ColumnType{
		schema.ColTypeString, schema.ColTypeText, schema.ColTypeInteger, schema.ColTypeBigInt, schema.ColTypeReal,
		schema.ColTypeNumeric, schema.ColTypeBoolean, schema.ColTypeDateTime, schema.ColTypeTimestamp, schema.ColTypeUuid,
		schema.ColTypeJson, schema.ColTypeBytes, schema.ColTypeBlob,
	} {
		native, err := renderMySQLType(ct, 0)
		if err != nil {
			t.Errorf("%s: %v", ct, err)
			continue
		}
		columnType := strings.ToLower(native)
		dataType, _, _ := strings.Cut(columnType, "(")
		got, ambig := mapMySQLType(dataType, columnType)
		want := d.NormalizeColumn("t", schema.Column{Name: "c", Type: ct}).Type
		if ambig != nil || got != want {
			t.Errorf("%s renders as %s, which reads back as %q (ambiguous %v); NormalizeColumn says %q", ct, native, got, ambig != nil, want)
		}
	}
}

func TestUniqueKeyName(t *testing.T) {
	if got := uniqueKeyName("users", "email"); got != "users_email_key" {
		t.Errorf("short name: got %q", got)
	}
	table, column := strings.Repeat("t", 40), strings.Repeat("c", 40)
	long := uniqueKeyName(table, column)
	if len(long) != maxIdentifierLength {
		t.Errorf("long name is %d characters, want %d", len(long), maxIdentifierLength)
	}
	if long != uniqueKeyName(table, column) {
		t.Error("the name must be the same every time")
	}
	if other := uniqueKeyName(table, column+"x"); other == long {
		t.Error("names that only differ past the cut must stay distinct")
	}
}

func TestRenderDefaultExpr(t *testing.T) {
	for name, tc := range map[string]struct {
		col  schema.Column
		want string
	}{
		"string":           {schema.Column{Type: schema.ColTypeString, Default: `it's a\b`}, `'it''s a\\b'`},
		"bool":             {schema.Column{Type: schema.ColTypeBoolean, Default: false}, "FALSE"},
		"number":           {schema.Column{Type: schema.ColTypeInteger, Default: float64(7)}, "7"},
		"text literal":     {schema.Column{Type: schema.ColTypeText, Default: "x"}, "('x')"},
		"number on text":   {schema.Column{Type: schema.ColTypeText, Default: -1}, "('-1')"},
		"json literal":     {schema.Column{Type: schema.ColTypeJson, Default: "{}"}, "('{}')"},
		"expression":       {schema.Column{Type: schema.ColTypeDateTime, Overrides: map[string]schema.ColumnOverride{DriverName: {Default: "now(6)"}}}, "(now(6))"},
		"no default":       {schema.Column{Type: schema.ColTypeString}, ""},
		"override to text": {schema.Column{Type: schema.ColTypeString, Default: "x", Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}}, "('x')"},
	} {
		got, err := renderDefaultExpr(tc.col)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, tc.want)
		}
	}
	if _, err := renderDefaultExpr(schema.Column{Type: schema.ColTypeString, Default: []string{"x"}}); err == nil {
		t.Error("a default that isn't a literal must be an error")
	}
}
