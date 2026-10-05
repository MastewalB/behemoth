package sqlserver

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestNormalizeColumn(t *testing.T) {
	yes := true
	d := NewSQLServerDriver(nil, nil)

	for name, tc := range map[string]struct {
		declared, want schema.Column
	}{
		"string without a length is NVARCHAR(255)": {
			schema.Column{Name: "s", Type: schema.ColTypeString},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 255},
		},
		"string with a length keeps it": {
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
		},
		"string over 4000 is NVARCHAR(MAX), read back as text": {
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 4001},
			schema.Column{Name: "s", Type: schema.ColTypeText},
		},
		"uuid is NCHAR(36), read back as a string": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			schema.Column{Name: "u", Type: schema.ColTypeString, Length: 36, Nullable: true},
		},
		"json is NVARCHAR(MAX), read back as text": {
			schema.Column{Name: "j", Type: schema.ColTypeJson},
			schema.Column{Name: "j", Type: schema.ColTypeText},
		},
		"bytes is VARBINARY(MAX), read back as blob": {
			schema.Column{Name: "b", Type: schema.ColTypeBytes, Nullable: true},
			schema.Column{Name: "b", Type: schema.ColTypeBlob, Nullable: true},
		},
		"timestamp stays a timestamp": {
			schema.Column{Name: "ts", Type: schema.ColTypeTimestamp},
			schema.Column{Name: "ts", Type: schema.ColTypeTimestamp},
		},
		"only strings carry a length": {
			schema.Column{Name: "t", Type: schema.ColTypeText, Length: 10},
			schema.Column{Name: "t", Type: schema.ColTypeText},
		},
		"primary key is NOT NULL and not separately UNIQUE": {
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, Nullable: true, Unique: true},
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		},
		"identity is NOT NULL": {
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, AutoInc: true, Nullable: true},
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, AutoInc: true},
		},
		"override type replaces the declared one": {
			schema.Column{Name: "o", Type: schema.ColTypeText, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeString}}},
			schema.Column{Name: "o", Type: schema.ColTypeString, Length: 255},
		},
		"override AutoInc replaces the declared one": {
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, AutoInc: true},
		},
		"other drivers' overrides are ignored": {
			schema.Column{Name: "r", Type: schema.ColTypeReal, Overrides: map[string]schema.ColumnOverride{"sqlite": {Type: schema.ColTypeText}}},
			schema.Column{Name: "r", Type: schema.ColTypeReal},
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
	d := NewSQLServerDriver(nil, nil)
	ms := func(expr string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{DriverName: {Default: expr}}
	}
	for name, tc := range map[string]struct {
		declared     schema.Column
		wantDefault  any
		wantOverride map[string]schema.ColumnOverride
	}{
		"string literal":                  {schema.Column{Type: schema.ColTypeText, Default: "it's"}, "it's", nil},
		"empty string":                    {schema.Column{Type: schema.ColTypeString, Default: ""}, "", nil},
		"integer literal":                 {schema.Column{Type: schema.ColTypeInteger, Default: 7}, int64(7), nil},
		"float64 from JSON":               {schema.Column{Type: schema.ColTypeInteger, Default: float64(7)}, int64(7), nil},
		"negative integer":                {schema.Column{Type: schema.ColTypeInteger, Default: -1}, int64(-1), nil},
		"fraction":                        {schema.Column{Type: schema.ColTypeReal, Default: 1.5}, 1.5, nil},
		"bool":                            {schema.Column{Type: schema.ColTypeBoolean, Default: true}, true, nil},
		"1 on a boolean column":           {schema.Column{Type: schema.ColTypeBoolean, Default: 1}, true, nil},
		"1 on an integer column":          {schema.Column{Type: schema.ColTypeInteger, Default: 1}, int64(1), nil},
		"no default":                      {schema.Column{Type: schema.ColTypeText}, nil, nil},
		"function expression":             {schema.Column{Type: schema.ColTypeTimestamp, Overrides: ms("sysdatetimeoffset()")}, nil, ms("sysdatetimeoffset()")},
		"CURRENT_TIMESTAMP":               {schema.Column{Type: schema.ColTypeDateTime, Overrides: ms("CURRENT_TIMESTAMP")}, nil, ms("getdate()")},
		"redundant parentheses":           {schema.Column{Type: schema.ColTypeDateTime, Overrides: ms("((getdate()))")}, nil, ms("getdate()")},
		"quoted literal as expr":          {schema.Column{Type: schema.ColTypeString, Overrides: ms("N'x'")}, "x", nil},
		"number as expr":                  {schema.Column{Type: schema.ColTypeInteger, Overrides: ms("((7))")}, int64(7), nil},
		"NULL expression":                 {schema.Column{Type: schema.ColTypeText, Overrides: ms("NULL")}, nil, nil},
		"concatenation is not one string": {schema.Column{Type: schema.ColTypeText, Overrides: ms("'a'+'b'")}, nil, ms("'a'+'b'")},
		"override wins over literal": {
			schema.Column{Type: schema.ColTypeTimestamp, Default: "2020-01-01", Overrides: ms("sysdatetimeoffset()")}, nil, ms("sysdatetimeoffset()")},
		"other drivers' expressions don't apply": {
			schema.Column{Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{"postgres": {Default: "now()"}}}, nil, nil},
		"identity has no default": {
			schema.Column{Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true, Default: 1}, nil, nil},
	} {
		got := d.NormalizeColumn("t", tc.declared)
		if !reflect.DeepEqual(got.Default, tc.wantDefault) || !reflect.DeepEqual(got.Overrides, tc.wantOverride) {
			t.Errorf("%s: got Default %#v, Overrides %v; want %#v, %v", name, got.Default, got.Overrides, tc.wantDefault, tc.wantOverride)
		}
	}
}

// The stored forms below were read from sys.default_constraints.definition
// on SQL Server 2019.
func TestSQLServerDefaultFromStored(t *testing.T) {
	ms := func(expr string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{DriverName: {Default: expr}}
	}
	for name, tc := range map[string]struct {
		stored       string
		ct           schema.ColumnType
		wantDefault  any
		wantOverride map[string]schema.ColumnOverride
	}{
		"unicode string":       {`(N'it''s')`, schema.ColTypeString, "it's", nil},
		"plain string":         {`('x')`, schema.ColTypeString, "x", nil},
		"empty string":         {`(N'')`, schema.ColTypeString, "", nil},
		"string with a paren":  {`(N'a) (b')`, schema.ColTypeText, "a) (b", nil},
		"number":               {`((7))`, schema.ColTypeInteger, int64(7), nil},
		"negative number":      {`((-1))`, schema.ColTypeInteger, int64(-1), nil},
		"fraction":             {`((1.50))`, schema.ColTypeReal, 1.5, nil},
		"bit true":             {`((1))`, schema.ColTypeBoolean, true, nil},
		"bit false":            {`((0))`, schema.ColTypeBoolean, false, nil},
		"date literal":         {`('2020-01-01')`, schema.ColTypeDateTime, "2020-01-01", nil},
		"function":             {`(getdate())`, schema.ColTypeDateTime, nil, ms("getdate()")},
		"function, other case": {`(sysdatetimeoffset())`, schema.ColTypeTimestamp, nil, ms("sysdatetimeoffset()")},
		"arithmetic":           {`((1)+(1))`, schema.ColTypeInteger, nil, ms("(1)+(1)")},
		"convert":              {`(CONVERT([nvarchar](10),(5)))`, schema.ColTypeString, nil, ms("CONVERT([nvarchar](10),(5))")},
		"NULL":                 {`(NULL)`, schema.ColTypeString, nil, nil},
	} {
		gotDefault, gotOverride := sqlServerDefaultFromStored(tc.stored, tc.ct)
		if !reflect.DeepEqual(gotDefault, tc.wantDefault) || !reflect.DeepEqual(gotOverride, tc.wantOverride) {
			t.Errorf("%s: %q -> Default %#v, Overrides %v; want %#v, %v", name, tc.stored, gotDefault, gotOverride, tc.wantDefault, tc.wantOverride)
		}
	}
}

func TestMapSQLServerType(t *testing.T) {
	for _, tc := range []struct {
		typeName   string
		maxLength  int
		want       schema.ColumnType
		wantLength int
		ambiguous  bool
	}{
		{"nvarchar", 80, schema.ColTypeString, 40, false},
		{"nchar", 72, schema.ColTypeString, 36, false},
		{"varchar", 100, schema.ColTypeString, 100, false},
		{"nvarchar", -1, schema.ColTypeText, 0, false},
		{"varchar", -1, schema.ColTypeText, 0, false},
		{"ntext", 16, schema.ColTypeText, 0, false},
		{"tinyint", 1, schema.ColTypeInteger, 0, false},
		{"bigint", 8, schema.ColTypeBigInt, 0, false},
		{"float", 8, schema.ColTypeReal, 0, false},
		{"money", 8, schema.ColTypeNumeric, 0, false},
		{"bit", 1, schema.ColTypeBoolean, 0, false},
		{"datetime", 8, schema.ColTypeDateTime, 0, false},
		{"datetime2", 8, schema.ColTypeDateTime, 0, false},
		{"datetimeoffset", 10, schema.ColTypeTimestamp, 0, false},
		{"uniqueidentifier", 16, schema.ColTypeUuid, 0, false},
		{"varbinary", -1, schema.ColTypeBlob, 0, false},
		{"varbinary", 16, schema.ColTypeBytes, 0, false},
		{"date", 3, schema.ColTypeText, 0, true},
		{"xml", -1, schema.ColTypeText, 0, true},
		{"timestamp", 8, schema.ColTypeText, 0, true}, // rowversion, not a time
	} {
		got, length, ambig := mapSQLServerType(tc.typeName, tc.maxLength)
		if got != tc.want || length != tc.wantLength || (ambig != nil) != tc.ambiguous {
			t.Errorf("mapSQLServerType(%q, %d) = %q, %d, ambiguous %v; want %q, %d, %v",
				tc.typeName, tc.maxLength, got, length, ambig != nil, tc.want, tc.wantLength, tc.ambiguous)
		}
	}
}

// A table rebuild recreates untouched columns from the catalog; the
// definition has to say what the catalog said.
func TestNativeDefinition(t *testing.T) {
	for want, c := range map[string]liveColumn{
		"NVARCHAR(40) NOT NULL":                        {typeName: "nvarchar", maxLength: 80},
		"NVARCHAR(MAX) NULL":                           {typeName: "nvarchar", maxLength: -1, nullable: true},
		"VARCHAR(20) NOT NULL DEFAULT ('none')":        {typeName: "varchar", maxLength: 20, defaultDef: sql.NullString{String: "('none')", Valid: true}},
		"VARBINARY(MAX) NULL":                          {typeName: "varbinary", maxLength: -1, nullable: true},
		"DECIMAL(38,10) NULL":                          {typeName: "decimal", maxLength: 17, precision: 38, scale: 10, nullable: true},
		"DATETIME2(6) NOT NULL":                        {typeName: "datetime2", maxLength: 8, precision: 26, scale: 6},
		"DATETIME NOT NULL DEFAULT (getdate())":        {typeName: "datetime", maxLength: 8, defaultDef: sql.NullString{String: "(getdate())", Valid: true}},
		"FLOAT(53) NULL":                               {typeName: "float", maxLength: 8, precision: 53, nullable: true},
		"MONEY NULL":                                   {typeName: "money", maxLength: 8, precision: 19, scale: 4, nullable: true},
		"BIGINT IDENTITY(100,5) NOT NULL":              {typeName: "bigint", maxLength: 8, identity: true, seed: "100", step: "5"},
		"NVARCHAR(10) COLLATE Latin1_General_BIN NULL": {typeName: "nvarchar", maxLength: 20, nullable: true, collation: sql.NullString{String: "Latin1_General_BIN", Valid: true}},
	} {
		if got := c.nativeDefinition(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestIndexSQL(t *testing.T) {
	nullable := map[string]bool{"a": true, "b": false, "c": true}
	for want, got := range map[string]string{
		"CREATE INDEX [i] ON [t] ([a], [b])":                                                       indexSQL("t", "i", []string{"a", "b"}, false, nullable),
		"CREATE UNIQUE INDEX [i] ON [t] ([b])":                                                     indexSQL("t", "i", []string{"b"}, true, nullable),
		"CREATE UNIQUE INDEX [i] ON [t] ([a], [b], [c]) WHERE [a] IS NOT NULL AND [c] IS NOT NULL": indexSQL("t", "i", []string{"a", "b", "c"}, true, nullable),
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// isNullFilter has to recognize the filter indexSQL writes, in the form SQL
// Server stores it, and nothing else.
func TestIsNullFilter(t *testing.T) {
	for _, tc := range []struct {
		filter  string
		columns []string
		want    bool
	}{
		{"", []string{"a"}, true},
		{"([a] IS NOT NULL)", []string{"a"}, true},
		{"([a] IS NOT NULL AND [b] IS NOT NULL)", []string{"a", "b", "c"}, true},
		{"([i]>(5))", []string{"i"}, false},
		{"([x] IS NOT NULL)", []string{"a"}, false}, // not a key column
		{"([a] IS NOT NULL AND [a]>(5))", []string{"a"}, false},
	} {
		if got := isNullFilter(tc.filter, tc.columns); got != tc.want {
			t.Errorf("isNullFilter(%q, %v) = %v, want %v", tc.filter, tc.columns, got, tc.want)
		}
	}
}

func TestUniqueKeyName(t *testing.T) {
	if got := uniqueKeyName("users", "email"); got != "users_email_key" {
		t.Errorf("short name: got %q", got)
	}
	table, column := strings.Repeat("t", 80), strings.Repeat("c", 80)
	long := uniqueKeyName(table, column)
	if len(long) != maxIdentifierLength {
		t.Errorf("long name is %d characters, want %d", len(long), maxIdentifierLength)
	}
	if other := uniqueKeyName(table, column+"x"); other == long {
		t.Error("names that only differ past the cut must stay distinct")
	}
}

// Every canonical type must survive render -> reverse mapping as the type
// NormalizeColumn predicts, or the column would differ on every run.
func TestRenderedTypesReadBackAsNormalized(t *testing.T) {
	d := NewSQLServerDriver(nil, nil)
	for _, ct := range []schema.ColumnType{
		schema.ColTypeString, schema.ColTypeText, schema.ColTypeInteger, schema.ColTypeBigInt, schema.ColTypeReal,
		schema.ColTypeNumeric, schema.ColTypeBoolean, schema.ColTypeDateTime, schema.ColTypeTimestamp, schema.ColTypeUuid,
		schema.ColTypeJson, schema.ColTypeBytes, schema.ColTypeBlob,
	} {
		native, err := renderSQLServerType(ct, 0)
		if err != nil {
			t.Errorf("%s: %v", ct, err)
			continue
		}
		typeName, size, _ := strings.Cut(strings.ToLower(native), "(")
		maxLength := 8
		switch {
		case strings.HasPrefix(size, "max"):
			maxLength = -1
		case typeName == "nvarchar":
			maxLength = 510
		case typeName == "nchar":
			maxLength = 72
		}
		got, _, ambig := mapSQLServerType(typeName, maxLength)
		want := d.NormalizeColumn("t", schema.Column{Name: "c", Type: ct}).Type
		if ambig != nil || got != want {
			t.Errorf("%s renders as %s, which reads back as %q (ambiguous %v); NormalizeColumn says %q", ct, native, got, ambig != nil, want)
		}
	}
}
