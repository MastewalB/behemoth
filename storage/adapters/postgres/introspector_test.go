package postgres

import (
	"reflect"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestNormalizeColumn(t *testing.T) {
	yes := true
	d := NewPostgreSQLDriver(nil, nil)

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
		"blob is BYTEA, read back as bytes": {
			schema.Column{Name: "b", Type: schema.ColTypeBlob, Nullable: true},
			schema.Column{Name: "b", Type: schema.ColTypeBytes, Nullable: true},
		},
		"only VARCHAR carries a length": {
			schema.Column{Name: "t", Type: schema.ColTypeText, Length: 10},
			schema.Column{Name: "t", Type: schema.ColTypeText},
		},
		"primary key is NOT NULL and not separately UNIQUE": {
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, Nullable: true, Unique: true},
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		},
		"override type replaces the declared one": {
			schema.Column{Name: "o", Type: schema.ColTypeString, Length: 40, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}},
			schema.Column{Name: "o", Type: schema.ColTypeText, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}},
		},
		"override AutoInc replaces the declared one": {
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
			schema.Column{Name: "n", Type: schema.ColTypeBigInt, AutoInc: true, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
		},
		"other drivers' overrides are ignored": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Overrides: map[string]schema.ColumnOverride{"sqlite": {Type: schema.ColTypeText}}},
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Overrides: map[string]schema.ColumnOverride{"sqlite": {Type: schema.ColTypeText}}},
		},
		"unchanged column stays unchanged": {
			schema.Column{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true, Nullable: true, Default: "x"},
			schema.Column{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true, Nullable: true, Default: "x"},
		},
	} {
		got := d.NormalizeColumn("t", tc.declared)
		if got.Name != tc.want.Name || got.PhysicalName != tc.want.PhysicalName || got.Type != tc.want.Type || got.Length != tc.want.Length ||
			got.Nullable != tc.want.Nullable || got.PrimaryKey != tc.want.PrimaryKey || got.Unique != tc.want.Unique ||
			got.AutoInc != tc.want.AutoInc || got.Default != tc.want.Default {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got, tc.want)
		}
	}
}

func TestNormalizeColumnDefaults(t *testing.T) {
	d := NewPostgreSQLDriver(nil, nil)
	pg := func(expr string) map[string]schema.ColumnOverride {
		return map[string]schema.ColumnOverride{DriverName: {Default: expr}}
	}
	for name, tc := range map[string]struct {
		declared     schema.Column
		wantDefault  any
		wantOverride map[string]schema.ColumnOverride
	}{
		"string literal":         {schema.Column{Type: schema.ColTypeText, Default: "it's"}, "it's", nil},
		"integer literal":        {schema.Column{Type: schema.ColTypeInteger, Default: 7}, int64(7), nil},
		"float64 from JSON":      {schema.Column{Type: schema.ColTypeInteger, Default: float64(7)}, int64(7), nil},
		"negative integer":       {schema.Column{Type: schema.ColTypeInteger, Default: -1}, int64(-1), nil},
		"fraction":               {schema.Column{Type: schema.ColTypeReal, Default: 1.5}, 1.5, nil},
		"bool":                   {schema.Column{Type: schema.ColTypeBoolean, Default: true}, true, nil},
		"no default":             {schema.Column{Type: schema.ColTypeText}, nil, nil},
		"function expression":    {schema.Column{Type: schema.ColTypeTimestamp, Overrides: pg("now()")}, nil, pg("now()")},
		"quoted literal as expr": {schema.Column{Type: schema.ColTypeJson, Overrides: pg("'{}'::jsonb")}, "{}", nil},
		"NULL expression":        {schema.Column{Type: schema.ColTypeText, Overrides: pg("NULL")}, nil, nil},
		"override wins over literal": {
			schema.Column{Type: schema.ColTypeTimestamp, Default: "2020-01-01", Overrides: pg("now()")}, nil, pg("now()")},
		"other drivers' expressions don't apply": {
			schema.Column{Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{"sqlite": {Default: "CURRENT_TIMESTAMP"}}}, nil, nil},
		"identity has no default": {
			schema.Column{Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true, Default: 1}, nil, nil},
	} {
		got := d.NormalizeColumn("t", tc.declared)
		if !reflect.DeepEqual(got.Default, tc.wantDefault) || !reflect.DeepEqual(got.Overrides, tc.wantOverride) {
			t.Errorf("%s: got Default %#v, Overrides %v; want %#v, %v", name, got.Default, got.Overrides, tc.wantDefault, tc.wantOverride)
		}
	}
}

// Postgres stores negative defaults quoted with a cast ('-1'::integer, and
// '-5'::integer even on a bigint column).
func TestParsePgDefaultIsTypeAware(t *testing.T) {
	for name, tc := range map[string]struct {
		expr string
		ct   schema.ColumnType
		want any
	}{
		"quoted negative on integer": {"'-1'::integer", schema.ColTypeInteger, int64(-1)},
		"quoted negative on bigint":  {"'-5'::integer", schema.ColTypeBigInt, int64(-5)},
		"quoted number on text":      {"'-1'::text", schema.ColTypeText, "-1"},
		"plain number":               {"7", schema.ColTypeInteger, int64(7)},
		"fraction":                   {"1.50", schema.ColTypeNumeric, 1.5},
		"upper-case bool":            {"TRUE", schema.ColTypeBoolean, true},
	} {
		got, isLiteral := parsePgDefault(tc.expr, tc.ct)
		if !isLiteral || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: parsePgDefault(%q) = %#v, %v; want %#v, true", name, tc.expr, got, isLiteral, tc.want)
		}
	}
}
