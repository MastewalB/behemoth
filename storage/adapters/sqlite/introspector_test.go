package sqlite

import (
	"reflect"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestNormalizeColumn(t *testing.T) {
	yes := true
	d := NewSQLiteDriver(nil, nil)

	for name, tc := range map[string]struct {
		declared, want schema.Column
	}{
		"uuid is BLOB": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			schema.Column{Name: "u", Type: schema.ColTypeBlob, Nullable: true},
		},
		"bytes is BLOB": {
			schema.Column{Name: "b", Type: schema.ColTypeBytes},
			schema.Column{Name: "b", Type: schema.ColTypeBlob},
		},
		"json is TEXT": {
			schema.Column{Name: "j", Type: schema.ColTypeJson},
			schema.Column{Name: "j", Type: schema.ColTypeText},
		},
		"string without a length is VARCHAR(255)": {
			schema.Column{Name: "s", Type: schema.ColTypeString},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 255},
		},
		"string with a length keeps it": {
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
			schema.Column{Name: "s", Type: schema.ColTypeString, Length: 40},
		},
		"only VARCHAR carries a length": {
			schema.Column{Name: "t", Type: schema.ColTypeText, Length: 10},
			schema.Column{Name: "t", Type: schema.ColTypeText},
		},
		"AUTOINCREMENT is always INTEGER": {
			schema.Column{Name: "id", Type: schema.ColTypeBigInt, PrimaryKey: true, AutoInc: true},
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true},
		},
		"primary key is never NULL and not separately UNIQUE": {
			schema.Column{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true, Nullable: true, Unique: true},
			schema.Column{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
		},
		"override type replaces the declared one": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}},
			schema.Column{Name: "u", Type: schema.ColTypeText, Overrides: map[string]schema.ColumnOverride{DriverName: {Type: schema.ColTypeText}}},
		},
		"override AutoInc replaces the declared one": {
			schema.Column{Name: "id", Type: schema.ColTypeBigInt, PrimaryKey: true, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
			schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true, Overrides: map[string]schema.ColumnOverride{DriverName: {AutoInc: &yes}}},
		},
		"other drivers' overrides are ignored": {
			schema.Column{Name: "u", Type: schema.ColTypeUuid, Overrides: map[string]schema.ColumnOverride{"postgres": {Type: schema.ColTypeText}}},
			schema.Column{Name: "u", Type: schema.ColTypeBlob, Overrides: map[string]schema.ColumnOverride{"postgres": {Type: schema.ColTypeText}}},
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
	d := NewSQLiteDriver(nil, nil)
	lite := func(expr string) map[string]schema.ColumnOverride {
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
		"bool on boolean column": {schema.Column{Type: schema.ColTypeBoolean, Default: true}, true, nil},
		"bool on integer column": {schema.Column{Type: schema.ColTypeInteger, Default: true}, int64(1), nil},
		"no default":             {schema.Column{Type: schema.ColTypeText}, nil, nil},
		"keyword expression":     {schema.Column{Type: schema.ColTypeTimestamp, Overrides: lite("CURRENT_TIMESTAMP")}, nil, lite("CURRENT_TIMESTAMP")},
		"function expression":    {schema.Column{Type: schema.ColTypeDateTime, Overrides: lite("datetime('now')")}, nil, lite("datetime('now')")},
		"quoted literal as expr": {schema.Column{Type: schema.ColTypeText, Overrides: lite("'{}'")}, "{}", nil},
		"override wins over literal": {
			schema.Column{Type: schema.ColTypeTimestamp, Default: "2020-01-01", Overrides: lite("CURRENT_TIMESTAMP")}, nil, lite("CURRENT_TIMESTAMP")},
		"other drivers' expressions don't apply": {
			schema.Column{Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{"postgres": {Default: "now()"}}}, nil, nil},
	} {
		got := d.NormalizeColumn("t", tc.declared)
		if !reflect.DeepEqual(got.Default, tc.wantDefault) || !reflect.DeepEqual(got.Overrides, tc.wantOverride) {
			t.Errorf("%s: got Default %#v, Overrides %v; want %#v, %v", name, got.Default, got.Overrides, tc.wantDefault, tc.wantOverride)
		}
	}
}
