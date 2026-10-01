package sqlite

import (
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
