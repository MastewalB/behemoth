package models

import (
	"sort"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types/schema"
)

// Each declared table lists exactly its model's own columns — the ones its
// ToMap writes and its FromMap reads into fields (not extras).
func TestDeclaredTablesMatchModels(t *testing.T) {
	for _, tc := range []struct {
		table schema.Table
		model behemoth.Model
		own   map[string]bool
	}{
		{UserTableSchema(), &User{}, userColumns},
		{SessionTableSchema(), &Session{}, sessionColumns},
		{TokenTableSchema(), &Token{}, tokenColumns},
		{AccountTableSchema(), &Account{}, accountColumns},
		{RateLimitTableSchema(), &RateLimit{}, rateLimitColumns},
	} {
		if tc.table.Name != tc.model.SchemaName() {
			t.Errorf("table %q declared for model %q", tc.table.Name, tc.model.SchemaName())
		}
		var declared, own, mapped []string
		for _, c := range tc.table.Columns {
			declared = append(declared, c.Name)
		}
		for c := range tc.own {
			own = append(own, c)
		}
		row, err := tc.model.(behemoth.Serializable).ToMap()
		if err != nil {
			t.Fatal(err)
		}
		for c := range row {
			mapped = append(mapped, c)
		}
		sort.Strings(declared)
		sort.Strings(own)
		sort.Strings(mapped)
		if !equal(declared, own) || !equal(declared, mapped) {
			t.Errorf("%s:\n declared %v\n own      %v\n ToMap    %v", tc.table.Name, declared, own, mapped)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
