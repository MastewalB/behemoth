package auth

import (
	"testing"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionCatalogDeclare(t *testing.T) {
	valid := core.PermissionDef{Name: "email:change", Kind: core.PermissionSelf, Description: "Change the account's email address", Owner: "emailverification"}

	for name, mutate := range map[string]func(*core.PermissionDef){
		"no colon":        func(d *core.PermissionDef) { d.Name = "emailchange" },
		"upper case":      func(d *core.PermissionDef) { d.Name = "Email:Change" },
		"a dot":           func(d *core.PermissionDef) { d.Name = "email.change" },
		"two colons":      func(d *core.PermissionDef) { d.Name = "a:b:c" },
		"empty":           func(d *core.PermissionDef) { d.Name = "" },
		"no kind":         func(d *core.PermissionDef) { d.Kind = "" },
		"an unknown kind": func(d *core.PermissionDef) { d.Kind = "owner" },
		"no description":  func(d *core.PermissionDef) { d.Description = "" },
		"no owner":        func(d *core.PermissionDef) { d.Owner = "" },
	} {
		t.Run(name, func(t *testing.T) {
			def := valid
			mutate(&def)
			err := NewDefaultPermissionCatalog().Declare(def)
			assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
		})
	}

	catalog := NewDefaultPermissionCatalog()
	require.NoError(t, catalog.Declare(valid))
	require.NoError(t, catalog.Declare(core.PermissionDef{Name: "session_token:issue", Kind: core.PermissionSelf, Description: "Get tokens for other services", Owner: "core"}))

	other := valid
	other.Owner = "another"
	assert.True(t, errs.IsCategory(catalog.Declare(other), errs.CategoryConfiguration), "a name has one owner")

	got, ok := catalog.Lookup("email:change")
	require.True(t, ok)
	assert.Equal(t, valid, got)
	_, ok = catalog.Lookup("email:delete")
	assert.False(t, ok)

	all := catalog.All()
	require.Len(t, all, 2)
	assert.Equal(t, core.Permission("email:change"), all[0].Name, "ordered by name")
	assert.Equal(t, core.Permission("session_token:issue"), all[1].Name)

	catalog.Freeze()
	late := core.PermissionDef{Name: "phone:change", Kind: core.PermissionSelf, Description: "Change the phone number", Owner: "phonenumber"}
	assert.True(t, errs.IsCategory(catalog.Declare(late), errs.CategoryConfiguration), "frozen")
}
