package engine

import (
	"testing"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissionPlugin declares permissions and does nothing else.
type permissionPlugin struct {
	name  string
	perms []core.PermissionDef
}

func (p *permissionPlugin) Meta() core.PluginMeta            { return core.PluginMeta{Name: p.name} }
func (p *permissionPlugin) Version() string                  { return "test" }
func (p *permissionPlugin) Init(*core.AuthContext) error     { return nil }
func (p *permissionPlugin) Routes() []core.Route             { return nil }
func (p *permissionPlugin) Middlewares() []core.Middleware   { return nil }
func (p *permissionPlugin) Register(core.HookRegistry) error { return nil }
func (p *permissionPlugin) Declare(ic *core.PluginInitContext) error {
	for _, def := range p.perms {
		if err := ic.Permissions.Declare(def); err != nil {
			return err
		}
	}
	return nil
}

func TestPreparePermissions(t *testing.T) {
	change := core.PermissionDef{Name: "email:change", Kind: core.PermissionSelf, Description: "Change the account's email address", Owner: "someone-else"}
	app, err := Prepare([]core.Plugin{&permissionPlugin{name: "mail", perms: []core.PermissionDef{change}}}, PrepareConfig{})
	require.NoError(t, err)

	got, ok := app.Permissions.Lookup("email:change")
	require.True(t, ok)
	assert.Equal(t, "mail", got.Owner, "the declarer is the owner, whatever it claims")

	_, err = Prepare([]core.Plugin{
		&permissionPlugin{name: "first", perms: []core.PermissionDef{change}},
		&permissionPlugin{name: "second", perms: []core.PermissionDef{change}},
	}, PrepareConfig{})
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "a name has one owner: got %v", err)

	late := core.PermissionDef{Name: "phone:change", Kind: core.PermissionSelf, Description: "Change the phone number"}
	err = (&scopedPermissionCatalog{inner: app.Permissions, owner: "late"}).Declare(late)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "frozen after Prepare: got %v", err)
}
