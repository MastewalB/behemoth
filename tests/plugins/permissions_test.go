package plugins_test

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/engine"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/emailverification"
	"github.com/MastewalB/behemoth/plugins/phonenumber"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Core and each plugin declare the permissions their self-service flows
// require, under their own names, and Prepare freezes the catalog with them.
func TestFlowsDeclareTheirPermissions(t *testing.T) {
	passwords := emailpassword.New(emailpassword.Options{})
	app, err := engine.Prepare([]core.Plugin{
		passwords,
		emailverification.New(changeOptions()),
		phonenumber.New(passwords, phonenumber.Options{}),
	}, engine.PrepareConfig{})
	require.NoError(t, err)

	got := map[core.Permission]string{}
	for _, def := range app.Permissions.All() {
		assert.Equal(t, core.PermissionSelf, def.Kind, def.Name)
		assert.NotEmpty(t, def.Description, def.Name)
		got[def.Name] = def.Owner
	}
	assert.Equal(t, map[core.Permission]string{
		core.PermissionSessionTokenIssue:        "core",
		emailpassword.PermissionSignOut:         emailpassword.PluginName,
		emailverification.PermissionEmailChange: emailverification.PluginName,
		phonenumber.PermissionPhoneChange:       phonenumber.PluginName,
	}, got)
}

// SignOut ends the session of the caller on the context, whatever reached
// it. A caller without a session has nothing to end, and a system caller
// that names no user is a mistake in the code that calls the flow.
func TestSignOutEndsTheCallersSession(t *testing.T) {
	ctx := context.Background()
	ac, p, _ := bootedPlugin(t, nil, nil)
	_, err := p.SignUp(ctx, behemoth.M{"email": "ada@example.com", "password": "correct horse"})
	require.NoError(t, err)
	signedIn, err := p.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"})
	require.NoError(t, err)

	err = p.SignOut(ctx)
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "an anonymous caller: %v", err)
	err = p.SignOut(actingFor(ctx, signedIn.User.ID))
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "a job acting for the user has no session: %v", err)
	err = p.SignOut(identity.WithCaller(ctx, identity.System("job")))
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "a system caller for nobody: %v", err)
	_, err = ac.SessionManager.Validate(ctx, signedIn.RawToken)
	require.NoError(t, err, "no refused sign-out ended the session")

	require.NoError(t, p.SignOut(presenting(ctx, ac, signedIn.RawToken)))
	_, err = ac.SessionManager.Validate(ctx, signedIn.RawToken)
	assert.True(t, errs.IsCode(err, errs.CodeSessionRevoked), "the caller's session is gone: %v", err)
	err = p.SignOut(presenting(ctx, ac, signedIn.RawToken))
	assert.True(t, errs.IsCode(err, errs.CodeSessionRevoked), "signing out again gets the reason: %v", err)
}
