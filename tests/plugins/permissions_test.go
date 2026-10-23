package plugins_test

import (
	"context"
	"testing"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/identity"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/emailverification"
	"github.com/go-behemoth/behemoth/plugins/phonenumber"
	"github.com/go-behemoth/behemoth/plugins/username"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Core and each plugin declare the permissions their flows require, under
// their own names and with their kind, and Prepare freezes the catalog with
// them.
func TestFlowsDeclareTheirPermissions(t *testing.T) {
	passwords := emailpassword.New(emailpassword.Options{})
	app, err := engine.Prepare([]core.Plugin{
		passwords,
		emailverification.New(changeOptions()),
		phonenumber.New(passwords, phonenumber.Options{}),
		username.New(passwords, username.Options{}),
	}, engine.PrepareConfig{})
	require.NoError(t, err)

	type declared struct {
		owner string
		kind  core.PermissionKind
	}
	got := map[core.Permission]declared{}
	for _, def := range app.Permissions.All() {
		assert.NotEmpty(t, def.Description, def.Name)
		got[def.Name] = declared{def.Owner, def.Kind}
	}
	self, admin := core.PermissionSelf, core.PermissionAdmin
	assert.Equal(t, map[core.Permission]declared{
		core.PermissionSessionTokenIssue:        {"core", self},
		emailpassword.PermissionSignOut:         {emailpassword.PluginName, self},
		emailpassword.PermissionSetPassword:     {emailpassword.PluginName, admin},
		emailverification.PermissionEmailChange: {emailverification.PluginName, self},
		phonenumber.PermissionPhoneChange:       {phonenumber.PluginName, self},
		phonenumber.PermissionSetPhone:          {phonenumber.PluginName, admin},
		phonenumber.PermissionAddPhone:          {phonenumber.PluginName, admin},
		username.PermissionSetUsername:          {username.PluginName, admin},
	}, got)
}

// An admin operation lets through a system caller only. A signed-in user is
// forbidden with insufficient_scope, an anonymous caller gets the session
// error, and a job acting for a user holds no admin permission.
// SetPasswordUnchecked, for a plugin that has its own proof, checks nothing.
func TestAdminOperationsRequireAPrivilegedCaller(t *testing.T) {
	ctx := context.Background()
	ac, p, _ := bootedPlugin(t, nil, nil)
	_, err := p.SignUp(ctx, behemoth.M{"email": "ada@example.com", "password": "correct horse"})
	require.NoError(t, err)
	signedIn, err := p.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"})
	require.NoError(t, err)
	userID := signedIn.User.ID

	_, err = p.SetPassword(presenting(ctx, ac, signedIn.RawToken), userID, "another password")
	assert.True(t, errs.IsCategory(err, errs.CategoryForbidden), "a signed-in user: %v", err)
	assert.True(t, errs.IsCode(err, errs.CodeInsufficientScope), "%v", err)
	_, err = p.SetPassword(ctx, userID, "another password")
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "an anonymous caller: %v", err)
	_, err = p.SetPassword(actingFor(ctx, userID), userID, "another password")
	assert.True(t, errs.IsCode(err, errs.CodeInsufficientScope), "a job acting for the user: %v", err)

	_, err = p.SetPassword(asAdmin(ctx), userID, "another password")
	require.NoError(t, err, "a system caller")
	_, err = p.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "another password"})
	require.NoError(t, err, "the password was set")

	_, err = p.SetPasswordUnchecked(ctx, userID, "a third password")
	require.NoError(t, err, "the unchecked step needs no caller")
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
