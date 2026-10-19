package plugins_test

import (
	"context"
	"errors"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/emailverification"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover what a flow reports when a hook chain stops it
// (types.FailIfRejected): a typed refusal fires the failed point with
// types.FailureRejectedByHook, whichever handler refused, and a failure of
// the system inside a handler fires nothing.

// A sign-in the email verification plugin refuses at
// auth.signIn.credentialsVerified is audited as refused by a hook. The
// reason is the cause, and its code is in the event too.
func TestSignInRefusedByAHookIsAuditedAsRejectedByHook(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{RequireVerified: true})
	user, _ := app.signUp(t, "ada@example.com", 1)

	_, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"})
	assert.True(t, errs.IsCode(err, emailverification.ErrorCodeEmailNotVerified), "the caller gets the plugin's own error: %v", err)

	events := app.rec.Audit.OfType(string(hooks.HookSignInFailed))
	require.Len(t, events, 1)
	assert.Equal(t, models.UserTable, events[0].SubjectType)
	assert.Equal(t, user.ID, events[0].SubjectID)
	assert.Equal(t, types.FailureRejectedByHook, events[0].Metadata["code"])
	assert.Contains(t, events[0].Metadata["cause"], "email address is not verified")
	assert.Equal(t, emailverification.ErrorCodeEmailNotVerified, events[0].Metadata["causeCode"], "the handler's own code")
}

// A handler that fails for a reason of the system (a database that is down,
// say) stops the flow with its error and fires no failed point: the password
// was right and nothing refused the user. This holds for a point a flow runs
// itself (auth.signIn.credentialsVerified) and for the before point of
// WithLifecycle (auth.signUp.before).
func TestHandlerSystemErrorFiresNoFailedPoint(t *testing.T) {
	ctx := context.Background()
	errDown := errors.New("lookup: connection refused")
	var failAt types.HookPoint
	var failed []types.FailureReason
	app := bootVerification(t, emailverification.Options{}, func(cfg *bmth.BootConfig) {
		cfg.Hooks = func(reg types.HookRegistry) error {
			for _, point := range []types.HookPoint{hooks.HookSignInCredentialsVerified, hooks.HookSignUpBefore} {
				if err := reg.OnBefore(point, func(hctx *types.HookContext, _ behemoth.M) (behemoth.M, error) {
					if hctx.Point == failAt {
						return nil, errDown
					}
					return nil, nil
				}, nil); err != nil {
					return err
				}
			}
			for _, point := range []types.HookPoint{hooks.HookSignInFailed, hooks.HookSignUpFailed} {
				if err := reg.OnFailed(point, func(_ *types.HookContext, reason types.FailureReason) error {
					failed = append(failed, reason)
					return nil
				}, nil); err != nil {
					return err
				}
			}
			return nil
		}
	})
	app.signUp(t, "ada@example.com", 1)

	failAt = hooks.HookSignInCredentialsVerified
	_, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"})
	require.ErrorIs(t, err, errDown)

	failAt = hooks.HookSignUpBefore
	_, err = app.passwords.SignUp(ctx, behemoth.M{"email": "grace@example.com", "password": "correct horse"})
	require.ErrorIs(t, err, errDown)

	assert.Empty(t, failed, "no failed handler ran")
	assert.Empty(t, app.rec.Audit.OfType(string(hooks.HookSignInFailed)))
	assert.Empty(t, app.rec.Audit.OfType(string(hooks.HookSignUpFailed)))
}
