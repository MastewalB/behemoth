package plugins_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/core/hooks"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/twofactor"
	"github.com/go-behemoth/behemoth/plugins/twofactor/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingSignIn signs email in by password, which waits for a second
// factor, and returns the result with the context a route would run with
// for the pending session.
func (app *twoFactorApp) pendingSignIn(t *testing.T, email string) (*core.SignInResult, context.Context) {
	t.Helper()
	ctx := context.Background()
	result, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: email, Password: password})
	require.NoError(t, err)
	require.Equal(t, models.SessionPending, result.Session.State)
	return result, presenting(ctx, app.ac, result.RawToken)
}

// enableByCode turns on the email or SMS method of req for the caller of
// ctx, with the setup code the sender got.
func (app *twoFactorApp) enableByCode(t *testing.T, ctx context.Context, req twofactor.EnrollRequest) *twofactor.ConfirmResult {
	t.Helper()
	_, err := app.plugin.Enroll(ctx, req)
	require.NoError(t, err)
	var code string
	if req.Method == twofactor.MethodSMS {
		code = app.sms.last(t, app.sms.count()).Code
	} else {
		code = app.mail.last(t).Code
	}
	confirmed, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: req.Method, Code: code})
	require.NoError(t, err)
	return confirmed
}

// nextTOTP returns the code of the step after now's: the step that confirmed
// TOTP is spent, so a test that signs in right after needs the next one.
func nextTOTP(secret []byte) string {
	return totp.Code(secret, time.Now().Add(totp.Period))
}

// A sign-in of a user with a method waits for the second factor, and Verify
// finishes it: the session becomes active with a new token, and records both
// factors. The pending token stops working, and a TOTP code works once.
func TestTwoFactorSignInWaitsForTheSecondFactor(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	user, setup, _ := app.signedIn(t, "ada@example.com") // active: no method was on
	secret, _ := app.enableTOTP(t, setup)

	signIn, pendingCtx := app.pendingSignIn(t, "ada@example.com")
	assert.Equal(t, []string{core.FactorPassword}, signIn.Session.Factors)
	challenge, err := app.plugin.Challenge(pendingCtx)
	require.NoError(t, err)
	assert.Equal(t, []twofactor.ChallengeMethod{{Method: twofactor.MethodTOTP}, {Method: twofactor.MethodRecoveryCode}}, challenge.Methods)
	assert.False(t, challenge.Locked)

	_, err = app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
	assert.True(t, invalidTwoFactorCode(err), "%v", err)

	next := nextTOTP(secret)
	result, err := app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: next})
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)
	assert.Equal(t, signIn.Session.ID, result.Session.ID, "the same session, promoted")
	assert.Equal(t, models.SessionActive, result.Session.State)
	assert.Equal(t, []string{core.FactorPassword, core.FactorTOTP}, result.Session.Factors)
	assert.NotEqual(t, signIn.RawToken, result.RawToken)
	_, err = app.ac.SessionManager.Validate(ctx, result.RawToken)
	assert.NoError(t, err)
	_, err = app.ac.SessionManager.Get(ctx, signIn.RawToken)
	assert.True(t, errs.IsNotFound(err), "the pending token stops working: %v", err)

	_, again := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.Verify(again, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: next})
	assert.True(t, invalidTwoFactorCode(err), "a TOTP code works once: %v", err)

	verified := app.rec.Audit.OfType(string(twofactor.HookVerifyAfter))
	require.Len(t, verified, 1)
	assert.Equal(t, user.ID, verified[0].SubjectID)
	failures := app.rec.Audit.OfType(string(twofactor.HookVerifyFailed))
	require.Len(t, failures, 2)
	assert.Equal(t, "invalid_code", failures[1].Metadata["code"])
}

// A method on the channel of the first factor does not count: the challenge
// leaves it out, and SendCode and Verify refuse it. At the checkpoint a
// sign-in waits for a recovery code then, and one that leaves the user no
// method is refused, so the user signs in another way.
func TestTwoFactorChannelCountsOnce(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail}, WaitForSend: true, SendLimit: core.Limit{Max: 20, Window: time.Minute}}, nil)
	user, setup, _ := app.signedIn(t, "ada@example.com")
	app.enableByCode(t, setup, twofactor.EnrollRequest{Method: twofactor.MethodEmail})

	// A pending session whose first factor was the mailbox, as a magic
	// link's is.
	_, raw, err := app.ac.SessionManager.Create(ctx, user.ID, core.SessionMeta{State: models.SessionPending, Factor: core.FactorEmail})
	require.NoError(t, err)
	byMail := presenting(ctx, app.ac, raw)
	challenge, err := app.plugin.Challenge(byMail)
	require.NoError(t, err)
	assert.Equal(t, []twofactor.ChallengeMethod{{Method: twofactor.MethodRecoveryCode}}, challenge.Methods, "no email code after the mailbox")
	unavailable := func(err error) bool {
		return hasCode(err, errs.CategoryForbidden, twofactor.ErrorCodeMethodUnavailable)
	}
	_, err = app.plugin.SendCode(byMail, twofactor.SendCodeRequest{Method: twofactor.MethodEmail})
	assert.True(t, unavailable(err), "%v", err)
	_, err = app.plugin.Verify(byMail, twofactor.VerifyRequest{Method: twofactor.MethodEmail, Code: "123456"})
	assert.True(t, unavailable(err), "%v", err)
	_, err = app.plugin.SendCode(byMail, twofactor.SendCodeRequest{Method: twofactor.MethodTOTP})
	assert.True(t, unavailable(err), "TOTP has nothing to send: %v", err)

	checkpoint := func() (behemoth.M, error) {
		hctx := &core.HookContext{Ctx: ctx, Auth: app.ac, Values: behemoth.M{}}
		return app.ac.Dispatcher.RunBefore(hctx, hooks.HookSignInCredentialsVerified,
			behemoth.M{hooks.HookValueUserID: user.ID, hooks.HookValueFactor: core.FactorEmail})
	}
	payload, err := checkpoint()
	require.NoError(t, err)
	assert.Equal(t, true, payload[hooks.HookValueRequireStepUp], "a recovery code counts after any first factor")
	_, err = app.db.Exec(`DELETE FROM two_factor_recovery_codes`) // as if every code were used
	require.NoError(t, err)
	_, err = checkpoint()
	assert.True(t, hasCode(err, errs.CategoryForbidden, twofactor.ErrorCodeSameChannel), "%v", err)

	// After a password, the email code counts.
	_, byPassword := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.SendCode(byPassword, twofactor.SendCodeRequest{Method: twofactor.MethodEmail})
	require.NoError(t, err)
	mail := app.mail.last(t)
	assert.Equal(t, core.MailTwoFactorCode, mail.Kind)
	result, err := app.plugin.Verify(byPassword, twofactor.VerifyRequest{Method: twofactor.MethodEmail, Code: mail.Code})
	require.NoError(t, err)
	assert.Equal(t, []string{core.FactorPassword, core.FactorEmail}, result.Session.Factors)
}

// A code sent for a pending sign-in finishes that sign-in and no other, and
// the challenge flows take a pending session only.
func TestTwoFactorSentCodeSignIn(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodSMS}, WaitForSend: true, SendLimit: core.Limit{Max: 20, Window: time.Minute}}, nil)
	_, setup, _ := app.signedIn(t, "ada@example.com")
	app.enableByCode(t, setup, twofactor.EnrollRequest{Method: twofactor.MethodSMS, PhoneNumber: adaNumber})

	first, firstCtx := app.pendingSignIn(t, "ada@example.com")
	challenge, err := app.plugin.Challenge(firstCtx)
	require.NoError(t, err)
	assert.Equal(t, []twofactor.ChallengeMethod{{Method: twofactor.MethodSMS, Destination: "+1******0101"}, {Method: twofactor.MethodRecoveryCode}}, challenge.Methods)

	sent, err := app.plugin.SendCode(firstCtx, twofactor.SendCodeRequest{Method: twofactor.MethodSMS})
	require.NoError(t, err)
	assert.Equal(t, twofactor.PurposeSignIn, sent.Purpose)
	text := app.sms.last(t, 2)
	assert.Equal(t, core.SMSTwoFactorCode, text.Kind)
	assert.Equal(t, adaNumber, text.To)

	_, secondCtx := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.Verify(secondCtx, twofactor.VerifyRequest{Method: twofactor.MethodSMS, Code: text.Code})
	assert.True(t, invalidTwoFactorCode(err), "another sign-in can't use the code: %v", err)
	_, err = app.plugin.Verify(firstCtx, twofactor.VerifyRequest{Method: twofactor.MethodSMS, Code: text.Code})
	assert.True(t, invalidTwoFactorCode(err), "and spent it trying: %v", err)

	_, err = app.plugin.SendCode(firstCtx, twofactor.SendCodeRequest{Method: twofactor.MethodSMS})
	require.NoError(t, err)
	result, err := app.plugin.Verify(firstCtx, twofactor.VerifyRequest{Method: twofactor.MethodSMS, Code: app.sms.last(t, 3).Code})
	require.NoError(t, err)
	assert.Equal(t, first.Session.ID, result.Session.ID)
	assert.Equal(t, []string{core.FactorPassword, core.FactorSMS}, result.Session.Factors)

	_, err = app.plugin.Challenge(presenting(ctx, app.ac, result.RawToken))
	assert.True(t, hasCode(err, errs.CategoryConflict, twofactor.ErrorCodeNotPending), "an active session: %v", err)
	_, err = app.plugin.Verify(ctx, twofactor.VerifyRequest{Method: twofactor.MethodSMS, Code: "123456"})
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "no session: %v", err)
	_, err = app.plugin.Verify(presenting(ctx, app.ac, "no such token"), twofactor.VerifyRequest{Method: twofactor.MethodSMS, Code: "123456"})
	assert.True(t, errs.IsCode(err, errs.CodeSessionInvalid), "a token of no session: %v", err)
}

// A recovery code finishes a sign-in once, typed in any case and with or
// without its dash, and the session records it.
func TestTwoFactorRecoveryCodeSignIn(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	_, setup, _ := app.signedIn(t, "ada@example.com")
	_, confirmed := app.enableTOTP(t, setup)
	code := confirmed.RecoveryCodes[0]

	_, pendingCtx := app.pendingSignIn(t, "ada@example.com")
	result, err := app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodRecoveryCode, Code: strings.ToLower(strings.ReplaceAll(code, "-", ""))})
	require.NoError(t, err)
	assert.Equal(t, []string{core.FactorPassword, core.FactorRecoveryCode}, result.Session.Factors)

	_, again := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.Verify(again, twofactor.VerifyRequest{Method: twofactor.MethodRecoveryCode, Code: code})
	assert.True(t, invalidTwoFactorCode(err), "a recovery code works once: %v", err)
	status, err := app.plugin.Status(presenting(context.Background(), app.ac, result.RawToken))
	require.NoError(t, err)
	assert.Equal(t, twofactor.DefaultRecoveryCodes-1, status.RecoveryCodesLeft)
}

// After MaxFailures failed second factors in a row, across sign-ins, only a
// recovery code passes. It clears the count, and the other methods work
// again.
func TestTwoFactorLock(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example", MaxFailures: 3, VerifyLimit: core.Limit{Max: 100, Window: time.Minute}}, nil)
	user, setup, _ := app.signedIn(t, "ada@example.com")
	secret, confirmed := app.enableTOTP(t, setup)
	for range 3 {
		_, ctx := app.pendingSignIn(t, "ada@example.com")
		_, err := app.plugin.Verify(ctx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
		require.True(t, invalidTwoFactorCode(err), "%v", err)
	}

	_, locked := app.pendingSignIn(t, "ada@example.com")
	next := nextTOTP(secret)
	_, err := app.plugin.Verify(locked, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: next})
	assert.True(t, hasCode(err, errs.CategoryForbidden, twofactor.ErrorCodeLocked), "the right code is refused under the lock: %v", err)
	challenge, err := app.plugin.Challenge(locked)
	require.NoError(t, err)
	assert.True(t, challenge.Locked)
	assert.Equal(t, []twofactor.ChallengeMethod{{Method: twofactor.MethodRecoveryCode}}, challenge.Methods)
	status, err := app.plugin.Status(setup)
	require.NoError(t, err)
	assert.True(t, status.Locked)

	_, err = app.plugin.Verify(locked, twofactor.VerifyRequest{Method: twofactor.MethodRecoveryCode, Code: confirmed.RecoveryCodes[0]})
	require.NoError(t, err, "a recovery code passes under the lock")
	assert.Zero(t, app.rows(t, twofactor.FailureTable, "user_id = ?", user.ID), "and clears the count")
	_, unlocked := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.Verify(unlocked, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: next})
	assert.NoError(t, err, "TOTP works again")

	codes := map[string]int{}
	for _, event := range app.rec.Audit.OfType(string(twofactor.HookVerifyFailed)) {
		codes[event.Metadata["code"].(string)]++
	}
	assert.Equal(t, map[string]int{"invalid_code": 3, "locked": 1}, codes)
}

// The second factors tried per user are limited across pending sessions:
// whoever knows the password can open a new one at any time.
func TestTwoFactorVerifiesAreLimitedPerUser(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example", VerifyLimit: core.Limit{Max: 2, Window: time.Hour}}, nil)
	_, setup, _ := app.signedIn(t, "ada@example.com")
	secret, _ := app.enableTOTP(t, setup)
	for range 2 {
		_, ctx := app.pendingSignIn(t, "ada@example.com")
		_, err := app.plugin.Verify(ctx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
		require.True(t, invalidTwoFactorCode(err), "%v", err)
	}
	_, ctx := app.pendingSignIn(t, "ada@example.com")
	_, err := app.plugin.Verify(ctx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: nextTOTP(secret)})
	assert.True(t, errs.IsCategory(err, errs.CategoryRateLimited), "%v", err)
}

// An admin turns every method of a user off. The user then signs in with a
// password alone.
func TestTwoFactorReset(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	user, setup, _ := app.signedIn(t, "ada@example.com")
	secret, _ := app.enableTOTP(t, setup)
	_, pendingCtx := app.pendingSignIn(t, "ada@example.com")
	_, err := app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
	require.True(t, invalidTwoFactorCode(err), "%v", err)

	_, err = app.plugin.Reset(setup, twofactor.ResetRequest{UserID: user.ID})
	assert.True(t, hasCode(err, errs.CategoryForbidden, errs.CodeInsufficientScope), "a signed-in user is no admin: %v", err)
	result, err := app.plugin.Reset(asAdmin(ctx), twofactor.ResetRequest{UserID: user.ID})
	require.NoError(t, err)
	assert.True(t, result.Off)
	assert.Equal(t, twofactor.ReasonAdminReset, result.Reason)
	for _, table := range []string{twofactor.MethodTable, twofactor.RecoveryCodeTable, twofactor.FailureTable} {
		assert.Zero(t, app.rows(t, table, "user_id = ?", user.ID), table)
	}
	signIn, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: password})
	require.NoError(t, err)
	assert.Equal(t, models.SessionActive, signIn.Session.State)

	_, err = app.plugin.Reset(asAdmin(ctx), twofactor.ResetRequest{UserID: user.ID})
	assert.True(t, hasCode(err, errs.CategoryConflict, twofactor.ErrorCodeNotEnabled), "%v", err)
	disabled := app.rec.Audit.OfType(string(twofactor.HookDisableAfter))
	require.Len(t, disabled, 1)
	assert.Equal(t, user.ID, disabled[0].SubjectID)
}

// A TOTP secret is sealed for its user. Copied into another user's row, as
// someone who can write the database but lacks the secrets could do, it does
// not open there: a code from the copied secret does not finish the other
// user's sign-in, which fails as a sealed value that was changed does.
func TestTwoFactorTOTPSecretIsBoundToItsUser(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	eve, eveCtx, _ := app.signedIn(t, "eve@example.com")
	eveSecret, _ := app.enableTOTP(t, eveCtx)
	ada, adaCtx, _ := app.signedIn(t, "ada@example.com")
	app.enableTOTP(t, adaCtx)

	var sealed string
	require.NoError(t, app.db.QueryRow(`SELECT secret FROM two_factor_methods WHERE user_id = ? AND method = ?`,
		eve.ID, string(twofactor.MethodTOTP)).Scan(&sealed))
	_, err := app.db.Exec(`UPDATE two_factor_methods SET secret = ? WHERE user_id = ? AND method = ?`,
		sealed, ada.ID, string(twofactor.MethodTOTP))
	require.NoError(t, err)

	_, pendingCtx := app.pendingSignIn(t, "ada@example.com")
	_, err = app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: totp.Code(eveSecret, time.Now())})
	assert.True(t, errs.IsCode(err, "invalid_payload"), "%v", err)
}
