package plugins_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/phonenumber"
	"github.com/go-behemoth/behemoth/plugins/twofactor"
	"github.com/go-behemoth/behemoth/plugins/twofactor/totp"
	sqliteAdapter "github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
	"github.com/go-behemoth/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type twoFactorApp struct {
	ac        *core.AuthContext
	passwords *emailpassword.Plugin
	plugin    *twofactor.Plugin
	mail      *outbox
	sms       *texts
	rec       *telemetrytest.Recorder
	db        *sql.DB
	lastToken string // the session token of the latest signIn
}

// bootTwoFactor boots the email/password and two-factor plugins over SQLite,
// with a mail and an SMS sender that keep what they send. configure, if set,
// changes the BootConfig before Boot.
func bootTwoFactor(t *testing.T, opts twofactor.Options, configure func(*engine.BootConfig)) *twoFactorApp {
	t.Helper()
	app, err := tryBootTwoFactor(t, opts, configure)
	require.NoError(t, err)
	return app
}

func tryBootTwoFactor(t *testing.T, opts twofactor.Options, configure func(*engine.BootConfig)) (*twoFactorApp, error) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "twofactor.db")+"?_foreign_keys=on&_busy_timeout=10000&_txlock=immediate")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := &twoFactorApp{mail: &outbox{}, sms: &texts{}, db: db}
	app.passwords = emailpassword.New(emailpassword.Options{})
	app.plugin = twofactor.New(opts)
	prepared, err := engine.Prepare([]core.Plugin{app.passwords, app.plugin}, engine.PrepareConfig{})
	require.NoError(t, err)
	testutils.MigrateApp(t, db, prepared)

	tel, rec := telemetrytest.New()
	app.rec = rec
	cfg := engine.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("2f", 32)}, Current: 1},
		},
		Mail:      core.MailConfig{Sender: app.mail},
		SMS:       core.SMSConfig{Sender: app.sms},
		Telemetry: tel,
	}
	if configure != nil {
		configure(&cfg)
	}
	app.ac, err = engine.Boot(context.Background(), prepared, sqliteAdapter.NewSQLiteAdapter(db, prepared.Resolver), cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		app.ac.Mailer.Close(context.Background())
		app.ac.SMS.Close(context.Background())
	})
	return app, nil
}

// signedIn signs a user up and in by password, and returns the user, the
// context a route would run with for the new session, and the session's
// token.
func (app *twoFactorApp) signedIn(t *testing.T, email string) (*models.User, context.Context, string) {
	t.Helper()
	ctx := context.Background()
	user, err := app.passwords.SignUp(ctx, behemoth.M{"email": email, "password": password})
	require.NoError(t, err)
	ctx = app.signIn(t, email)
	return user, ctx, app.lastToken
}

// signIn signs email in by password again, and returns the context a route
// would run with for the new session. Its token is in lastToken.
func (app *twoFactorApp) signIn(t *testing.T, email string) context.Context {
	t.Helper()
	ctx := context.Background()
	result, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: email, Password: password})
	require.NoError(t, err)
	app.lastToken = result.RawToken
	return presenting(ctx, app.ac, result.RawToken)
}

// enableTOTP turns TOTP on for the caller of ctx and returns the secret and
// what Confirm returned.
func (app *twoFactorApp) enableTOTP(t *testing.T, ctx context.Context) ([]byte, *twofactor.ConfirmResult) {
	t.Helper()
	enrollment, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
	require.NoError(t, err)
	secret, err := totp.DecodeSecret(enrollment.Secret)
	require.NoError(t, err)
	confirmed, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: totp.Code(secret, time.Now())})
	require.NoError(t, err)
	return secret, confirmed
}

// rows counts the rows of table that query, a WHERE clause, selects.
func (app *twoFactorApp) rows(t *testing.T, table, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, app.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+query, args...).Scan(&n))
	return n
}

// wrongTOTP returns a code that secret does not produce around now.
func wrongTOTP(secret []byte) string {
	for i := 0; ; i++ {
		if code := fmt.Sprintf("%06d", i); !slices.ContainsFunc([]int{-1, 0, 1}, func(skew int) bool {
			return totp.Code(secret, time.Now().Add(time.Duration(skew)*totp.Period)) == code
		}) {
			return code
		}
	}
}

func invalidTwoFactorCode(err error) bool {
	return hasCode(err, errs.CategoryUnauthorized, twofactor.ErrorCodeInvalidCode)
}

// TOTP is set up with a secret stored sealed, and turned on by a code the
// app computes from it. The first method brings the recovery codes, stored
// as hashes, and a second setup keeps the first secret until it is
// confirmed.
func TestTwoFactorTOTPSetup(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")

	enrollment, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(enrollment.URI, "otpauth://totp/Example:ada@example.com?secret="+enrollment.Secret+"&issuer=Example"), enrollment.URI)
	secret, err := totp.DecodeSecret(enrollment.Secret)
	require.NoError(t, err)
	var stored string
	require.NoError(t, app.db.QueryRow(`SELECT pending_secret FROM two_factor_methods WHERE user_id = ?`, user.ID).Scan(&stored))
	assert.True(t, strings.HasPrefix(stored, "v1:"), "the secret is sealed: %s", stored)
	assert.NotContains(t, stored, enrollment.Secret)
	status, err := app.plugin.Status(ctx)
	require.NoError(t, err)
	assert.Empty(t, status.Methods, "nothing is on before the confirmation")

	_, err = app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
	assert.True(t, invalidTwoFactorCode(err), "%v", err)

	confirmed, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: totp.Code(secret, time.Now())})
	require.NoError(t, err)
	assert.True(t, confirmed.First)
	require.Len(t, confirmed.RecoveryCodes, twofactor.DefaultRecoveryCodes)
	for _, code := range confirmed.RecoveryCodes {
		assert.Regexp(t, `^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$`, code)
	}
	assert.Zero(t, app.rows(t, twofactor.RecoveryCodeTable, "code_hash LIKE ?", "%"+strings.ReplaceAll(confirmed.RecoveryCodes[0], "-", "")+"%"), "only a hash is stored")
	status, err = app.plugin.Status(ctx)
	require.NoError(t, err)
	require.Len(t, status.Methods, 1)
	assert.Equal(t, twofactor.MethodTOTP, status.Methods[0].Method)
	assert.Equal(t, twofactor.DefaultRecoveryCodes, status.RecoveryCodesLeft)
	var lastStep int64
	require.NoError(t, app.db.QueryRow(`SELECT last_step FROM two_factor_methods WHERE user_id = ?`, user.ID).Scan(&lastStep))
	assert.InDelta(t, totp.Step(time.Now()), lastStep, 1, "the confirming code's step is recorded, so it can't sign in")

	again, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
	require.NoError(t, err)
	assert.NotEqual(t, enrollment.Secret, again.Secret)
	status, err = app.plugin.Status(ctx)
	require.NoError(t, err)
	assert.Len(t, status.Methods, 1, "TOTP stays on while a new secret is set up")
	newSecret, err := totp.DecodeSecret(again.Secret)
	require.NoError(t, err)
	second, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: totp.Code(newSecret, time.Now())})
	require.NoError(t, err)
	assert.False(t, second.First)
	assert.Empty(t, second.RecoveryCodes, "recovery codes come with the first method only")
	assert.Equal(t, twofactor.DefaultRecoveryCodes, app.rows(t, twofactor.RecoveryCodeTable, "user_id = ?", user.ID))

	assert.Len(t, app.rec.Audit.OfType(string(twofactor.HookEnableAfter)), 2)
	failures := app.rec.Audit.OfType(string(twofactor.HookEnableFailed))
	require.Len(t, failures, 1)
	assert.Equal(t, "invalid_code", failures[0].Metadata["code"])
	assert.Equal(t, user.ID, failures[0].SubjectID)
}

// A code by email goes to the account's address, and one by SMS to the
// number the user gives. Each method's setup code turns on that method only,
// once, and the method keeps the destination the code went to.
func TestTwoFactorEmailAndSMSSetup(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail, twofactor.MethodSMS}, WaitForSend: true}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")

	enrollment, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodEmail, Metadata: behemoth.M{"locale": "am"}})
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", enrollment.Destination)
	mail := app.mail.last(t)
	assert.Equal(t, core.MailTwoFactorSetup, mail.Kind)
	assert.Equal(t, "ada@example.com", mail.To)
	assert.Len(t, mail.Code, 6)
	assert.Empty(t, mail.URL)
	assert.Equal(t, "am", mail.Metadata["locale"])

	_, err = app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodSMS, Code: mail.Code})
	assert.True(t, invalidTwoFactorCode(err), "an email setup code does not turn on SMS: %v", err)
	confirmed, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodEmail, Code: mail.Code})
	require.NoError(t, err)
	assert.True(t, confirmed.First)
	assert.Equal(t, "ada@example.com", confirmed.Destination)
	_, err = app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodEmail, Code: mail.Code})
	assert.True(t, invalidTwoFactorCode(err), "a code works once: %v", err)

	_, err = app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodSMS, PhoneNumber: "0911 234567"})
	assert.True(t, hasCode(err, errs.CategoryValidation, phonenumber.ErrorCodeInvalidPhoneNumber), "%v", err)
	_, err = app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodSMS, PhoneNumber: adaNumber})
	require.NoError(t, err)
	text := app.sms.last(t, 1)
	assert.Equal(t, core.SMSTwoFactorSetup, text.Kind)
	assert.Equal(t, adaNumber, text.To)
	smsOn, err := app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodSMS, Code: text.Code})
	require.NoError(t, err)
	assert.False(t, smsOn.First)

	status, err := app.plugin.Status(ctx)
	require.NoError(t, err)
	require.Len(t, status.Methods, 2)
	assert.Equal(t, "ada@example.com", status.Methods[0].Destination)
	assert.Equal(t, adaNumber, status.Methods[1].Destination)
	assert.Zero(t, app.rows(t, "verification_codes", "subject = ?", user.ID), "the setup codes are used up")

	sends := app.rec.Audit.OfType(string(twofactor.HookSendAfter))
	require.Len(t, sends, 2)
	assert.Equal(t, user.ID, sends[0].SubjectID)
}

// The first method ends the user's other sessions, which were opened without
// a second factor, and leaves the one that confirmed. A later method ends
// nothing.
func TestTwoFactorFirstMethodEndsOtherSessions(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	user, confirming, raw := app.signedIn(t, "ada@example.com")
	app.signIn(t, "ada@example.com")
	other := app.lastToken

	app.enableTOTP(t, confirming)
	_, err := app.ac.SessionManager.Validate(ctx, other)
	assert.True(t, errs.IsCode(err, errs.CodeSessionRevoked), "%v", err)
	_, err = app.ac.SessionManager.Validate(ctx, raw)
	assert.NoError(t, err, "the session that confirmed stays")
	sessions, err := app.ac.SessionManager.ListForUser(ctx, user.ID)
	require.NoError(t, err)
	reasons := map[string]int{}
	for _, s := range sessions {
		reasons[s.RevokedReason]++
	}
	assert.Equal(t, map[string]int{"": 1, twofactor.SessionRevokedEnabled: 1}, reasons)

	app.signIn(t, "ada@example.com") // pending now: TOTP is on
	later := app.lastToken
	app.enableTOTP(t, confirming) // a new secret: TOTP was on already
	session, err := app.ac.SessionManager.Get(ctx, later)
	require.NoError(t, err, "a method that is not the first ends no session")
	assert.Equal(t, models.SessionPending, session.State)
}

// Turning the last method off turns the plugin off for the user, and takes
// the recovery codes with it.
func TestTwoFactorDisable(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example", Methods: []twofactor.Method{twofactor.MethodTOTP, twofactor.MethodEmail}, WaitForSend: true}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")
	app.enableTOTP(t, ctx)
	_, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodEmail})
	require.NoError(t, err)
	_, err = app.plugin.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodEmail, Code: app.mail.last(t).Code})
	require.NoError(t, err)

	result, err := app.plugin.Disable(ctx, twofactor.DisableRequest{Method: twofactor.MethodEmail})
	require.NoError(t, err)
	assert.False(t, result.Off)
	status, err := app.plugin.Status(ctx)
	require.NoError(t, err)
	assert.Len(t, status.Methods, 1)
	assert.Equal(t, twofactor.DefaultRecoveryCodes, status.RecoveryCodesLeft)

	result, err = app.plugin.Disable(ctx, twofactor.DisableRequest{Method: twofactor.MethodTOTP})
	require.NoError(t, err)
	assert.True(t, result.Off)
	assert.Equal(t, twofactor.ReasonUserDisabled, result.Reason)
	status, err = app.plugin.Status(ctx)
	require.NoError(t, err)
	assert.Empty(t, status.Methods)
	assert.Zero(t, status.RecoveryCodesLeft)
	assert.Zero(t, app.rows(t, twofactor.RecoveryCodeTable, "user_id = ?", user.ID))

	_, err = app.plugin.Disable(ctx, twofactor.DisableRequest{Method: twofactor.MethodTOTP})
	assert.True(t, hasCode(err, errs.CategoryConflict, twofactor.ErrorCodeNotEnabled), "%v", err)
	_, err = app.plugin.Disable(ctx, twofactor.DisableRequest{Method: "fax"})
	assert.True(t, errs.IsCategory(err, errs.CategoryValidation), "%v", err)

	assert.Len(t, app.rec.Audit.OfType(string(twofactor.HookDisableAfter)), 2)
	failures := app.rec.Audit.OfType(string(twofactor.HookDisableFailed))
	require.Len(t, failures, 1)
	assert.Equal(t, "not_enabled", failures[0].Metadata["code"])
}

// A new set of recovery codes replaces the old one, and needs a method that
// is on.
func TestTwoFactorRegenerateRecoveryCodes(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example", RecoveryCodes: 4}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")
	_, err := app.plugin.RegenerateRecoveryCodes(ctx)
	assert.True(t, hasCode(err, errs.CategoryConflict, twofactor.ErrorCodeNotEnabled), "%v", err)

	_, confirmed := app.enableTOTP(t, ctx)
	require.Len(t, confirmed.RecoveryCodes, 4)
	fresh, err := app.plugin.RegenerateRecoveryCodes(ctx)
	require.NoError(t, err)
	require.Len(t, fresh, 4)
	for _, code := range fresh {
		assert.NotContains(t, confirmed.RecoveryCodes, code)
	}
	assert.Equal(t, 4, app.rows(t, twofactor.RecoveryCodeTable, "user_id = ?", user.ID), "the old set is gone")
	events := app.rec.Audit.OfType(string(twofactor.HookRegenerateAfter))
	require.Len(t, events, 1)
	assert.Equal(t, user.ID, events[0].SubjectID)
}

// The setup flows act on the caller's own account and need a fresh session.
// Status needs a session only.
func TestTwoFactorSetupNeedsAFreshSession(t *testing.T) {
	ctx := context.Background()
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, func(cfg *engine.BootConfig) {
		cfg.Session.FreshAge = 200 * time.Millisecond
	})
	user, signedIn, _ := app.signedIn(t, "ada@example.com")
	enroll := func(ctx context.Context) error {
		_, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
		return err
	}

	assert.True(t, errs.IsCode(enroll(ctx), errs.CodeSessionMissing))
	_, pendingRaw, err := app.ac.SessionManager.Create(ctx, user.ID, core.SessionMeta{State: models.SessionPending, Factor: core.FactorPassword})
	require.NoError(t, err)
	assert.True(t, errs.IsCode(enroll(presenting(ctx, app.ac, pendingRaw)), errs.CodeSessionPending))
	assert.NoError(t, enroll(actingFor(ctx, user.ID)), "a system caller acting for the user passes")

	time.Sleep(300 * time.Millisecond)
	assert.True(t, errs.IsCode(enroll(signedIn), errs.CodeSessionNotFresh))
	_, err = app.plugin.Status(signedIn)
	assert.NoError(t, err, "reading the methods needs no fresh session")
}

// A method Options.Methods does not offer is refused, and a name that is
// not a method is a validation error.
func TestTwoFactorOffersTheConfiguredMethods(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	_, ctx, _ := app.signedIn(t, "ada@example.com")
	_, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodEmail})
	assert.True(t, hasCode(err, errs.CategoryForbidden, twofactor.ErrorCodeMethodUnavailable), "%v", err)
	_, err = app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: "fax"})
	assert.True(t, errs.IsCategory(err, errs.CategoryValidation), "%v", err)
}

// The codes sent per user are limited across purposes and sessions.
func TestTwoFactorSendsAreLimitedPerUser(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail}, SendLimit: core.Limit{Max: 1, Window: time.Hour}, WaitForSend: true}, nil)
	_, ctx, _ := app.signedIn(t, "ada@example.com")
	_, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodEmail})
	require.NoError(t, err)
	_, err = app.plugin.Enroll(app.signIn(t, "ada@example.com"), twofactor.EnrollRequest{Method: twofactor.MethodEmail})
	assert.True(t, errs.IsCategory(err, errs.CategoryRateLimited), "another session of the user shares the limit: %v", err)
	assert.Equal(t, 1, app.mail.count())
}

// A failed send revokes the code nobody received, and is returned.
func TestTwoFactorFailedSendRevokesTheCode(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Methods: []twofactor.Method{twofactor.MethodSMS}, WaitForSend: true}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")
	app.sms.fail = fmt.Errorf("provider down")
	_, err := app.plugin.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodSMS, PhoneNumber: adaNumber})
	assert.ErrorContains(t, err, "provider down")
	assert.Zero(t, app.rows(t, "verification_codes", "subject = ?", user.ID))
	failures := app.rec.Audit.OfType(string(twofactor.HookSendFailed))
	require.Len(t, failures, 1)
	assert.Equal(t, "send_failed", failures[0].Metadata["code"])
}

// A user's rows go with the user, without foreign keys enforced.
func TestTwoFactorRowsGoWithTheUser(t *testing.T) {
	app := bootTwoFactor(t, twofactor.Options{Issuer: "Example"}, nil)
	user, ctx, _ := app.signedIn(t, "ada@example.com")
	secret, _ := app.enableTOTP(t, ctx)
	_, pendingCtx := app.pendingSignIn(t, "ada@example.com")
	_, err := app.plugin.Verify(pendingCtx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: wrongTOTP(secret)})
	require.True(t, invalidTwoFactorCode(err), "%v", err)
	require.Equal(t, 1, app.rows(t, twofactor.FailureTable, "user_id = ?", user.ID))

	require.NoError(t, app.ac.Store.DeleteUser(context.Background(), user.ID))
	for _, table := range []string{twofactor.MethodTable, twofactor.RecoveryCodeTable, twofactor.FailureTable} {
		assert.Zero(t, app.rows(t, table, "user_id = ?", user.ID), table)
	}
}

// Boot reports options that can't work.
func TestTwoFactorOptionsAreChecked(t *testing.T) {
	for name, tc := range map[string]struct {
		opts      twofactor.Options
		configure func(*engine.BootConfig)
	}{
		"TOTP without an issuer":         {opts: twofactor.Options{}},
		"email without a sender":         {opts: twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail}}, configure: func(cfg *engine.BootConfig) { cfg.Mail.Sender = nil }},
		"SMS without a sender":           {opts: twofactor.Options{Methods: []twofactor.Method{twofactor.MethodSMS}}, configure: func(cfg *engine.BootConfig) { cfg.SMS.Sender = nil }},
		"a method that is not one":       {opts: twofactor.Options{Methods: []twofactor.Method{"fax"}}},
		"too many recovery codes":        {opts: twofactor.Options{Issuer: "Example", RecoveryCodes: 21}},
		"a code too short to guard":      {opts: twofactor.Options{Methods: []twofactor.Method{twofactor.MethodEmail}, CodeLength: 3}},
		"more failures than NIST allows": {opts: twofactor.Options{Issuer: "Example", MaxFailures: 101}},
	} {
		_, err := tryBootTwoFactor(t, tc.opts, tc.configure)
		assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%s: %v", name, err)
	}
}
