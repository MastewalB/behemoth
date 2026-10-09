package plugins_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/emailverification"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type verificationApp struct {
	passwords *emailpassword.Plugin
	plugin    *emailverification.Plugin
	ac        *types.AuthContext
	outbox    *outbox
	rec       *telemetrytest.Recorder
	mounted   mountedRoutes
}

// bootVerification boots the email/password plugin and the verification
// plugin over a fresh database, with one trusted origin. configure may
// adjust the BootConfig.
func bootVerification(t *testing.T, opts emailverification.Options, configure ...func(*bmth.BootConfig)) *verificationApp {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "verification.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	if opts.LinkURL == "" {
		opts.LinkURL = "https://app.example.com/auth/verify-email"
	}
	app := &verificationApp{
		passwords: emailpassword.New(emailpassword.Options{}),
		plugin:    emailverification.New(opts),
		outbox:    &outbox{},
		mounted:   mountedRoutes{},
	}
	tel, rec := telemetrytest.New()
	app.rec = rec

	prepared, err := bmth.Prepare([]types.Plugin{app.passwords, app.plugin}, bmth.PrepareConfig{})
	require.NoError(t, err)
	cfg := bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session:   types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: types.TransportHeader},
		Router:    types.RouterConfig{TrustedOrigins: []string{"https://app.example.com"}},
		Mail:      types.MailConfig{Sender: app.outbox},
		Telemetry: tel,
		HTTP:      app.mounted,
	}
	for _, fn := range configure {
		fn(&cfg)
	}
	app.ac, err = bmth.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { app.ac.Mailer.Close(context.Background()) })
	return app
}

// signUp signs a user up with a password and waits for the n-th message.
func (app *verificationApp) signUp(t *testing.T, email string, n int) (*models.User, types.MailMessage) {
	t.Helper()
	user, err := app.passwords.SignUp(context.Background(), behemoth.M{"email": email, "password": "correct horse"})
	require.NoError(t, err)
	return user, app.mail(t, n)
}

// mail waits until n messages have been sent and returns the last one. The
// plugin sends in the background.
func (app *verificationApp) mail(t *testing.T, n int) types.MailMessage {
	t.Helper()
	require.Eventually(t, func() bool { return app.outbox.count() >= n }, 5*time.Second, time.Millisecond, "message %d was not sent", n)
	require.Equal(t, n, app.outbox.count())
	return app.outbox.last(t)
}

func invalidVerificationLink(err error) bool {
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	return ok && de.Category == behemotherr.CategoryUnauthorized && de.Code == emailverification.ErrorCodeInvalidLink
}

// A user created by another plugin is sent a link without that plugin
// knowing, the sign-up does not wait for the sender, and the link verifies
// the address once.
func TestEmailVerificationAfterSignUp(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{})

	app.outbox.mu.Lock() // the sender blocks until the sign-up has returned
	user, err := app.passwords.SignUp(ctx, behemoth.M{"email": "Ada@Example.com", "password": "correct horse"})
	app.outbox.mu.Unlock()
	require.NoError(t, err, "the sign-up did not wait for the sender")
	assert.False(t, user.EmailVerified)

	msg := app.mail(t, 1)
	assert.Equal(t, types.MailEmailVerification, msg.Kind)
	assert.Equal(t, "ada@example.com", msg.To)
	assert.Equal(t, user.ID, msg.User.ID)
	assert.True(t, strings.HasPrefix(msg.URL, "https://app.example.com/auth/verify-email?token="), msg.URL)
	assert.WithinDuration(t, time.Now().Add(emailverification.DefaultTTL), msg.ExpiresAt, time.Minute)

	result, err := app.plugin.Verify(ctx, msg.Token)
	require.NoError(t, err)
	assert.True(t, result.User.EmailVerified)
	stored, err := app.ac.Store.FindUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, stored.EmailVerified)

	_, err = app.plugin.Verify(ctx, msg.Token)
	assert.True(t, invalidVerificationLink(err), "a link works once: %v", err)
	_, err = app.plugin.Verify(ctx, "not-a-token")
	assert.True(t, invalidVerificationLink(err), "an unknown token gets the same answer: %v", err)

	// Asking again for a verified user sends nothing.
	_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{UserID: user.ID})
	assert.ErrorIs(t, err, emailverification.ErrAlreadyVerified)
	_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{UserID: "no-such-user"})
	assert.ErrorIs(t, err, emailverification.ErrNoAccount)
	_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{Email: "nobody@example.com"})
	assert.ErrorIs(t, err, emailverification.ErrNoAccount)
	assert.Equal(t, 1, app.outbox.count())

	sent := app.rec.Audit.OfType(string(emailverification.HookSendAfter))
	require.Len(t, sent, 1)
	assert.Equal(t, user.ID, sent[0].SubjectID)
	verified := app.rec.Audit.OfType(string(emailverification.HookVerifyAfter))
	require.Len(t, verified, 1)
	assert.Equal(t, user.ID, verified[0].SubjectID)
	assert.Len(t, app.rec.Audit.OfType(string(emailverification.HookVerifyFailed)), 2)
}

// A change of address clears the verified flag and sends a link to the new
// address. Other updates send nothing, and an update that sets the flag
// itself keeps it.
func TestEmailVerificationAfterEmailChange(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{})
	user, first := app.signUp(t, "ada@example.com", 1)

	// Unverified, the address changes: the pending link is for the old one.
	updated, err := app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: "Ada@New.example.com"})
	require.NoError(t, err)
	assert.False(t, updated.EmailVerified)
	second := app.mail(t, 2)
	assert.Equal(t, "ada@new.example.com", second.To)
	_, err = app.plugin.Verify(ctx, first.Token)
	assert.True(t, invalidVerificationLink(err), "the link sent to the old address: %v", err)

	result, err := app.plugin.Verify(ctx, second.Token)
	require.NoError(t, err)
	assert.True(t, result.User.EmailVerified)

	// An update that leaves the address alone, or rewrites it unchanged.
	_, err = app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)
	same, err := app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: " ADA@new.example.com"})
	require.NoError(t, err)
	assert.True(t, same.EmailVerified, "the same address in another spelling is not a change")

	// Verified, the address changes again: the flag is cleared.
	changed, err := app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: "ada@third.example.com"})
	require.NoError(t, err)
	assert.False(t, changed.EmailVerified, "a new address is not verified")
	third := app.mail(t, 3)
	assert.Equal(t, "ada@third.example.com", third.To)

	// An update that vouches for the address itself.
	vouched, err := app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: "ada@fourth.example.com", models.UserEmailVerified: true})
	require.NoError(t, err)
	assert.True(t, vouched.EmailVerified)
	_, err = app.plugin.Verify(ctx, third.Token)
	assert.True(t, invalidVerificationLink(err), "the link for the third address: %v", err)
	time.Sleep(50 * time.Millisecond) // nothing more is queued
	assert.Equal(t, 3, app.outbox.count())
}

// The send route answers the same for an unknown email, a verified one and
// one that is sent a link. The verify route returns the user and the
// redirect.
func TestEmailVerificationRoutes(t *testing.T) {
	app := bootVerification(t, emailverification.Options{})
	send := app.mounted["/api/auth"+emailverification.PathSend]
	verify := app.mounted["/api/auth"+emailverification.PathVerify]
	require.NotNil(t, send.Handler)
	require.NotNil(t, verify.Handler)
	assert.Equal(t, http.MethodPost, verify.Method)

	user, _ := app.signUp(t, "ada@example.com", 1)
	done, mail := app.signUp(t, "grace@example.com", 2)
	_, err := app.plugin.Verify(context.Background(), mail.Token)
	require.NoError(t, err)

	pending := call(t, app.ac, send, `{"email":"ada@example.com","redirectURL":"https://app.example.com/welcome","metadata":{"locale":"fr"}}`)
	require.Equal(t, http.StatusOK, pending.Code, pending.Body.String())
	link := app.mail(t, 3)
	assert.Equal(t, "ada@example.com", link.To)
	assert.Equal(t, behemoth.M{"locale": "fr"}, link.Metadata)

	for name, body := range map[string]string{
		"an unknown email":  `{"email":"nobody@example.com"}`,
		"a verified email":  `{"email":"grace@example.com"}`,
		"a verified email2": `{"email":" GRACE@example.com "}`,
	} {
		w := call(t, app.ac, send, body)
		assert.Equal(t, pending.Code, w.Code, name)
		assert.Equal(t, pending.Body.String(), w.Body.String(), "%s: the response does not tell", name)
	}
	assert.Equal(t, 3, app.outbox.count(), "neither was sent anything")

	for body, want := range map[string]int{
		`{`:                        http.StatusBadRequest,
		`{"email":"not an email"}`: http.StatusBadRequest,
		`{"email":"ada@example.com","redirectURL":"https://evil.example.com/"}`: http.StatusBadRequest,
	} {
		assert.Equal(t, want, call(t, app.ac, send, body).Code, "send body %s", body)
	}
	assert.Equal(t, http.StatusBadRequest, call(t, app.ac, verify, `{}`).Code, "a verify without a token")

	w := call(t, app.ac, verify, `{"token":"`+link.Token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		User        models.User `json:"user"`
		RedirectURL string      `json:"redirectURL"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, user.ID, body.User.ID)
	assert.True(t, body.User.EmailVerified)
	assert.Equal(t, "https://app.example.com/welcome", body.RedirectURL)
	assert.NotEqual(t, user.ID, done.ID)

	w = call(t, app.ac, verify, `{"token":"`+link.Token+`"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), emailverification.ErrorCodeInvalidLink)
}

// With RequireVerified a password sign-in is refused until the address is
// verified.
func TestEmailVerificationRequiredToSignIn(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{RequireVerified: true})
	_, mail := app.signUp(t, "ada@example.com", 1)
	creds := emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"}

	_, err := app.passwords.SignIn(ctx, creds)
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, behemotherr.CategoryForbidden, de.Category)
	assert.Equal(t, emailverification.ErrorCodeEmailNotVerified, de.Code)

	_, err = app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "a wrong password"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryUnauthorized), "a wrong password is not told the address is unverified: %v", err)

	_, err = app.plugin.Verify(ctx, mail.Token)
	require.NoError(t, err)
	result, err := app.passwords.SignIn(ctx, creds)
	require.NoError(t, err)
	assert.NotEmpty(t, result.RawToken)
}

// Links are limited per email from any caller, the automatic send included,
// and the limit answers the same for an email without an account.
func TestEmailVerificationSendsAreLimitedPerEmail(t *testing.T) {
	ctx := context.Background()
	app := bootVerification(t, emailverification.Options{SendLimit: types.Limit{Max: 2, Window: time.Minute}})
	user, _ := app.signUp(t, "ada@example.com", 1) // the first of the two

	_, err := app.plugin.SendVerification(ctx, emailverification.SendRequest{UserID: user.ID})
	require.NoError(t, err)
	app.mail(t, 2)
	_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{Email: "ADA@example.com"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryRateLimited), "the third link for the address: %v", err)

	for i := 1; i <= 2; i++ {
		_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{Email: "nobody@example.com"})
		assert.ErrorIs(t, err, emailverification.ErrNoAccount, "request %d", i)
	}
	_, err = app.plugin.SendVerification(ctx, emailverification.SendRequest{Email: "nobody@example.com"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryRateLimited), "an unknown email is counted too: %v", err)

	events := app.rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	require.Len(t, events, 2)
	assert.Equal(t, emailverification.RuleSendEmail, events[0].Metadata["rule"])
	assert.Equal(t, 2, app.outbox.count())
}

// LinkURL and a mail sender are required, and a missing one stops Boot.
func TestEmailVerificationOptions(t *testing.T) {
	sender := types.MailSenderFunc(func(context.Context, types.MailMessage) error { return nil })
	for name, tc := range map[string]struct {
		opts   emailverification.Options
		sender types.MailSender
	}{
		"no sender":      {emailverification.Options{LinkURL: "https://app.example.com/verify"}, nil},
		"no link URL":    {emailverification.Options{}, sender},
		"a negative TTL": {emailverification.Options{LinkURL: "https://app.example.com/verify", TTL: -time.Minute}, sender},
	} {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "verification-opts.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		_, err = db.Exec(magicLinkSchema)
		require.NoError(t, err)

		p := emailverification.New(tc.opts)
		_, err = p.Verify(context.Background(), "token")
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%s: a flow called before Boot: %v", name, err)

		prepared, err := bmth.Prepare([]types.Plugin{p}, bmth.PrepareConfig{})
		require.NoError(t, err, name)
		_, err = bmth.Boot(context.Background(), prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
			Crypto: crypto.Config{
				Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
			},
			Mail: types.MailConfig{Sender: tc.sender},
		})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "emailverification", name)
	}
}
