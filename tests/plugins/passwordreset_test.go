package plugins_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	resetEmail       = "ada@example.com"
	resetOldPassword = "correct horse battery"
	resetNewPassword = "a brand new staple"
)

type resetApp struct {
	plugin  *emailpassword.Plugin
	ac      *types.AuthContext
	outbox  *outbox
	rec     *telemetrytest.Recorder
	mounted mountedRoutes
}

// bootReset boots the email/password plugin with reset enabled over a fresh
// database, and signs up "ada@example.com", whose email is not verified.
// The request waits for the sender unless opts says otherwise, so a test
// reads the outbox without polling.
func bootReset(t *testing.T, opts emailpassword.ResetOptions, hookFn func(reg types.HookRegistry) error) (*resetApp, *models.User) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "reset.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	app := &resetApp{outbox: &outbox{}, mounted: mountedRoutes{}}
	if opts.LinkURL == "" {
		opts.LinkURL = "https://app.example.com/auth/reset?from=email"
	}
	app.plugin = emailpassword.New(emailpassword.Options{Reset: opts})
	tel, rec := telemetrytest.New()
	app.rec = rec

	prepared, err := bmth.Prepare([]types.Plugin{app.plugin}, bmth.PrepareConfig{})
	require.NoError(t, err)
	app.ac, err = bmth.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session:   types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: types.TransportHeader},
		Mail:      types.MailConfig{Sender: app.outbox},
		Telemetry: tel,
		HTTP:      app.mounted,
		Hooks:     hookFn,
	})
	require.NoError(t, err)
	t.Cleanup(func() { app.ac.Mailer.Close(context.Background()) })

	user, err := app.plugin.SignUp(ctx, behemoth.M{"email": resetEmail, "password": resetOldPassword})
	require.NoError(t, err)
	return app, user
}

func (app *resetApp) signIn(password string) (*emailpassword.SignInResult, error) {
	return app.plugin.SignIn(context.Background(), emailpassword.EmailAndPasswordCredentials{Email: resetEmail, Password: password})
}

// link requests a reset for Ada and returns the message that was sent.
func (app *resetApp) link(t *testing.T) types.MailMessage {
	t.Helper()
	_, err := app.plugin.RequestPasswordReset(context.Background(), emailpassword.ResetRequest{Email: resetEmail})
	require.NoError(t, err)
	return app.outbox.last(t)
}

func invalidResetToken(err error) bool {
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	return ok && de.Category == behemotherr.CategoryUnauthorized && de.Code == emailpassword.ErrorCodeInvalidResetToken
}

// The two flows called from code: a link is sent to a known email only, a
// new link replaces the old one, and a link sets the password once, ends the
// user's sessions and marks the email verified.
func TestPasswordResetRequestAndConfirm(t *testing.T) {
	ctx := context.Background()
	var befores []behemoth.M
	var afters []any
	app, user := bootReset(t, emailpassword.ResetOptions{WaitForSend: true}, func(reg types.HookRegistry) error {
		if err := reg.OnBefore(emailpassword.HookResetBefore, func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
			befores = append(befores, payload)
			return behemoth.M{"password": "swapped by a handler"}, nil
		}, nil); err != nil {
			return err
		}
		return reg.OnAfter(emailpassword.HookResetAfter, func(_ *types.HookContext, result any) error {
			afters = append(afters, result)
			return nil
		}, nil)
	})
	p := app.plugin

	_, err := p.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: "nobody@example.com"})
	assert.ErrorIs(t, err, emailpassword.ErrNoAccount)
	_, err = p.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: "not an email"})
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)
	require.Zero(t, app.outbox.count(), "neither sent a link")

	before, err := app.signIn(resetOldPassword)
	require.NoError(t, err)

	sent, err := p.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: "  Ada@Example.com ", Metadata: behemoth.M{"locale": "fr"}})
	require.NoError(t, err)
	first := app.outbox.last(t)
	assert.Equal(t, types.MailPasswordReset, first.Kind)
	assert.Equal(t, resetEmail, first.To, "normalized")
	assert.Equal(t, behemoth.M{"locale": "fr"}, first.Metadata, "passed to the sender as given")
	assert.Equal(t, user.ID, first.User.ID)
	assert.WithinDuration(t, time.Now().Add(emailpassword.DefaultResetTTL), first.ExpiresAt, time.Minute)
	assert.Equal(t, &emailpassword.ResetRequestResult{UserID: user.ID, Email: resetEmail, TokenID: sent.TokenID, ExpiresAt: first.ExpiresAt}, sent)
	link, err := url.Parse(first.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/auth/reset", link.Scheme+"://"+link.Host+link.Path)
	assert.Equal(t, first.Token, link.Query().Get("token"))
	assert.Equal(t, "email", link.Query().Get("from"), "the query LinkURL came with is kept")

	// Asking for a link changes nothing yet.
	_, err = app.ac.SessionManager.Validate(ctx, before.RawToken)
	require.NoError(t, err, "the session is still live")

	// A second request replaces the first link.
	second := app.link(t)
	_, err = p.ResetPassword(ctx, first.Token, resetNewPassword)
	assert.True(t, invalidResetToken(err), "the replaced link: %v", err)

	// A password the rules refuse does not use the link up.
	_, err = p.ResetPassword(ctx, second.Token, "short")
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)

	reset, err := p.ResetPassword(ctx, second.Token, resetNewPassword)
	require.NoError(t, err)
	assert.Equal(t, user.ID, reset.ID)
	assert.True(t, reset.EmailVerified, "following the link verifies the address")
	stored, err := app.ac.Store.FindUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, stored.EmailVerified)

	_, err = app.signIn(resetOldPassword)
	assert.True(t, behemotherr.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "the old password: %v", err)
	_, err = app.signIn("swapped by a handler")
	assert.True(t, behemotherr.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "a before handler can't swap the password: %v", err)
	_, err = app.signIn(resetNewPassword)
	require.NoError(t, err, "the new password signs in")
	_, err = app.ac.SessionManager.Validate(ctx, before.RawToken)
	assert.Error(t, err, "the session from before the reset has ended")

	// The owner is told, in the background, by a message without a link.
	require.Eventually(t, func() bool { return app.outbox.last(t).Kind == types.MailPasswordChanged }, 5*time.Second, time.Millisecond)
	notice := app.outbox.last(t)
	assert.Equal(t, resetEmail, notice.To)
	assert.Equal(t, user.ID, notice.User.ID)
	assert.Empty(t, notice.Token)
	assert.Empty(t, notice.URL)
	assert.Equal(t, 3, app.outbox.count(), "two links and one notice: a refused reset sends none")

	_, err = p.ResetPassword(ctx, second.Token, "yet another password")
	assert.True(t, invalidResetToken(err), "a link works once: %v", err)
	_, err = p.ResetPassword(ctx, "not-a-token", "yet another password")
	assert.True(t, invalidResetToken(err), "an unknown token gets the same answer: %v", err)

	// auth.passwordReset.before saw the email and the password, never the
	// token. The call with the refused password went through it too.
	require.Len(t, befores, 5)
	assert.Equal(t, behemoth.M{"email": resetEmail, "password": resetNewPassword}, befores[2])
	assert.Equal(t, behemoth.M{"password": "yet another password"}, befores[4], "no email for a token that does not check out")
	require.Len(t, afters, 1)
	assert.Same(t, reset, afters[0])

	// Both flows are audited under the plugin's point names.
	requested := app.rec.Audit.OfType(string(emailpassword.HookResetRequestAfter))
	require.Len(t, requested, 2)
	assert.Equal(t, user.ID, requested[0].SubjectID)
	requestFailed := app.rec.Audit.OfType(string(emailpassword.HookResetRequestFailed))
	require.Len(t, requestFailed, 1)
	assert.Equal(t, "userNotFound", requestFailed[0].Metadata["code"])
	done := app.rec.Audit.OfType(string(emailpassword.HookResetAfter))
	require.Len(t, done, 1)
	assert.Equal(t, user.ID, done[0].SubjectID)
	failed := app.rec.Audit.OfType(string(emailpassword.HookResetFailed))
	require.Len(t, failed, 3)
	assert.Equal(t, "invalidToken", failed[0].Metadata["code"])
}

// The routes: the request route answers the same for a known email, an
// unknown one and a failed send, and the confirm route sets the password
// without signing the user in.
func TestPasswordResetRoutes(t *testing.T) {
	app, _ := bootReset(t, emailpassword.ResetOptions{WaitForSend: true}, nil)
	request := app.mounted["/api/auth"+emailpassword.PathResetRequest]
	confirm := app.mounted["/api/auth"+emailpassword.PathResetConfirm]
	require.NotNil(t, request.Handler)
	require.NotNil(t, confirm.Handler)
	assert.Equal(t, http.MethodPost, confirm.Method)

	known := call(t, app.ac, request, `{"email":"ada@example.com","metadata":{"locale":"fr"}}`)
	require.Equal(t, http.StatusOK, known.Code, known.Body.String())
	link := app.outbox.last(t)
	assert.Equal(t, behemoth.M{"locale": "fr"}, link.Metadata)

	unknown := call(t, app.ac, request, `{"email":"nobody@example.com"}`)
	assert.Equal(t, known.Code, unknown.Code)
	assert.Equal(t, known.Body.String(), unknown.Body.String(), "the response does not tell which emails have an account")
	assert.Equal(t, 1, app.outbox.count())

	app.outbox.err = errors.New("smtp down")
	failed := call(t, app.ac, request, `{"email":"ada@example.com"}`)
	assert.Equal(t, known.Code, failed.Code)
	assert.Equal(t, known.Body.String(), failed.Body.String(), "a failed send is not told apart either")
	assert.NotEmpty(t, app.rec.Logger.At(slog.LevelError), "it is logged instead")
	unsent := app.outbox.last(t)
	app.outbox.err = nil
	w := call(t, app.ac, confirm, `{"token":"`+unsent.Token+`","password":"`+resetNewPassword+`"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the link that was not sent is revoked")

	for body, want := range map[string]int{
		`{`:                        http.StatusBadRequest,
		`{"email":42}`:             http.StatusBadRequest,
		`{"email":"not an email"}`: http.StatusBadRequest,
		`{"email":"ada@example.com","metadata":"x"}`: http.StatusBadRequest,
	} {
		assert.Equal(t, want, call(t, app.ac, request, body).Code, "request body %s", body)
	}

	require.Equal(t, http.StatusOK, call(t, app.ac, request, `{"email":"ada@example.com"}`).Code)
	link = app.outbox.last(t)
	for body, why := range map[string]string{
		`{`: "not JSON",
		`{"password":"` + resetNewPassword + `"}`:           "no token",
		`{"token":"` + link.Token + `"}`:                    "no password",
		`{"token":"` + link.Token + `","password":"short"}`: "a password the rules refuse",
	} {
		assert.Equal(t, http.StatusBadRequest, call(t, app.ac, confirm, body).Code, why)
	}

	w = call(t, app.ac, confirm, `{"token":"`+link.Token+`","password":"`+resetNewPassword+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"status":"password_reset"}`, w.Body.String())
	assert.Empty(t, w.Header().Get(types.SessionTokenHeader), "a reset does not sign the user in")
	_, err := app.signIn(resetNewPassword)
	require.NoError(t, err)

	w = call(t, app.ac, confirm, `{"token":"`+link.Token+`","password":"`+resetNewPassword+`"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), emailpassword.ErrorCodeInvalidResetToken)
}

// Reset requests are limited per email from any caller, and the limit
// answers the same for an email without an account.
func TestPasswordResetRequestsAreLimitedPerEmail(t *testing.T) {
	ctx := context.Background()
	app, _ := bootReset(t, emailpassword.ResetOptions{WaitForSend: true, RequestLimit: types.Limit{Max: 2, Window: time.Minute}}, nil)
	limited := func(email string) bool {
		_, err := app.plugin.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: email})
		return behemotherr.Is(err, behemotherr.CategoryRateLimited)
	}
	for _, email := range []string{resetEmail, "nobody@example.com"} {
		assert.False(t, limited(email), email)
		assert.False(t, limited(strings.ToUpper(email)), "%s: the second request, in another spelling", email)
		assert.True(t, limited(email), "%s: the third request is refused", email)
	}
	assert.Equal(t, 2, app.outbox.count(), "only the known email was sent links")

	events := app.rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	require.Len(t, events, 2)
	assert.Equal(t, emailpassword.RuleResetRequestEmail, events[0].Metadata["rule"])
}

// A link stops working when the account it was sent for is no longer the
// one at that address.
func TestPasswordResetRefusals(t *testing.T) {
	ctx := context.Background()
	app, user := bootReset(t, emailpassword.ResetOptions{WaitForSend: true}, nil)
	p := app.plugin

	// The email changes after the link was sent.
	stale := app.link(t)
	_, err := app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: "ada@new.example.com"})
	require.NoError(t, err)
	_, err = p.ResetPassword(ctx, stale.Token, resetNewPassword)
	assert.True(t, invalidResetToken(err), "a link sent to the old address: %v", err)
	failures := app.rec.Audit.OfType(string(emailpassword.HookResetFailed))
	require.NotEmpty(t, failures)
	assert.Equal(t, "emailChanged", failures[len(failures)-1].Metadata["code"])
	assert.Equal(t, user.ID, failures[len(failures)-1].SubjectID)

	// The user is deleted after the link was sent: the link goes with it.
	_, err = p.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: "ada@new.example.com"})
	require.NoError(t, err)
	orphan := app.outbox.last(t)
	require.NoError(t, app.ac.Store.DeleteUser(ctx, user.ID))
	_, err = p.ResetPassword(ctx, orphan.Token, resetNewPassword)
	assert.True(t, invalidResetToken(err), "a deleted user's link: %v", err)
}

// A user who never had a password gets one from a reset, and with
// LeaveEmailUnverified the reset does not touch the verified flag.
func TestPasswordResetWithoutAPasswordAndLeavingEmailUnverified(t *testing.T) {
	ctx := context.Background()
	app, _ := bootReset(t, emailpassword.ResetOptions{WaitForSend: true, LeaveEmailUnverified: true}, nil)

	grace := &models.User{Email: "grace@example.com"}
	require.NoError(t, app.ac.Store.CreateUser(ctx, grace))
	_, err := app.plugin.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: grace.Email})
	require.NoError(t, err)

	reset, err := app.plugin.ResetPassword(ctx, app.outbox.last(t).Token, resetNewPassword)
	require.NoError(t, err)
	assert.False(t, reset.EmailVerified, "the option leaves the flag alone")
	stored, err := app.ac.Store.FindUserByID(ctx, grace.ID)
	require.NoError(t, err)
	assert.False(t, stored.EmailVerified)

	result, err := app.plugin.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: grace.Email, Password: resetNewPassword})
	require.NoError(t, err, "the reset created the credential account")
	assert.Equal(t, grace.ID, result.User.ID)
}

// Reset is off without a link URL: no routes, no mail sender needed. Turned
// on, it needs a sender and an absolute URL, and a missing one stops Boot.
func TestPasswordResetOptions(t *testing.T) {
	boot := func(t *testing.T, opts emailpassword.ResetOptions, sender types.MailSender) (*emailpassword.Plugin, mountedRoutes, error) {
		t.Helper()
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "reset-opts.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		_, err = db.Exec(magicLinkSchema)
		require.NoError(t, err)
		p := emailpassword.New(emailpassword.Options{Reset: opts})
		mounted := mountedRoutes{}
		prepared, err := bmth.Prepare([]types.Plugin{p}, bmth.PrepareConfig{})
		require.NoError(t, err)
		_, err = bmth.Boot(context.Background(), prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
			Crypto: crypto.Config{
				Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
			},
			Mail: types.MailConfig{Sender: sender},
			HTTP: mounted,
		})
		return p, mounted, err
	}
	sender := types.MailSenderFunc(func(context.Context, types.MailMessage) error { return nil })

	t.Run("off by default", func(t *testing.T) {
		p, mounted, err := boot(t, emailpassword.ResetOptions{}, nil)
		require.NoError(t, err, "no sender is needed")
		assert.NotContains(t, mounted, "/api/auth"+emailpassword.PathResetRequest)
		assert.NotContains(t, mounted, "/api/auth"+emailpassword.PathResetConfirm)
		_, err = p.RequestPasswordReset(context.Background(), emailpassword.ResetRequest{Email: resetEmail})
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
		_, err = p.ResetPassword(context.Background(), "token", resetNewPassword)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	})
	for name, tc := range map[string]struct {
		opts   emailpassword.ResetOptions
		sender types.MailSender
	}{
		"no sender":           {emailpassword.ResetOptions{LinkURL: "https://app.example.com/auth/reset"}, nil},
		"a relative link URL": {emailpassword.ResetOptions{LinkURL: "/auth/reset"}, sender},
		"a negative TTL":      {emailpassword.ResetOptions{LinkURL: "https://app.example.com/auth/reset", TTL: -time.Minute}, sender},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := boot(t, tc.opts, tc.sender)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "emailpassword")
		})
	}
}

// By default the request does not wait for the sender: it returns while the
// sender is still blocked, and a failed send leaves the link valid.
func TestPasswordResetSendsInBackground(t *testing.T) {
	ctx := context.Background()
	app, user := bootReset(t, emailpassword.ResetOptions{}, nil)
	app.outbox.err = errors.New("smtp down")

	app.outbox.mu.Lock() // the sender blocks until the request has returned
	_, err := app.plugin.RequestPasswordReset(ctx, emailpassword.ResetRequest{Email: resetEmail})
	app.outbox.mu.Unlock()
	require.NoError(t, err, "the request did not wait for the sender, and does not see its error")

	require.Eventually(t, func() bool { return app.outbox.count() == 1 }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return len(app.rec.Logger.At(slog.LevelError)) == 1 }, 5*time.Second, time.Millisecond,
		"the mailer logs the failed send")
	reset, err := app.plugin.ResetPassword(ctx, app.outbox.last(t).Token, resetNewPassword)
	require.NoError(t, err, "the link was not revoked: nobody was waiting for the send")
	assert.Equal(t, user.ID, reset.ID)
}
