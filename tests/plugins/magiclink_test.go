package plugins_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/magiclink"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const magicLinkSchema = schema + `
CREATE TABLE rate_limits (limit_key TEXT PRIMARY KEY, count BIGINT NOT NULL, expires_at TIMESTAMP NOT NULL);
CREATE TABLE tokens (
	id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT, lookup_hash TEXT NOT NULL, token_hash TEXT NOT NULL,
	key_version INTEGER NOT NULL, metadata TEXT, expires_at TIMESTAMP, consumed_at TIMESTAMP, revoked_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL);`

// outbox is a MailSender that keeps what it was asked to send, and fails
// when told to. The lock is for background sends.
type outbox struct {
	mu    sync.Mutex
	links []types.MailMessage
	err   error
}

func (o *outbox) Send(_ context.Context, msg types.MailMessage) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.links = append(o.links, msg)
	return o.err
}

func (o *outbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.links)
}

func (o *outbox) last(t *testing.T) types.MailMessage {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	require.NotEmpty(t, o.links, "no link was sent")
	return o.links[len(o.links)-1]
}

type magicLinkApp struct {
	plugin  *magiclink.Plugin
	ac      *types.AuthContext
	outbox  *outbox
	rec     *telemetrytest.Recorder
	mounted mountedRoutes
}

// bootMagicLink boots the plugin alone over a fresh database, with one
// trusted origin and a user "ada@example.com" whose email is not verified.
func bootMagicLink(t *testing.T, opts magiclink.Options, hookFn func(reg types.HookRegistry) error) (*magicLinkApp, *models.User) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "magiclink.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	app := &magicLinkApp{outbox: &outbox{}, mounted: mountedRoutes{}}
	if opts.LinkURL == "" {
		opts.LinkURL = "https://app.example.com/auth/magic?from=email"
	}
	app.plugin = magiclink.New(opts)
	tel, rec := telemetrytest.New()
	app.rec = rec

	prepared, err := bmth.Prepare([]types.Plugin{app.plugin}, bmth.PrepareConfig{})
	require.NoError(t, err)
	app.ac, err = bmth.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session:   types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: types.TransportHeader},
		Router:    types.RouterConfig{TrustedOrigins: []string{"https://app.example.com"}},
		Mail:      types.MailConfig{Sender: app.outbox},
		Telemetry: tel,
		HTTP:      app.mounted,
		Hooks:     hookFn,
	})
	require.NoError(t, err)
	t.Cleanup(func() { app.ac.Mailer.Close(context.Background()) })

	user := &models.User{Email: "ada@example.com"}
	require.NoError(t, app.ac.Store.CreateUser(ctx, user))
	return app, user
}

func invalidLink(err error) bool {
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	return ok && de.Category == behemotherr.CategoryUnauthorized && de.Code == magiclink.ErrorCodeInvalidLink
}

// The two flows called from code, without an HTTP request: a link is sent
// to a known email only, a new link replaces the old one, and a link signs
// its user in once.
func TestMagicLinkRequestAndVerify(t *testing.T) {
	ctx := context.Background()
	type signInBefore struct{ payload, values behemoth.M }
	var befores []signInBefore
	var afters []any
	app, user := bootMagicLink(t, magiclink.Options{WaitForSend: true}, func(reg types.HookRegistry) error {
		if err := reg.OnBefore(hooks.HookSignInBefore, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
			befores = append(befores, signInBefore{payload, behemoth.M{hooks.HookValueEmail: hctx.Values[hooks.HookValueEmail]}})
			return nil, nil
		}, nil); err != nil {
			return err
		}
		return reg.OnAfter(hooks.HookSignInAfter, func(_ *types.HookContext, result any) error {
			afters = append(afters, result)
			return nil
		}, nil)
	})
	p := app.plugin

	_, err := p.RequestLink(ctx, magiclink.LinkRequest{Email: "nobody@example.com"})
	assert.ErrorIs(t, err, magiclink.ErrNoAccount, "the plugin does not sign users up")
	_, err = p.RequestLink(ctx, magiclink.LinkRequest{Email: "not an email"})
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)
	for _, redirect := range []string{"https://evil.example.com/", "//evil.example.com", "http://app.example.com/"} {
		_, err = p.RequestLink(ctx, magiclink.LinkRequest{Email: "ada@example.com", RedirectURL: redirect})
		assert.True(t, behemotherr.IsValidationError(err), "redirect %q: %v", redirect, err)
	}
	require.Zero(t, app.outbox.count(), "none of these sent a link")

	sent, err := p.RequestLink(ctx, magiclink.LinkRequest{
		Email: "  Ada@Example.com ", RedirectURL: "https://app.example.com/welcome", Metadata: behemoth.M{"locale": "fr"},
	})
	require.NoError(t, err)
	first := app.outbox.last(t)
	assert.Equal(t, types.MailMagicLink, first.Kind)
	assert.Equal(t, "ada@example.com", first.To, "normalized")
	assert.Equal(t, behemoth.M{"locale": "fr"}, first.Metadata, "passed to the sender as given")
	assert.Equal(t, user.ID, first.User.ID)
	assert.WithinDuration(t, time.Now().Add(magiclink.DefaultTTL), first.ExpiresAt, time.Minute)
	assert.Equal(t, &magiclink.LinkResult{UserID: user.ID, Email: "ada@example.com", TokenID: sent.TokenID, ExpiresAt: first.ExpiresAt}, sent)
	link, err := url.Parse(first.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/auth/magic", link.Scheme+"://"+link.Host+link.Path)
	assert.Equal(t, first.Token, link.Query().Get("token"))
	assert.Equal(t, "email", link.Query().Get("from"), "the query LinkURL came with is kept")

	// A second request replaces the first link.
	_, err = p.RequestLink(ctx, magiclink.LinkRequest{Email: "ada@example.com", RedirectURL: "/dashboard"})
	require.NoError(t, err)
	second := app.outbox.last(t)
	_, err = p.Verify(ctx, first.Token)
	assert.True(t, invalidLink(err), "the replaced link: %v", err)

	result, err := p.Verify(ctx, second.Token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)
	assert.True(t, result.User.EmailVerified, "following the link verifies the address")
	assert.Equal(t, models.SessionActive, result.Session.State)
	assert.Equal(t, magiclink.PluginName, result.Method)
	assert.Equal(t, "/dashboard", result.RedirectURL)
	stored, err := app.ac.Store.FindUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, stored.EmailVerified)
	session, err := app.ac.SessionManager.Validate(ctx, result.RawToken)
	require.NoError(t, err, "the session token works")
	assert.Equal(t, user.ID, session.UserID)

	_, err = p.Verify(ctx, second.Token)
	assert.True(t, invalidLink(err), "a link works once: %v", err)
	_, err = p.Verify(ctx, "not-a-token")
	assert.True(t, invalidLink(err), "an unknown token gets the same answer: %v", err)

	// auth.signIn.before saw the email and the method, never the token.
	known := signInBefore{behemoth.M{"method": "magiclink", "email": "ada@example.com"}, behemoth.M{hooks.HookValueEmail: "ada@example.com"}}
	unknown := signInBefore{behemoth.M{"method": "magiclink"}, behemoth.M{hooks.HookValueEmail: nil}}
	assert.Equal(t, []signInBefore{unknown, known, unknown, unknown}, befores)
	require.Len(t, afters, 1)
	assert.Same(t, result.SignInResult, afters[0], "auth.signIn.after gets the shared *types.SignInResult")

	// The request points are audited under the plugin's point names.
	requested := app.rec.Audit.OfType(string(magiclink.HookRequestAfter))
	require.Len(t, requested, 2)
	assert.Equal(t, user.ID, requested[0].SubjectID)
	failed := app.rec.Audit.OfType(string(magiclink.HookRequestFailed))
	require.Len(t, failed, 1)
	assert.Equal(t, "userNotFound", failed[0].Metadata["code"])
	assert.Equal(t, "nobody@example.com", failed[0].Metadata[hooks.HookValueEmail])
}

// The routes: the request route answers the same for a known email, an
// unknown one and a failed send, and the verify route is a POST that
// returns the user and the redirect.
func TestMagicLinkRoutes(t *testing.T) {
	app, user := bootMagicLink(t, magiclink.Options{WaitForSend: true}, nil)
	request := app.mounted["/api/auth"+magiclink.PathRequest]
	verify := app.mounted["/api/auth"+magiclink.PathVerify]
	require.NotNil(t, request.Handler)
	require.NotNil(t, verify.Handler)
	assert.Equal(t, http.MethodPost, verify.Method, "a GET would let a mail scanner use the link up")

	known := call(t, app.ac, request, `{"email":"ada@example.com","redirectURL":"/dashboard","metadata":{"locale":"fr"}}`)
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
	_, err := app.plugin.Verify(context.Background(), unsent.Token)
	assert.True(t, invalidLink(err), "the link that was not sent is revoked: %v", err)
	_, err = app.plugin.Verify(context.Background(), link.Token)
	assert.True(t, invalidLink(err), "and it had already replaced the earlier one: %v", err)
	app.outbox.err = nil

	for body, want := range map[string]int{
		`{`:                        http.StatusBadRequest,
		`{"email":42}`:             http.StatusBadRequest,
		`{"email":"not an email"}`: http.StatusBadRequest,
		`{"email":"ada@example.com","redirectURL":"https://evil.example.com/"}`: http.StatusBadRequest,
		`{"email":"ada@example.com","metadata":"x"}`:                            http.StatusBadRequest,
	} {
		assert.Equal(t, want, call(t, app.ac, request, body).Code, "request body %s", body)
	}

	require.Equal(t, http.StatusOK, call(t, app.ac, request, `{"email":"ada@example.com","redirectURL":"/dashboard"}`).Code)
	link = app.outbox.last(t)
	assert.Equal(t, http.StatusBadRequest, call(t, app.ac, verify, `{}`).Code, "a verify without a token")

	w := call(t, app.ac, verify, `{"token":"`+link.Token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		User        models.User `json:"user"`
		RedirectURL string      `json:"redirectURL"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, user.ID, body.User.ID)
	assert.Equal(t, "/dashboard", body.RedirectURL)
	// The route answers like every sign-in: the session token travels by
	// the configured transport, here the response header.
	session, err := app.ac.SessionManager.Validate(context.Background(), w.Header().Get(types.SessionTokenHeader))
	require.NoError(t, err, "the %s header carries the session token", types.SessionTokenHeader)
	assert.Equal(t, user.ID, session.UserID)
	assert.NotContains(t, w.Body.String(), `"token"`, "and the body does not")

	w = call(t, app.ac, verify, `{"token":"`+link.Token+`"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), magiclink.ErrorCodeInvalidLink)
}

// Link requests are limited per email from any caller, and the limit
// answers the same for an email without an account.
func TestMagicLinkRequestsAreLimitedPerEmail(t *testing.T) {
	ctx := context.Background()
	app, _ := bootMagicLink(t, magiclink.Options{WaitForSend: true, RequestLimit: types.Limit{Max: 2, Window: time.Minute}}, nil)
	limited := func(email string) bool {
		_, err := app.plugin.RequestLink(ctx, magiclink.LinkRequest{Email: email})
		return behemotherr.Is(err, behemotherr.CategoryRateLimited)
	}
	for _, email := range []string{"ada@example.com", "nobody@example.com"} {
		assert.False(t, limited(email), email)
		assert.False(t, limited(strings.ToUpper(email)), "%s: the second request, in another spelling", email)
		assert.True(t, limited(email), "%s: the third request is refused", email)
	}
	assert.Equal(t, 2, app.outbox.count(), "only the known email was sent links")

	events := app.rec.Audit.OfType(telemetry.AuditRateLimitExceeded)
	require.Len(t, events, 2)
	assert.Equal(t, magiclink.RuleRequestEmail, events[0].Metadata["rule"])
}

// A link stops working when the account it was sent for is no longer the
// one at that address, and a second-factor handler makes the session
// pending as it does for a password sign-in.
func TestMagicLinkVerifyRefusalsAndSecondFactor(t *testing.T) {
	ctx := context.Background()
	stepUp := false
	app, user := bootMagicLink(t, magiclink.Options{WaitForSend: true}, func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
			payload["requireStepUp"] = stepUp
			return payload, nil
		}, nil)
	})
	p := app.plugin
	link := func() types.MailMessage {
		_, err := p.RequestLink(ctx, magiclink.LinkRequest{Email: "ada@example.com"})
		require.NoError(t, err)
		return app.outbox.last(t)
	}

	stepUp = true
	result, err := p.Verify(ctx, link().Token)
	require.NoError(t, err)
	assert.Equal(t, models.SessionPending, result.Session.State, "a second factor is still asked for")
	stepUp = false

	// The email changes after the link was sent.
	stale := link()
	_, err = app.ac.Store.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmail: "ada@new.example.com"})
	require.NoError(t, err)
	_, err = p.Verify(ctx, stale.Token)
	assert.True(t, invalidLink(err), "a link sent to the old address: %v", err)
	failures := app.rec.Audit.OfType(string(hooks.HookSignInFailed))
	require.NotEmpty(t, failures)
	assert.Equal(t, "emailChanged", failures[len(failures)-1].Metadata["code"])
	assert.Equal(t, user.ID, failures[len(failures)-1].SubjectID)

	// The user is deleted after the link was sent: the link goes with it.
	_, err = p.RequestLink(ctx, magiclink.LinkRequest{Email: "ada@new.example.com"})
	require.NoError(t, err)
	orphan := app.outbox.last(t)
	require.NoError(t, app.ac.Store.DeleteUser(ctx, user.ID))
	_, err = p.Verify(ctx, orphan.Token)
	assert.True(t, invalidLink(err), "a deleted user's link: %v", err)
}

// LinkURL and a mail sender are required, and a missing one stops Boot.
func TestMagicLinkOptions(t *testing.T) {
	sender := types.MailSenderFunc(func(context.Context, types.MailMessage) error { return nil })
	for name, tc := range map[string]struct {
		opts   magiclink.Options
		sender types.MailSender
	}{
		"no sender":           {magiclink.Options{LinkURL: "https://app.example.com/auth/magic"}, nil},
		"no link URL":         {magiclink.Options{}, sender},
		"a relative link URL": {magiclink.Options{LinkURL: "/auth/magic"}, sender},
		"a negative TTL":      {magiclink.Options{LinkURL: "https://app.example.com/auth/magic", TTL: -time.Minute}, sender},
	} {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "magiclink-opts.db"))
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		_, err = db.Exec(magicLinkSchema)
		require.NoError(t, err)

		p := magiclink.New(tc.opts)
		_, err = p.RequestLink(context.Background(), magiclink.LinkRequest{Email: "ada@example.com"})
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
		assert.Contains(t, err.Error(), "magiclink", name)
	}
}

// By default the request does not wait for the sender: it
// returns while the sender is still blocked, and a failed send leaves the
// link valid.
func TestMagicLinkSendsInBackground(t *testing.T) {
	ctx := context.Background()
	app, user := bootMagicLink(t, magiclink.Options{}, nil)
	app.outbox.err = errors.New("smtp down")

	app.outbox.mu.Lock() // the sender blocks until the request has returned
	_, err := app.plugin.RequestLink(ctx, magiclink.LinkRequest{Email: "ada@example.com"})
	app.outbox.mu.Unlock()
	require.NoError(t, err, "the request did not wait for the sender, and does not see its error")

	require.Eventually(t, func() bool { return app.outbox.count() == 1 }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return len(app.rec.Logger.At(slog.LevelError)) == 1 }, 5*time.Second, time.Millisecond,
		"the mailer logs the failed send")
	result, err := app.plugin.Verify(ctx, app.outbox.last(t).Token)
	require.NoError(t, err, "the link was not revoked: nobody was waiting for the send")
	assert.Equal(t, user.ID, result.User.ID)
}

// With LeaveEmailUnverified a magic link signs the user in and leaves the
// verified flag as it was.
func TestMagicLinkLeavesEmailUnverified(t *testing.T) {
	ctx := context.Background()
	app, user := bootMagicLink(t, magiclink.Options{WaitForSend: true, LeaveEmailUnverified: true}, nil)
	_, err := app.plugin.RequestLink(ctx, magiclink.LinkRequest{Email: user.Email})
	require.NoError(t, err)
	result, err := app.plugin.Verify(ctx, app.outbox.last(t).Token)
	require.NoError(t, err)
	assert.False(t, result.User.EmailVerified)
	stored, err := app.ac.Store.FindUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, stored.EmailVerified)
}
