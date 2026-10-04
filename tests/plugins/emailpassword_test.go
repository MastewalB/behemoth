package plugins_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
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
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/transport"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	binit "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE users (
	id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT, firstname TEXT, lastname TEXT,
	email_verified BOOLEAN NOT NULL DEFAULT 0, image_url TEXT,
	created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE accounts (
	id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id TEXT NOT NULL, account_id TEXT NOT NULL,
	password_hash TEXT, access_token TEXT, refresh_token TEXT, id_token TEXT,
	access_token_expires_at TIMESTAMP, refresh_token_expires_at TIMESTAMP, scope TEXT,
	created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE (provider_id, account_id));
CREATE TABLE sessions (
	id TEXT PRIMARY KEY, user_id TEXT NOT NULL, lookup_hash TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL,
	key_version INTEGER NOT NULL, state TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, last_active_at TIMESTAMP,
	fresh_at TIMESTAMP, ip_address TEXT, user_agent TEXT, impersonator_id TEXT, revoked_at TIMESTAMP,
	revoked_reason TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);`

type passDispatcher struct{}

func (passDispatcher) RunBefore(_ *types.HookContext, _ types.HookPoint, p behemoth.M) (behemoth.M, error) {
	return p, nil
}
func (passDispatcher) RunAfter(*types.HookContext, types.HookPoint, any) error   { return nil }
func (passDispatcher) RunAfterTx(*types.HookContext, types.HookPoint, any) error { return nil }
func (passDispatcher) Fail(*types.HookContext, types.HookPoint, types.FailureReason) error {
	return nil
}

// authContext wires what Boot would, by hand, with a pass-through
// dispatcher. TestEmailPasswordThroughPrepareAndBoot covers the booted path.
func authContext(t *testing.T) *types.AuthContext {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "ep.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(schema)
	require.NoError(t, err)

	c, err := crypto.New(context.Background(), crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
	}, nil)
	require.NoError(t, err)

	st := store.New(sqliteAdapter.NewSQLiteAdapter(db, nil))
	return &types.AuthContext{
		Store:      st,
		Crypto:     c,
		Dispatcher: passDispatcher{},
		SessionManager: transport.NewSessionManager(st, nil, c,
			types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: types.TransportHeader},
			passDispatcher{}, nil, nil),
	}
}

// call invokes a plugin route the way the router does.
func call(t *testing.T, ac *types.AuthContext, route types.Route, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	rctx := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}, Auth: ac}
	rctx.Ctx = types.ContextWithRequest(req.Context(), rctx)
	err := route.Handler(rctx)
	w := httptest.NewRecorder()
	if err != nil {
		w.Code = http.StatusUnauthorized // the router's error mapping, approximated
		return w
	}
	rctx.Response.Flush(w)
	return w
}

func TestEmailPasswordSignUpAndSignInThroughTheStore(t *testing.T) {
	ctx := context.Background()
	ac := authContext(t)
	p := emailpassword.New(emailpassword.Options{})
	require.NoError(t, p.Init(ac))
	routes := map[string]types.Route{}
	for _, r := range p.Routes() {
		routes[r.Path] = r
	}

	w := call(t, ac, routes["/sign-up/email"],
		`{"email":"  Ada@Example.COM ","password":"correct horse","firstname":"Ada","email_verified":true,"role":"admin"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "PasswordHash", "the response never carries the password hash")
	assert.NotContains(t, w.Body.String(), "argon2", "the response never carries the password hash")

	stored, err := ac.Store.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", stored.Email, "stored normalized")
	assert.Equal(t, "Ada", stored.Firstname, "profile fields from the payload")
	assert.NotEmpty(t, stored.ID)
	credential, err := ac.Store.FindAccount(ctx, models.ProviderCredential, stored.ID)
	require.NoError(t, err, "signing up creates the user's credential account")
	assert.Equal(t, stored.ID, credential.UserID)
	assert.Contains(t, credential.PasswordHash, "argon2", "the hash is stored on the account")
	assert.False(t, stored.EmailVerified, "a client can't verify its own email")
	assert.Empty(t, stored.Extras(), "a client can't write arbitrary columns (mass assignment)")

	w = call(t, ac, routes["/sign-up/email"], `{"email":"ada@example.com","password":"another one"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "an existing email can't sign up again")

	w = call(t, ac, routes["/sign-in/email"], `{"email":"ADA@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "argon2")
	sessions, err := ac.Store.ListSessionsForUser(ctx, stored.ID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1, "signing in created a session")

	w = call(t, ac, routes["/sign-in/email"], `{"email":"ada@example.com","password":"wrong password"}`)
	assert.NotEqual(t, http.StatusOK, w.Code, "a wrong password is rejected")

	// A user who only has an OAuth account has no password to sign in with.
	oauthOnly := &models.User{Email: "grace@example.com"}
	require.NoError(t, ac.Store.CreateUser(ctx, oauthOnly))
	require.NoError(t, ac.Store.CreateAccount(ctx, &models.Account{UserID: oauthOnly.ID, ProviderID: "google", AccountID: "g-1"}))
	w = call(t, ac, routes["/sign-in/email"], `{"email":"grace@example.com","password":"correct horse"}`)
	assert.NotEqual(t, http.StatusOK, w.Code, "no credential account, no password sign-in")
}

func TestEmailPasswordPluginMetadata(t *testing.T) {
	p := emailpassword.New(emailpassword.Options{})
	assert.Equal(t, emailpassword.PluginName, p.Meta().Name)
	assert.Empty(t, p.Meta().MountPath, "routes sit directly under the base path")
	assert.Empty(t, p.Meta().Dependencies)
	assert.NotEmpty(t, p.Version())
	assert.Empty(t, p.Middlewares(), "no application-wide middleware")
}

// The plugin goes through Prepare and Boot like any other, and its flows
// dispatch through the real dispatcher: every point they fire is declared.
func TestEmailPasswordThroughPrepareAndBoot(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "ep-boot.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(schema)
	require.NoError(t, err)

	p := emailpassword.New(emailpassword.Options{})
	app, err := binit.Prepare([]types.Plugin{p}, binit.PrepareConfig{})
	require.NoError(t, err)
	assert.Equal(t, []string{emailpassword.PluginName}, app.Order)

	// The application observes the flows through hooks. The sign-in result
	// carries the raw session token, which the test needs to sign out.
	var fired []types.HookPoint
	var failures []string
	var rawToken string
	observe := func(point types.HookPoint) types.AfterHookFunc {
		return func(_ *types.HookContext, result any) error {
			fired = append(fired, point)
			if r, ok := result.(*emailpassword.SignInResult); ok {
				rawToken = r.RawToken
			}
			return nil
		}
	}
	ac, err := binit.Boot(ctx, app, sqliteAdapter.NewSQLiteAdapter(db, nil), binit.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session: types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: types.TransportHeader},
		Hooks: func(reg types.HookRegistry) error {
			for _, point := range []types.HookPoint{hooks.HookSignUpAfter, hooks.HookSignInAfter, hooks.HookSignOutAfter} {
				if err := reg.OnAfter(point, observe(point), nil); err != nil {
					return err
				}
			}
			return reg.OnFailed(hooks.HookSignInFailed, func(_ *types.HookContext, reason types.FailureReason) error {
				failures = append(failures, reason.Code)
				return nil
			}, nil)
		},
	})
	require.NoError(t, err)

	routes := map[string]types.Route{}
	for _, r := range p.Routes() {
		routes[r.Path] = r
	}
	require.Len(t, routes, 3)

	w := call(t, ac, routes["/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = call(t, ac, routes["/sign-in/email"], `{"email":"ada@example.com","password":"wrong password"}`)
	assert.NotEqual(t, http.StatusOK, w.Code)
	w = call(t, ac, routes["/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, rawToken)

	// Sign-out with its route middleware, the way the router mounts it.
	signOut := routes["/sign-out"].Handler
	for i := len(routes["/sign-out"].Middlewares) - 1; i >= 0; i-- {
		signOut = routes["/sign-out"].Middlewares[i](signOut)
	}
	signOutWith := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rctx := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}, Auth: ac}
		rctx.Ctx = types.ContextWithRequest(req.Context(), rctx)
		require.NoError(t, signOut(rctx))
		rec := httptest.NewRecorder()
		rctx.Response.Flush(rec)
		return rec
	}
	assert.Equal(t, http.StatusUnauthorized, signOutWith("").Code, "sign-out needs a session")
	assert.Equal(t, http.StatusOK, signOutWith(rawToken).Code)
	assert.Equal(t, http.StatusUnauthorized, signOutWith(rawToken).Code, "the session is revoked")

	assert.Equal(t, []types.HookPoint{hooks.HookSignUpAfter, hooks.HookSignInAfter, hooks.HookSignOutAfter}, fired)
	assert.Equal(t, []string{"invalidCredentials"}, failures)
}

// The email and password rules are the plugin's own options.
func TestEmailPasswordOptions(t *testing.T) {
	signUp := func(t *testing.T, opts emailpassword.Options, body string) int {
		t.Helper()
		ac := authContext(t)
		p := emailpassword.New(opts)
		require.NoError(t, p.Init(ac))
		for _, r := range p.Routes() {
			if r.Path == "/sign-up/email" {
				return call(t, ac, r, body).Code
			}
		}
		t.Fatal("no sign-up route")
		return 0
	}
	const ok, rejected = http.StatusCreated, http.StatusBadRequest

	t.Run("defaults", func(t *testing.T) {
		assert.Equal(t, ok, signUp(t, emailpassword.Options{}, `{"email":"a@example.com","password":"12345678"}`))
		assert.Equal(t, rejected, signUp(t, emailpassword.Options{}, `{"email":"a@example.com","password":"1234567"}`), "shorter than 8")
		assert.Equal(t, rejected, signUp(t, emailpassword.Options{},
			`{"email":"a@example.com","password":"`+strings.Repeat("x", 129)+`"}`), "longer than 128")
		assert.Equal(t, rejected, signUp(t, emailpassword.Options{}, `{"email":"not-an-email","password":"12345678"}`))
		assert.Equal(t, ok, signUp(t, emailpassword.Options{}, `{"email":"a@example.com","password":"пароль12"}`),
			"length is counted in characters, not bytes")
	})
	t.Run("custom limits and checks", func(t *testing.T) {
		opts := emailpassword.Options{
			MinPasswordLength: 12,
			ValidatePassword: func(pw string) error {
				if strings.Contains(pw, "password") {
					return errors.New("too common")
				}
				return nil
			},
			ValidateEmail: func(email string) error {
				if !strings.HasSuffix(email, "@example.com") {
					return errors.New("company addresses only")
				}
				return nil
			},
		}
		assert.Equal(t, ok, signUp(t, opts, `{"email":"a@example.com","password":"correct horse"}`))
		assert.Equal(t, rejected, signUp(t, opts, `{"email":"a@example.com","password":"12345678"}`), "below the custom minimum")
		assert.Equal(t, rejected, signUp(t, opts, `{"email":"a@example.com","password":"password-password"}`), "the extra check")
		assert.Equal(t, rejected, signUp(t, opts, `{"email":"a@other.org","password":"correct horse"}`), "the custom email check")
	})
	t.Run("contradicting limits fail Init", func(t *testing.T) {
		p := emailpassword.New(emailpassword.Options{MinPasswordLength: 20, MaxPasswordLength: 10})
		err := p.Init(authContext(t))
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	})
}
