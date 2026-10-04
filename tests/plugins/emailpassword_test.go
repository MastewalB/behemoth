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
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/transport"
	"github.com/MastewalB/behemoth/types"
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

// acceptAll is a stand-in Validator: none ships with behemoth yet.
type acceptAll struct{}

func (acceptAll) ValidateEmail(email string) error {
	if !strings.Contains(email, "@") {
		return errors.New("invalid email")
	}
	return nil
}
func (acceptAll) ValidatePassword(password string, _ types.PasswordOptions) error {
	if len(password) < 8 {
		return errors.New("too short")
	}
	return nil
}

type passDispatcher struct{}

func (passDispatcher) RunBefore(_ *types.HookContext, _ types.HookPoint, p behemoth.M) (behemoth.M, error) {
	return p, nil
}
func (passDispatcher) RunAfter(*types.HookContext, types.HookPoint, any) error   { return nil }
func (passDispatcher) RunAfterTx(*types.HookContext, types.HookPoint, any) error { return nil }
func (passDispatcher) Fail(*types.HookContext, types.HookPoint, types.FailureReason) error {
	return nil
}

// authContext wires what Boot would, by hand: the plugin can't go through
// Prepare/Boot yet (its Meta and Declare are unimplemented).
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
		Store:           st,
		Crypto:          c,
		Dispatcher:      passDispatcher{},
		Validator:       acceptAll{},
		PasswordOptions: types.PasswordOptions{PasswordHasher: c.Passwords},
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
	p := emailpassword.New(types.AuthContext{})
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
