package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	binit "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
)

// usersDB opens a SQLite database with the users table models.User maps to.
// (Until core declares its tables, the test creates it by hand.)
func usersDB(t *testing.T) behemoth.Database {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "store.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE users (
		id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT, firstname TEXT, lastname TEXT,
		password_hash TEXT, email_verified BOOLEAN NOT NULL DEFAULT 0, image_url TEXT,
		created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)`)
	require.NoError(t, err)
	return sqliteAdapter.NewSQLiteAdapter(db, nil)
}

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func fixedClock(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		t := times[min(i, len(times)-1)]
		i++
		return t
	}
}

func sequentialIDs() func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("id-%d", n) }
}

type recordingHooks struct {
	tables    []string
	rewrite   behemoth.M
	abort     error
	createdAs []behemoth.Model

	updateIDs     []any
	updateSeen    []behemoth.M
	updateRewrite behemoth.M
	updateAbort   error
	updatedAs     []behemoth.Model
}

func (h *recordingHooks) BeforeUpdate(_ context.Context, table string, id any, changes behemoth.M) (behemoth.M, error) {
	h.updateIDs = append(h.updateIDs, id)
	seen := behemoth.M{}
	for k, v := range changes {
		seen[k] = v
	}
	h.updateSeen = append(h.updateSeen, seen)
	if h.updateAbort != nil {
		return nil, h.updateAbort
	}
	for k, v := range h.updateRewrite {
		changes[k] = v
	}
	return changes, nil
}

func (h *recordingHooks) AfterUpdate(_ context.Context, table string, updated behemoth.Model) {
	h.updatedAs = append(h.updatedAs, updated)
}

func (h *recordingHooks) BeforeCreate(_ context.Context, table string, row behemoth.M) (behemoth.M, error) {
	h.tables = append(h.tables, table)
	if h.abort != nil {
		return nil, h.abort
	}
	for k, v := range h.rewrite {
		row[k] = v
	}
	return row, nil
}

func (h *recordingHooks) AfterCreate(_ context.Context, table string, created behemoth.Model) {
	h.createdAs = append(h.createdAs, created)
}

func TestCreateUserAssignsIDTimestampsAndNormalizedEmail(t *testing.T) {
	ctx := context.Background()
	s := store.New(usersDB(t), store.WithClock(fixedClock(t0)), store.WithIDs(sequentialIDs()))

	u := &models.User{Email: "  Ada@Example.COM ", Username: "ada"}
	require.NoError(t, s.CreateUser(ctx, u))
	assert.Equal(t, "id-1", u.ID)
	assert.Equal(t, "ada@example.com", u.Email)
	assert.True(t, u.CreatedAt.Equal(t0) && u.UpdatedAt.Equal(t0))

	found, err := s.FindUserByEmail(ctx, "ADA@example.com")
	require.NoError(t, err, "lookup normalizes the same way creation does")
	assert.Equal(t, "id-1", found.ID)
	assert.True(t, found.CreatedAt.Equal(t0), "created_at is a real timestamp, got %v", found.CreatedAt)

	byID, err := s.FindUserByID(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, "ada", byID.Username)
}

func TestCreateUserRunsHooks(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{rewrite: behemoth.M{models.UserUsername: "from-hook"}}
	s := store.New(usersDB(t), store.WithHooks(h))

	u := &models.User{Email: "a@example.com", Username: "mine"}
	require.NoError(t, s.CreateUser(ctx, u))
	assert.Equal(t, []string{models.UserTable}, h.tables)
	assert.Equal(t, "from-hook", u.Username, "the caller's model reflects the hook's rewrite")

	stored, err := s.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "from-hook", stored.Username, "the hook's rewrite is what was stored")
	require.Len(t, h.createdAs, 1)
	assert.Same(t, u, h.createdAs[0], "AfterCreate receives the stored model")
}

func TestCreateUserHookErrorAborts(t *testing.T) {
	ctx := context.Background()
	abort := errors.New("rejected by hook")
	h := &recordingHooks{abort: abort}
	s := store.New(usersDB(t), store.WithHooks(h))

	err := s.CreateUser(ctx, &models.User{Email: "a@example.com"})
	assert.ErrorIs(t, err, abort)
	_, err = s.FindUserByEmail(ctx, "a@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "nothing was written: %v", err)
	assert.Empty(t, h.createdAs, "AfterCreate never ran")
}

func TestCreateHookAddingUnknownColumnIsRejected(t *testing.T) {
	ctx := context.Background()
	s := store.New(usersDB(t), store.WithHooks(&recordingHooks{rewrite: behemoth.M{"nickname": "x"}}))

	err := s.CreateUser(ctx, &models.User{Email: "a@example.com"})
	require.Error(t, err)
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)
	assert.Contains(t, errors.Unwrap(err).Error(), "nickname")
	_, err = s.FindUserByEmail(ctx, "a@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "nothing was written: %v", err)
}

func TestUpdateUserRunsHooks(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{updateRewrite: behemoth.M{models.UserEmail: " Hooked@Example.com"}}
	s := store.New(usersDB(t), store.WithHooks(h))
	u := &models.User{Email: "a@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))

	updates := behemoth.M{models.UserFirstname: "Ada"}
	updated, err := s.UpdateUser(ctx, u.ID, updates)
	require.NoError(t, err)

	require.Len(t, h.updateIDs, 1)
	assert.Equal(t, u.ID, h.updateIDs[0], "the hook is told which row")
	assert.Equal(t, behemoth.M{models.UserFirstname: "Ada"}, h.updateSeen[0], "the hook sees only the changes — no id, no updated_at")
	assert.Equal(t, "hooked@example.com", updated.Email, "the hook's rewrite is applied, and normalized")
	assert.Equal(t, "Ada", updated.Firstname)
	assert.Equal(t, behemoth.M{models.UserFirstname: "Ada"}, updates, "the caller's map is not modified")
	require.Len(t, h.updatedAs, 1)
	assert.Equal(t, "hooked@example.com", h.updatedAs[0].(*models.User).Email, "AfterUpdate receives the stored row")
}

func TestUpdateUserHookErrorsAndRewritesAreChecked(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	s := store.New(usersDB(t), store.WithHooks(h))
	u := &models.User{Email: "a@example.com", Firstname: "Ada"}
	require.NoError(t, s.CreateUser(ctx, u))
	unchanged := func() {
		t.Helper()
		got, err := s.FindUserByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, "Ada", got.Firstname, "nothing was written")
	}

	h.updateAbort = errors.New("rejected by hook")
	_, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Grace"})
	assert.ErrorIs(t, err, h.updateAbort)
	unchanged()

	h.updateAbort, h.updateRewrite = nil, behemoth.M{models.UserID: "someone-else"}
	_, err = s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Grace"})
	assert.True(t, behemotherr.IsValidationError(err), "a hook can't change the primary key: %v", err)
	unchanged()

	h.updateRewrite = behemoth.M{"nickname": "x"}
	_, err = s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Grace"})
	assert.True(t, behemotherr.IsValidationError(err), "a hook can't add an unknown column: %v", err)
	unchanged()
	assert.Empty(t, h.updatedAs, "AfterUpdate never ran")
}

func TestUpdateUserRejectsPrimaryKey(t *testing.T) {
	ctx := context.Background()
	s := store.New(usersDB(t))
	u := &models.User{Email: "a@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	_, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserID: "other"})
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)
}

func TestUpdateUser(t *testing.T) {
	ctx := context.Background()
	t1 := t0.Add(time.Hour)
	s := store.New(usersDB(t), store.WithClock(fixedClock(t0, t1)), store.WithIDs(sequentialIDs()))
	u := &models.User{Email: "a@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))

	updated, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserEmail: " New@Example.com", models.UserFirstname: "Ada"})
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", updated.Email)
	assert.Equal(t, "Ada", updated.Firstname)
	assert.True(t, updated.UpdatedAt.Equal(t1), "updated_at is stamped, got %v", updated.UpdatedAt)
	assert.True(t, updated.CreatedAt.Equal(t0), "created_at is untouched")

	_, err = s.UpdateUser(ctx, u.ID, behemoth.M{"firstnmae": "typo"})
	require.Error(t, err)
	assert.True(t, behemotherr.IsValidationError(err), "an unknown column is a validation error: %v", err)
	assert.Contains(t, errors.Unwrap(err).Error(), "firstnmae", "the cause names the column")
	unchanged, err := s.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "Ada", unchanged.Firstname, "a rejected update writes nothing")
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	s := store.New(usersDB(t))
	u := &models.User{Email: "a@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	require.NoError(t, s.DeleteUser(ctx, u.ID))
	_, err := s.FindUserByID(ctx, u.ID)
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)
}

// usernamePlugin registers a data.user.beforeCreate handler — the real
// dispatch path a plugin would use.
type usernamePlugin struct{}

func (usernamePlugin) Meta() types.PluginMeta                 { return types.PluginMeta{Name: "usernames"} }
func (usernamePlugin) Version() string                        { return "0.0.0" }
func (usernamePlugin) Init(*types.AuthContext) error          { return nil }
func (usernamePlugin) Routes() []types.Route                  { return nil }
func (usernamePlugin) Middlewares() []types.Middleware        { return nil }
func (usernamePlugin) Declare(*types.PluginInitContext) error { return nil }
func (usernamePlugin) RegisterHooks() []types.Listener        { return nil }
func (usernamePlugin) Register(reg types.HookRegistry) error {
	if err := reg.OnBefore(hooks.HookUserBeforeCreate, func(hctx *types.HookContext, row behemoth.M) (behemoth.M, error) {
		email, _ := row[models.UserEmail].(string)
		row[models.UserUsername] = strings.SplitN(email, "@", 2)[0]
		return row, nil
	}, nil); err != nil {
		return err
	}
	// On update, keep the username in step with a changed email, and record
	// which user it was (published in Values, not in the payload).
	return reg.OnBefore(hooks.HookUserBeforeUpdate, func(hctx *types.HookContext, changes behemoth.M) (behemoth.M, error) {
		if email, ok := changes[models.UserEmail].(string); ok {
			changes[models.UserUsername] = strings.SplitN(email, "@", 2)[0]
		}
		if id, _ := hctx.Values[hooks.HookValueUserID].(string); id != "" {
			changes[models.UserLastname] = "updated:" + id
		}
		return changes, nil
	}, nil)
}

// End to end: Boot wires AuthContext.Store to the Dispatcher, so a plugin's
// data.user.beforeCreate handler shapes the stored user.
func TestBootWiresStoreToPluginHooks(t *testing.T) {
	ctx := context.Background()
	app, err := binit.Prepare([]types.Plugin{usernamePlugin{}}, binit.PrepareConfig{})
	require.NoError(t, err)
	ac, err := binit.Boot(ctx, app, usersDB(t), binit.BootConfig{Crypto: crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
	}})
	require.NoError(t, err)
	require.NotNil(t, ac.Store)

	u := &models.User{Email: "grace@example.com"}
	require.NoError(t, ac.Store.CreateUser(ctx, u))
	stored, err := ac.Store.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "grace", stored.Username, "the plugin's before-create handler ran through the Dispatcher")

	updated, err := ac.Store.UpdateUser(ctx, u.ID, behemoth.M{models.UserEmail: "hopper@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "hopper", updated.Username, "the plugin's before-update handler ran through the Dispatcher")
	assert.Equal(t, "updated:"+u.ID, updated.Lastname, "the handler was told which user")
}

// capturingDriver keeps the routes Boot mounts, so a test can call them.
type capturingDriver struct{ routes []types.Route }

func (d *capturingDriver) Mount(routes ...types.Route) error {
	d.routes = append(d.routes, routes...)
	return nil
}

// signupPlugin creates a user from a route, through the store only; its
// data hook names the user after a request header — which the hook can only
// see if the request travelled through the context.
type signupPlugin struct{ ac *types.AuthContext }

func (p *signupPlugin) Meta() types.PluginMeta                 { return types.PluginMeta{Name: "signup"} }
func (p *signupPlugin) Version() string                        { return "0.0.0" }
func (p *signupPlugin) Init(ac *types.AuthContext) error       { p.ac = ac; return nil }
func (p *signupPlugin) Middlewares() []types.Middleware        { return nil }
func (p *signupPlugin) Declare(*types.PluginInitContext) error { return nil }
func (p *signupPlugin) RegisterHooks() []types.Listener        { return nil }

func (p *signupPlugin) Routes() []types.Route {
	return []types.Route{{Method: http.MethodPost, Path: "/sign-up", Handler: func(rctx *types.RequestContext) error {
		u := &models.User{Email: rctx.Request.URL.Query().Get("email")}
		if err := p.ac.Store.CreateUser(rctx.Ctx, u); err != nil {
			return err
		}
		return rctx.Response.JSON(http.StatusCreated, behemoth.M{"id": u.ID})
	}}}
}

func (p *signupPlugin) Register(reg types.HookRegistry) error {
	return reg.OnBefore(hooks.HookUserBeforeCreate, func(hctx *types.HookContext, row behemoth.M) (behemoth.M, error) {
		if hctx.Request == nil {
			row[models.UserUsername] = "no-request"
		} else {
			row[models.UserUsername] = hctx.Request.Request.Header.Get("X-Username")
		}
		return row, nil
	}, nil)
}

func TestDataHooksSeeTheRequestBeingHandled(t *testing.T) {
	ctx := context.Background()
	plugin := &signupPlugin{}
	app, err := binit.Prepare([]types.Plugin{plugin}, binit.PrepareConfig{})
	require.NoError(t, err)
	driver := &capturingDriver{}
	ac, err := binit.Boot(ctx, app, usersDB(t), binit.BootConfig{
		HTTP: driver,
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
		},
	})
	require.NoError(t, err)
	require.Len(t, driver.routes, 1)

	// Called the way every adapter calls a route: a RequestContext built from
	// the native request, with the request's own context.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up?email=ada@example.com", nil)
	req.Header.Set("X-Username", "from-header")
	rctx := &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
	require.NoError(t, driver.routes[0].Handler(rctx))
	w := httptest.NewRecorder()
	rctx.Response.Flush(w)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	created, err := ac.Store.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, "from-header", created.Username, "the data hook saw the request the route was handling")

	// The same write outside any request: the hook is told there is none.
	outside := &models.User{Email: "job@example.com"}
	require.NoError(t, ac.Store.CreateUser(ctx, outside))
	assert.Equal(t, "no-request", outside.Username)
}
