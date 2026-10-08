package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
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
		email_verified BOOLEAN NOT NULL DEFAULT 0, image_url TEXT,
		created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(testutils.AuditLogSQLiteSchema)
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

	// silent makes Fires report false, as for a table without hook points.
	silent bool
	// afterCreate and afterUpdate, if set, run as the after hooks with the
	// store bound to the write's transaction.
	afterCreate func(ctx context.Context, tx *store.Store, created behemoth.Model) error
	afterUpdate func(ctx context.Context, tx *store.Store, updated behemoth.Model) error
	inTx        []*store.Store

	// committed records the after-commit notifications, in order.
	committed []string

	// begun counts Begin calls; writes records, per Before and After call,
	// the number of the write its context belongs to.
	begun  int
	writes []any
}

// reportCommit queues an after-commit notification on the write's store, the
// way an implementation of store.Hooks does (the store has no call for it).
func (h *recordingHooks) reportCommit(ctx context.Context, tx *store.Store, what, table string, m behemoth.Model) {
	tx.AfterCommit(ctx, func(context.Context) {
		h.committed = append(h.committed, fmt.Sprint(what, " ", table, " ", m.PrimaryKeyField()))
	})
}

func (h *recordingHooks) Fires(string) bool { return !h.silent }

type writeKey struct{}

// Begin numbers the writes, so a test can tell that a write's Before and
// After calls ran with the context Begin returned.
func (h *recordingHooks) Begin(ctx context.Context, table string) context.Context {
	h.begun++
	return context.WithValue(ctx, writeKey{}, h.begun)
}

func (h *recordingHooks) BeforeUpdate(ctx context.Context, _ *store.Store, table string, id any, changes behemoth.M) (behemoth.M, error) {
	h.writes = append(h.writes, ctx.Value(writeKey{}))
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

func (h *recordingHooks) AfterUpdate(ctx context.Context, tx *store.Store, table string, updated behemoth.Model) error {
	h.updatedAs = append(h.updatedAs, updated)
	h.writes = append(h.writes, ctx.Value(writeKey{}))
	if h.afterUpdate != nil {
		if err := h.afterUpdate(ctx, tx, updated); err != nil {
			return err
		}
	}
	h.reportCommit(ctx, tx, "updated", table, updated)
	return nil
}

func (h *recordingHooks) BeforeCreate(ctx context.Context, tx *store.Store, table string, row behemoth.M) (behemoth.M, error) {
	h.writes = append(h.writes, ctx.Value(writeKey{}))
	h.tables = append(h.tables, table)
	h.inTx = append(h.inTx, tx)
	if h.abort != nil {
		return nil, h.abort
	}
	for k, v := range h.rewrite {
		row[k] = v
	}
	return row, nil
}

func (h *recordingHooks) AfterCreate(ctx context.Context, tx *store.Store, table string, created behemoth.Model) error {
	h.createdAs = append(h.createdAs, created)
	h.inTx = append(h.inTx, tx)
	h.writes = append(h.writes, ctx.Value(writeKey{}))
	if h.afterCreate != nil {
		if err := h.afterCreate(ctx, tx, created); err != nil {
			return err
		}
	}
	h.reportCommit(ctx, tx, "created", table, created)
	return nil
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

// An email a before-create hook sets is normalized like the caller's, so the
// user is stored in the form FindUserByEmail looks up.
func TestCreateUserNormalizesAHooksEmail(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{rewrite: behemoth.M{models.UserEmail: "  Grace@Example.COM "}}
	s := store.New(usersDB(t), store.WithHooks(h))

	u := &models.User{Email: "ada@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	assert.Equal(t, "grace@example.com", u.Email, "the caller's model holds what was stored")
	found, err := s.FindUserByEmail(ctx, "grace@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
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

// An after-create hook runs in the create's transaction: its error fails the
// create and rolls the row back.
func TestCreateUserAfterHookErrorRollsBack(t *testing.T) {
	ctx := context.Background()
	abort := errors.New("rejected after insert")
	h := &recordingHooks{}
	h.afterCreate = func(ctx context.Context, tx *store.Store, created behemoth.Model) error {
		_, err := tx.FindUserByID(ctx, created.PrimaryKeyField().(string))
		assert.NoError(t, err, "the hook's store sees the row it was fired for")
		return abort
	}
	s := store.New(usersDB(t), store.WithHooks(h))

	err := s.CreateUser(ctx, &models.User{Email: "a@example.com"})
	assert.ErrorIs(t, err, abort, "the hook's error is returned as-is")
	_, err = s.FindUserByEmail(ctx, "a@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "the insert was rolled back: %v", err)
}

// What a hook writes through the store it is given commits or rolls back
// with the write that fired it.
func TestAfterCreateHookWritesShareTheTransaction(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	var fail error
	h.afterCreate = func(ctx context.Context, tx *store.Store, created behemoth.Model) error {
		if created.(*models.User).Email == "shadow@example.com" {
			return fail
		}
		return tx.CreateUser(ctx, &models.User{Email: "shadow@example.com"})
	}
	s := store.New(usersDB(t), store.WithHooks(h))

	fail = errors.New("the hook's own write failed")
	err := s.CreateUser(ctx, &models.User{Email: "a@example.com"})
	assert.ErrorIs(t, err, fail)
	for _, email := range []string{"a@example.com", "shadow@example.com"} {
		_, err = s.FindUserByEmail(ctx, email)
		assert.True(t, behemotherr.IsNotFound(err), "%s was rolled back: %v", email, err)
	}

	fail = nil
	require.NoError(t, s.CreateUser(ctx, &models.User{Email: "a@example.com"}))
	for _, email := range []string{"a@example.com", "shadow@example.com"} {
		_, err = s.FindUserByEmail(ctx, email)
		assert.NoError(t, err, "%s was committed", email)
	}
}

// In a transaction the caller opened, hooks join it: a later failure rolls
// back the row and what its hooks wrote, after the after hook has run.
func TestHooksJoinTheCallersTransaction(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	h.afterCreate = func(ctx context.Context, tx *store.Store, created behemoth.Model) error {
		_, err := tx.UpdateUser(ctx, created.PrimaryKeyField().(string), behemoth.M{models.UserFirstname: "from-hook"})
		return err
	}
	s := store.New(usersDB(t), store.WithHooks(h))

	later := errors.New("a later write failed")
	var callers *store.Store
	err := s.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		callers = tx
		if err := tx.CreateUser(ctx, &models.User{Email: "a@example.com"}); err != nil {
			return err
		}
		return later
	})
	assert.ErrorIs(t, err, later)
	require.Len(t, h.createdAs, 1, "the after hook ran before the rollback")
	for _, tx := range h.inTx {
		assert.Same(t, callers, tx, "hooks get the caller's transaction, not a nested one")
	}
	_, err = s.FindUserByEmail(ctx, "a@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "the user was rolled back: %v", err)
}

// A hook writes tables the store has no operations for through tx.DB(), the
// adapter bound to the write's transaction. Here a raw users row stands in
// for a plugin's own table.
func TestHookWritesThroughTheAdapterShareTheTransaction(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	var fail error
	h.afterCreate = func(ctx context.Context, tx *store.Store, created behemoth.Model) error {
		raw := &models.User{ID: "raw-1", Email: "raw@example.com", CreatedAt: t0, UpdatedAt: t0}
		// Transaction on the bound adapter joins the open transaction.
		err := tx.DB().Transaction(ctx, func(ctx context.Context, db behemoth.Database) (any, error) {
			return nil, db.Create(ctx, raw)
		})
		if err != nil {
			return err
		}
		return fail
	}
	db := usersDB(t)
	s := store.New(db, store.WithHooks(h))
	assert.Same(t, db, s.DB(), "outside a transaction DB is the adapter the store was built with")
	rawExists := func() bool {
		_, err := s.FindUserByID(ctx, "raw-1")
		return err == nil
	}

	fail = errors.New("rejected after the raw write")
	assert.ErrorIs(t, s.CreateUser(ctx, &models.User{Email: "a@example.com"}), fail)
	assert.False(t, rawExists(), "the adapter write was rolled back with the user")

	fail = nil
	require.NoError(t, s.CreateUser(ctx, &models.User{Email: "a@example.com"}))
	assert.True(t, rawExists(), "the adapter write was committed with the user")
	assert.Len(t, h.createdAs, 2, "the raw insert fired no data hook")
}

// A table whose hooks don't fire writes directly, without a transaction.
func TestWritesWithoutHooksOpenNoTransaction(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{silent: true}
	s := store.New(usersDB(t), store.WithHooks(h))
	require.NoError(t, s.CreateUser(ctx, &models.User{Email: "a@example.com"}))
	for _, tx := range h.inTx {
		assert.Same(t, s, tx, "the write went through the store itself")
	}

	h = &recordingHooks{}
	s = store.New(usersDB(t), store.WithHooks(h))
	require.NoError(t, s.CreateUser(ctx, &models.User{Email: "a@example.com"}))
	require.NotEmpty(t, h.inTx)
	for _, tx := range h.inTx {
		assert.NotSame(t, s, tx, "a hooked write runs on a store bound to a transaction")
	}
}

func TestUpdateUserAfterHookErrorRollsBack(t *testing.T) {
	ctx := context.Background()
	abort := errors.New("rejected after update")
	h := &recordingHooks{}
	s := store.New(usersDB(t), store.WithHooks(h))
	u := &models.User{Email: "a@example.com", Firstname: "Ada"}
	require.NoError(t, s.CreateUser(ctx, u))

	h.afterUpdate = func(context.Context, *store.Store, behemoth.Model) error { return abort }
	_, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Grace"})
	assert.ErrorIs(t, err, abort)
	require.Len(t, h.updatedAs, 1)
	assert.Equal(t, "Grace", h.updatedAs[0].(*models.User).Firstname, "the hook saw the updated row")
	got, err := s.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "Ada", got.Firstname, "the update was rolled back")
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
	app, err := bmth.Prepare([]types.Plugin{usernamePlugin{}}, bmth.PrepareConfig{})
	require.NoError(t, err)
	ac, err := bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{Crypto: crypto.Config{
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

// BootConfig.Hooks registers the application's handlers without a plugin.
// With no ordering constraint they run after the plugins' handlers.
func TestBootRegistersApplicationHooks(t *testing.T) {
	ctx := context.Background()
	cryptoCfg := crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
	}
	app, err := bmth.Prepare([]types.Plugin{usernamePlugin{}}, bmth.PrepareConfig{})
	require.NoError(t, err)

	var sawUsername any
	rejected := errors.New("rejected by the application")
	reject := false
	ac, err := bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
		Crypto: cryptoCfg,
		Hooks: func(reg types.HookRegistry) error {
			if err := reg.OnBefore(hooks.HookUserBeforeCreate, func(_ *types.HookContext, row behemoth.M) (behemoth.M, error) {
				sawUsername = row[models.UserUsername]
				row[models.UserFirstname] = "from-app"
				return row, nil
			}, nil); err != nil {
				return err
			}
			return reg.OnAfter(hooks.HookUserAfterCreate, func(hctx *types.HookContext, _ any) error {
				if hctx.Tx == nil {
					return errors.New("a data hook should get the transaction's store")
				}
				if reject {
					return rejected
				}
				return nil
			}, nil)
		},
	})
	require.NoError(t, err)

	u := &models.User{Email: "grace@example.com"}
	require.NoError(t, ac.Store.CreateUser(ctx, u))
	assert.Equal(t, "grace", sawUsername, "the application's handler ran after the plugin's")
	stored, err := ac.Store.FindUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "from-app", stored.Firstname)

	reject = true
	err = ac.Store.CreateUser(ctx, &models.User{Email: "ada@example.com"})
	assert.ErrorIs(t, err, rejected)
	_, err = ac.Store.FindUserByEmail(ctx, "ada@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "the application's after-hook error rolled the user back: %v", err)

	// A registration error is a boot error.
	app, err = bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)
	_, err = bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
		Crypto: cryptoCfg,
		Hooks: func(reg types.HookRegistry) error {
			return reg.OnBefore("no.such.point", func(_ *types.HookContext, p behemoth.M) (behemoth.M, error) { return p, nil }, nil)
		},
	})
	require.Error(t, err, "registering on an undeclared point fails Boot")
}

// The application's owner name comes from PrepareConfig.AppName, is usable
// in ordering constraints, and can't collide with core or a plugin.
func TestAppNameIsConfigurableAndChecked(t *testing.T) {
	ctx := context.Background()
	cryptoCfg := crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
	}
	pluginName := usernamePlugin{}.Meta().Name

	app, err := bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)
	assert.Equal(t, "app", app.AppName, "the default name")

	app, err = bmth.Prepare([]types.Plugin{usernamePlugin{}}, bmth.PrepareConfig{AppName: "shop"})
	require.NoError(t, err)
	assert.Equal(t, "shop", app.AppName)

	// The application asks to run before the plugin, which names it "shop".
	var sawUsername any = "unset"
	ac, err := bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
		Crypto: cryptoCfg,
		Hooks: func(reg types.HookRegistry) error {
			return reg.OnBefore(hooks.HookUserBeforeCreate, func(_ *types.HookContext, row behemoth.M) (behemoth.M, error) {
				sawUsername = row[models.UserUsername]
				return row, nil
			}, &types.HookOptions{Before: []string{pluginName}})
		},
	})
	require.NoError(t, err)
	require.NoError(t, ac.Store.CreateUser(ctx, &models.User{Email: "grace@example.com"}))
	assert.NotEqual(t, "grace", sawUsername, "the application's handler ran before the plugin's")

	for name, cfg := range map[string]bmth.PrepareConfig{
		"an application named core":   {AppName: "core"},
		"a plugin named like the app": {AppName: pluginName},
	} {
		_, err = bmth.Prepare([]types.Plugin{usernamePlugin{}}, cfg)
		assert.Error(t, err, name)
	}
}

// An owner may register one handler per point; a second is a boot error
// instead of being dropped by the chain ordering.
func TestSecondHandlerOnAPointIsRejected(t *testing.T) {
	ctx := context.Background()
	app, err := bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)
	pass := func(_ *types.HookContext, row behemoth.M) (behemoth.M, error) { return row, nil }

	_, err = bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
		},
		Hooks: func(reg types.HookRegistry) error {
			if err := reg.OnBefore(hooks.HookUserBeforeCreate, pass, nil); err != nil {
				return err
			}
			// A different priority doesn't make it a different handler slot.
			return reg.OnBefore(hooks.HookUserBeforeCreate, pass, &types.HookOptions{Priority: types.PriorityLow})
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), string(hooks.HookUserBeforeCreate))
	assert.Contains(t, err.Error(), `"app"`)
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
	app, err := bmth.Prepare([]types.Plugin{plugin}, bmth.PrepareConfig{})
	require.NoError(t, err)
	driver := &capturingDriver{}
	ac, err := bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
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

// noTransactionsDB is a database whose deployment has no transactions, the
// way the MongoDB adapter reports a standalone server.
type noTransactionsDB struct {
	behemoth.Database
	err error
}

func (d noTransactionsDB) CheckTransactions(context.Context) error { return d.err }

// Boot asks a database that can tell whether its transactions work, and
// refuses to start when they don't: hooked writes would fail later.
func TestBootChecksTheDatabaseHasTransactions(t *testing.T) {
	ctx := context.Background()
	cfg := bmth.BootConfig{Crypto: crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
	}}
	app, err := bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)

	standalone := behemotherr.NewConfigurationError("test", "standalone server", nil)
	_, err = bmth.Boot(ctx, app, noTransactionsDB{Database: usersDB(t), err: standalone}, cfg)
	require.Error(t, err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	assert.ErrorIs(t, err, standalone)

	_, err = bmth.Boot(ctx, app, noTransactionsDB{Database: usersDB(t)}, cfg)
	assert.NoError(t, err, "a database whose check passes boots")
}

// The store calls Begin once per hooked write and runs the write's Before and
// After calls with the context it returned. A table without hooks begins
// nothing.
func TestBeginScopesEachHookedWrite(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	s := store.New(usersDB(t), store.WithHooks(h))

	u := &models.User{Email: "ada@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	_, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)
	assert.Equal(t, 2, h.begun)
	assert.Equal(t, []any{1, 1, 2, 2}, h.writes, "before and after of a write share the context Begin returned")

	h.silent = true
	require.NoError(t, s.CreateUser(ctx, &models.User{Email: "grace@example.com"}))
	assert.Equal(t, 2, h.begun, "a table that fires no hooks begins no write")
}

// Callbacks a hook queues with AfterCommit wait for the commit: they run
// after a single write, and not at all when the write is rolled back.
func TestCommittedHooksFireAfterCommitOnly(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	s := store.New(usersDB(t), store.WithHooks(h))

	u := &models.User{Email: "ada@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	_, err := s.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)
	assert.Equal(t, []string{"created users " + u.ID, "updated users " + u.ID}, h.committed)

	// An after hook that fails rolls the write back: nothing committed.
	h.committed = nil
	h.afterCreate = func(context.Context, *store.Store, behemoth.Model) error { return errors.New("rejected") }
	require.Error(t, s.CreateUser(ctx, &models.User{Email: "grace@example.com"}))
	assert.Empty(t, h.committed, "a rolled-back write is never reported as committed")
}

// Inside a caller's transaction the notifications wait for the outermost
// commit, the way sign-up creates a user and its account together.
func TestCommittedHooksWaitForTheOutermostTransaction(t *testing.T) {
	ctx := context.Background()
	h := &recordingHooks{}
	s := store.New(usersDB(t), store.WithHooks(h))

	// A later step fails: the user is rolled back and never reported.
	failed := errors.New("account insert failed")
	err := s.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		if err := tx.CreateUser(ctx, &models.User{Email: "ada@example.com"}); err != nil {
			return err
		}
		return failed
	})
	require.ErrorIs(t, err, failed)
	assert.Empty(t, h.committed)
	_, err = s.FindUserByEmail(ctx, "ada@example.com")
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)

	// Everything succeeds: nothing is reported while the transaction is
	// open, and everything is, in order, once it has committed.
	var during []string
	var extra []string
	u := &models.User{Email: "ada@example.com"}
	err = s.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		tx.AfterCommit(ctx, func(context.Context) { extra = append(extra, "callback") })
		// A helper that opens its own transaction joins this one.
		if err := tx.Transaction(ctx, func(ctx context.Context, inner *store.Store) error {
			_, err := inner.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Ada"})
			return err
		}); err != nil {
			return err
		}
		during = append(during, h.committed...)
		during = append(during, extra...)
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, during, "nothing fires before the outermost commit")
	assert.Equal(t, []string{"created users " + u.ID, "updated users " + u.ID}, h.committed)
	assert.Equal(t, []string{"callback"}, extra)

	// Outside a transaction there is nothing to wait for.
	ran := false
	s.AfterCommit(ctx, func(context.Context) { ran = true })
	assert.True(t, ran)
}

// A callback that panics after the commit does not undo the caller's view of
// the write: Transaction returns nil, the callbacks queued behind it run, and
// the panic is logged. The same holds for a callback run at once on a store
// that is not bound to a transaction.
func TestAfterCommitCallbackPanicIsRecovered(t *testing.T) {
	ctx := context.Background()
	tel, rec := telemetrytest.New()
	s := store.New(usersDB(t), store.WithTelemetry(tel))

	var ran []string
	err := s.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		if err := tx.CreateUser(ctx, &models.User{Email: "ada@example.com"}); err != nil {
			return err
		}
		tx.AfterCommit(ctx, func(context.Context) { ran = append(ran, "first") })
		tx.AfterCommit(ctx, func(context.Context) { panic("boom") })
		tx.AfterCommit(ctx, func(context.Context) { ran = append(ran, "third") })
		return nil
	})
	require.NoError(t, err, "the write committed")
	assert.Equal(t, []string{"first", "third"}, ran, "the callback behind the panic still runs")
	_, err = s.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)

	logged := rec.Logger.At(slog.LevelError)
	require.Len(t, logged, 1)
	assert.Equal(t, "after-commit callback panicked", logged[0].Message)
	assert.Equal(t, "store", logged[0].Fields[telemetry.FieldComponent])
	assert.Contains(t, logged[0].Fields[telemetry.FieldError], "boom")

	rec.Logger.Reset()
	assert.NotPanics(t, func() { s.AfterCommit(ctx, func(context.Context) { panic("unbound") }) })
	assert.Len(t, rec.Logger.At(slog.LevelError), 1)

	// Without a Telemetry there is no logger; the panic is still recovered.
	quiet := store.New(usersDB(t))
	assert.NotPanics(t, func() { quiet.AfterCommit(ctx, func(context.Context) { panic("quiet") }) })
}

// Under Boot the notifications are the data.user.created and
// data.user.updated points: a handler sees only committed users, has no
// transaction, and can't fail the write.
func TestCommittedDataPointsUnderBoot(t *testing.T) {
	ctx := context.Background()
	app, err := bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)

	var seen []string
	ac, err := bmth.Boot(ctx, app, usersDB(t), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
		},
		Hooks: func(reg types.HookRegistry) error {
			if err := reg.OnAfter(hooks.HookUserCreated, func(hctx *types.HookContext, result any) error {
				seen = append(seen, "created "+result.(*models.User).Email)
				assert.Nil(t, hctx.Tx, "the transaction is over")
				// The row is visible on the root store's connection.
				_, err := hctx.Auth.Store.FindUserByID(hctx.Ctx, result.(*models.User).ID)
				assert.NoError(t, err)
				return errors.New("a handler error is logged, not returned")
			}, nil); err != nil {
				return err
			}
			return reg.OnAfter(hooks.HookUserUpdated, func(hctx *types.HookContext, result any) error {
				seen = append(seen, fmt.Sprint("updated ", hctx.Values[hooks.HookValueUserID] == result.(*models.User).ID))
				return nil
			}, nil)
		},
	})
	require.NoError(t, err)

	u := &models.User{Email: "ada@example.com"}
	require.NoError(t, ac.Store.CreateUser(ctx, u), "an after-commit handler's error does not fail the write")
	_, err = ac.Store.UpdateUser(ctx, u.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)

	failed := errors.New("later step failed")
	err = ac.Store.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		if err := tx.CreateUser(ctx, &models.User{Email: "grace@example.com"}); err != nil {
			return err
		}
		return failed
	})
	require.ErrorIs(t, err, failed)

	assert.Equal(t, []string{"created ada@example.com", "updated true"}, seen)
}
