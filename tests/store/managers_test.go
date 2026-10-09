package store_test

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	pgAdapter "github.com/MastewalB/behemoth/storage/adapters/postgres"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/transport"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sessionsTokensSQLite = `
CREATE TABLE sessions (
	id TEXT PRIMARY KEY, user_id TEXT NOT NULL, lookup_hash TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL,
	key_version INTEGER NOT NULL, state TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, last_active_at TIMESTAMP,
	fresh_at TIMESTAMP, ip_address TEXT, user_agent TEXT, impersonator_id TEXT, revoked_at TIMESTAMP,
	revoked_reason TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE tokens (
	id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT, lookup_hash TEXT NOT NULL, token_hash TEXT NOT NULL,
	key_version INTEGER NOT NULL, metadata TEXT, expires_at TIMESTAMP, consumed_at TIMESTAMP, revoked_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL);`

// sessionsTokensDB opens a file SQLite database with the sessions and tokens
// tables. busy_timeout makes concurrent writers wait instead of failing, so
// concurrency tests exercise the logic, not lock errors.
func sessionsTokensDB(t *testing.T) behemoth.Database {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "managers.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(sessionsTokensSQLite + testutils.AuditLogSQLiteSchema)
	require.NoError(t, err)
	return sqliteAdapter.NewSQLiteAdapter(db, nil)
}

func testCrypto(t *testing.T) types.Crypto {
	t.Helper()
	c, err := crypto.New(context.Background(), crypto.Config{
		Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("cd", 32)}, Current: 1},
	}, nil)
	require.NoError(t, err)
	return c
}

// passDispatcher passes every payload through and records the contexts.
type passDispatcher struct {
	mu   sync.Mutex
	seen []*types.HookContext
}

func (d *passDispatcher) record(h *types.HookContext) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, h)
}
func (d *passDispatcher) RunBefore(h *types.HookContext, _ types.HookPoint, p behemoth.M) (behemoth.M, error) {
	d.record(h)
	return p, nil
}
func (d *passDispatcher) RunAfter(h *types.HookContext, _ types.HookPoint, _ any) error {
	d.record(h)
	return nil
}
func (d *passDispatcher) RunAfterTx(h *types.HookContext, _ types.HookPoint, _ any) error {
	d.record(h)
	return nil
}
func (d *passDispatcher) Fail(h *types.HookContext, _ types.HookPoint, _ types.FailureReason) error {
	d.record(h)
	return nil
}

// ---- store: ConsumeToken ----

func issueRawToken(t *testing.T, s *store.Store) *models.Token {
	t.Helper()
	tok := &models.Token{Kind: "test", Subject: "u1", LookupHash: "lh", TokenHash: "th", KeyVersion: 1,
		ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, s.CreateToken(context.Background(), tok))
	return tok
}

func consumeConcurrently(t *testing.T, s *store.Store, id string, n int) (wins int, lost int) {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ConsumeToken(context.Background(), id)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case behemotherr.IsCode(err, store.ErrorCodeTokenAlreadyConsumed):
				lost++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	return wins, lost
}

func TestConsumeTokenExactlyOnce(t *testing.T) {
	s := store.New(sessionsTokensDB(t))
	tok := issueRawToken(t, s)
	wins, lost := consumeConcurrently(t, s, tok.ID, 20)
	assert.Equal(t, 1, wins, "exactly one consumer wins")
	assert.Equal(t, 19, lost)
}

func TestConsumeTokenExactlyOncePostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a Postgres container")
	}
	ctx := context.Background()
	db, cleanup := testutils.SetupPostgresTestDB(t, ctx)
	t.Cleanup(cleanup)
	require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)
	_, err := db.ExecContext(ctx, `CREATE TABLE tokens (
		id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT, lookup_hash TEXT NOT NULL, token_hash TEXT NOT NULL,
		key_version INTEGER NOT NULL, metadata TEXT, expires_at TIMESTAMPTZ, consumed_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL)`)
	require.NoError(t, err)

	s := store.New(pgAdapter.NewPostgresAdapter(db, nil))
	for round := 0; round < 5; round++ {
		tok := issueRawToken(t, s)
		wins, lost := consumeConcurrently(t, s, tok.ID, 20)
		assert.Equal(t, 1, wins, "round %d: exactly one consumer wins", round)
		assert.Equal(t, 19, lost, "round %d", round)
	}
}

func TestConsumeAndRevokeUnknownToken(t *testing.T) {
	s := store.New(sessionsTokensDB(t))
	_, err := s.ConsumeToken(context.Background(), "no-such-token")
	assert.True(t, behemotherr.IsNotFound(err), "an unknown token is NotFound, not already consumed: %v", err)
	err = s.RevokeToken(context.Background(), "no-such-token")
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)
}

// ---- session manager ----

func newSessionManager(t *testing.T, cfg types.SessionConfig) (types.SessionManager, *passDispatcher) {
	t.Helper()
	d := &passDispatcher{}
	if cfg.ExpiresIn == 0 {
		cfg.ExpiresIn = time.Hour
	}
	if cfg.PendingExpiresIn == 0 {
		cfg.PendingExpiresIn = 5 * time.Minute
	}
	return transport.NewSessionManager(store.New(sessionsTokensDB(t)), nil, testCrypto(t), cfg, d, nil, managersAuth, nil), d
}

// managersAuth is the AuthContext the managers under test are built with. It
// only has to be the pointer handlers get back as HookContext.Auth.
var managersAuth = &types.AuthContext{}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	sm, _ := newSessionManager(t, types.SessionConfig{})

	sess, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)
	assert.NotEmpty(t, sess.ID, "the store assigned the id")
	assert.False(t, sess.CreatedAt.IsZero(), "the store stamped created_at")

	got, err := sm.Get(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	_, err = sm.Validate(ctx, raw)
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionPending), "%v", err)

	promoted, err := sm.Promote(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, models.SessionActive, promoted.State)
	assert.True(t, promoted.UpdatedAt.After(sess.UpdatedAt) || promoted.UpdatedAt.Equal(sess.UpdatedAt), "updated_at stamped")
	_, err = sm.Validate(ctx, raw)
	require.NoError(t, err)

	require.NoError(t, sm.Revoke(ctx, sess.ID, "user_logout"))
	_, err = sm.Get(ctx, raw)
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionRevoked), "%v", err)
	listed, err := sm.ListForUser(ctx, "u1")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "user_logout", listed[0].RevokedReason)
	assert.NotNil(t, listed[0].RevokedAt)
}

func TestSessionTouchExtendsExpiry(t *testing.T) {
	ctx := context.Background()
	sm, _ := newSessionManager(t, types.SessionConfig{UpdateAge: 2 * time.Hour}) // always due
	sess, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	extended, err := sm.Touch(ctx, sess)
	require.NoError(t, err)
	require.NotNil(t, extended, "Touch returns the session it extended")
	got, err := sm.Get(ctx, raw)
	require.NoError(t, err)
	assert.True(t, got.ExpiresAt.After(sess.ExpiresAt), "expiry moved forward")
	assert.True(t, extended.ExpiresAt.Equal(got.ExpiresAt), "and that is the expiry Touch reports")

	// Not due: with UpdateAge at zero a session is never extended, and
	// Touch says so by returning no session.
	fixed, _ := newSessionManager(t, types.SessionConfig{})
	sess, _, err = fixed.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	extended, err = fixed.Touch(ctx, sess)
	require.NoError(t, err)
	assert.Nil(t, extended)
	extended, err = fixed.Touch(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, extended, "no session, nothing to extend")
}

// Touch runs on every authenticated request. It decides from the session it
// is handed, and goes to the database only when that session is due. The row
// then has the last word, because the copy may be older than the row.
func TestSessionTouchDecidesFromTheSessionItIsGiven(t *testing.T) {
	ctx := context.Background()
	sm, _ := newSessionManager(t, types.SessionConfig{UpdateAge: 30 * time.Minute}) // due in the second half of the hour a session lasts

	// Not due: the row is not looked for. A session that was never stored
	// shows it, since reading it would fail.
	unstored := &models.Session{ID: "not-in-the-database", State: models.SessionActive, ExpiresAt: time.Now().Add(time.Hour)}
	extended, err := sm.Touch(ctx, unstored)
	require.NoError(t, err, "a session that is not due costs no read")
	assert.Nil(t, extended)

	// Due by the copy, not by the row: another request has extended the
	// session already. Nothing is written.
	fresh, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	stale := *fresh
	stale.ExpiresAt = time.Now().Add(time.Minute)
	extended, err = sm.Touch(ctx, &stale)
	require.NoError(t, err)
	assert.Nil(t, extended, "the row is not due")
	stored, err := sm.Get(ctx, raw)
	require.NoError(t, err)
	assert.True(t, stored.ExpiresAt.Equal(fresh.ExpiresAt), "the expiry is where it was")

	// Due by the copy, and the row has been revoked since.
	require.NoError(t, sm.Revoke(ctx, fresh.ID, "test"))
	extended, err = sm.Touch(ctx, &stale)
	require.NoError(t, err)
	assert.Nil(t, extended, "a revoked session is not extended")

	// Due by the copy and by the row is TestSessionTouchExtendsExpiry.
}

// RequireSession refuses a request with a typed session error and writes no
// response of its own, so the router answers every refusal the same way: 401
// with a public message and a code. A failure of the system is not a
// refusal. It passes through as it is, and the router answers it with 500
// and keeps its text from the client.
func TestRequireSessionRefusesWithTypedErrors(t *testing.T) {
	ctx := context.Background()
	sqlDB, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "refusals.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	_, err = sqlDB.Exec(sessionsTokensSQLite + testutils.AuditLogSQLiteSchema)
	require.NoError(t, err)
	sm := transport.NewSessionManager(store.New(sqliteAdapter.NewSQLiteAdapter(sqlDB, nil)), nil, testCrypto(t),
		types.SessionConfig{Transport: types.TransportHeader, ExpiresIn: time.Hour, PendingExpiresIn: time.Minute},
		&passDispatcher{}, nil, managersAuth, nil)

	reached := 0
	handler := types.RequireSession(sm)(func(*types.RequestContext) error {
		reached++
		return nil
	})
	// request returns what the router would answer with: the status and
	// body its error mapper gives the middleware's error.
	request := func(token string) (rctx *types.RequestContext, status int, body behemoth.M, err error) {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rctx = &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		if err = handler(rctx); err != nil {
			status, body = (&behemotherr.DefaultErrorMapper{}).Map(err)
		}
		return rctx, status, body, err
	}

	_, liveToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	revoked, revokedToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	require.NoError(t, sm.Revoke(ctx, revoked.ID, "test"))
	_, pendingToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)

	for name, tc := range map[string]struct{ token, code, message string }{
		"no token":                    {"", behemotherr.ErrorCodeSessionMissing, "missing session token"},
		"a token of no session":       {"never-issued", behemotherr.ErrorCodeSessionInvalid, "invalid session"},
		"a revoked session":           {revokedToken, behemotherr.ErrorCodeSessionRevoked, "session has been revoked"},
		"waiting for a second factor": {pendingToken, behemotherr.ErrorCodeSessionPending, "additional verification required"},
	} {
		rctx, status, body, err := request(tc.token)
		require.Error(t, err, name)
		assert.True(t, behemotherr.Is(err, behemotherr.CategorySession), "%s: a session error: %v", name, err)
		assert.Equal(t, http.StatusUnauthorized, status, name)
		assert.Equal(t, behemoth.M{"error": tc.message, "code": tc.code}, body, name)
		assert.Equal(t, http.StatusOK, rctx.Response.Code, "%s: the middleware wrote no response of its own", name)
		assert.Empty(t, rctx.Response.Headers, name)
	}
	assert.Zero(t, reached, "no refused request reached the handler")

	_, _, _, err = request(liveToken)
	require.NoError(t, err)
	assert.Equal(t, 1, reached)

	// The database fails. The session may be perfectly good, so this is not
	// a 401: a client would take that for the end of its session.
	require.NoError(t, sqlDB.Close())
	_, status, body, err := request(liveToken)
	require.Error(t, err)
	assert.False(t, behemotherr.Is(err, behemotherr.CategorySession), "not a refusal: %v", err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryDatabase), "the store's error, unchanged: %v", err)
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Equal(t, behemoth.M{"error": "an internal error occurred", "code": "database_error"}, body, "the error's own text stays on the server")
	assert.Equal(t, 1, reached, "the request did not reach the handler")
}

// A session can end in another request: it is revoked from another device,
// it expires, or it is deleted with its user. The browser still holds the
// cookie, and can't drop an HttpOnly cookie itself. The session check takes
// it back with the refusal. A cookie that may still be needed stays.
func TestRequireSessionTakesBackTheCookieOfASessionThatIsGone(t *testing.T) {
	ctx := context.Background()
	sqlDB, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "gone.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	_, err = sqlDB.Exec(sessionsTokensSQLite + testutils.AuditLogSQLiteSchema)
	require.NoError(t, err)
	// Every manager shares the database, so one can create what another
	// is asked about.
	manager := func(cfg types.SessionConfig) types.SessionManager {
		if cfg.ExpiresIn == 0 {
			cfg.ExpiresIn = time.Hour
		}
		cfg.PendingExpiresIn = time.Minute
		return transport.NewSessionManager(store.New(sqliteAdapter.NewSQLiteAdapter(sqlDB, nil)), nil, testCrypto(t), cfg, &passDispatcher{}, nil, managersAuth, nil)
	}
	// request sends cookie and bearer through the middleware mw builds, and
	// returns the response and the middleware's error.
	request := func(sm types.SessionManager, mw func(types.SessionManager) types.Middleware, cookie, bearer string) (*types.RequestContext, error) {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "session_token", Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rctx := &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		return rctx, mw(sm)(func(*types.RequestContext) error { return nil })(rctx)
	}
	// removed reports whether the response removes the session cookie.
	removed := func(rctx *types.RequestContext) bool {
		set := (&http.Response{Header: rctx.Response.Headers}).Cookies()
		return len(set) == 1 && set[0].Name == "session_token" && set[0].Value == "" && set[0].MaxAge < 0
	}

	sm := manager(types.SessionConfig{})
	revoked, revokedToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	require.NoError(t, sm.Revoke(ctx, revoked.ID, "revoked_elsewhere"))
	_, expiredToken, err := manager(types.SessionConfig{ExpiresIn: 20 * time.Millisecond}).Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(40 * time.Millisecond)
	_, pendingToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)
	_, liveToken, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)

	// Gone for good: the cookie goes with the refusal.
	for name, tc := range map[string]struct{ token, code string }{
		"revoked":      {revokedToken, behemotherr.ErrorCodeSessionRevoked},
		"expired":      {expiredToken, behemotherr.ErrorCodeSessionExpired},
		"never issued": {"never-issued", behemotherr.ErrorCodeSessionInvalid},
	} {
		rctx, err := request(sm, types.RequireSession, tc.token, "")
		assert.True(t, behemotherr.IsCode(err, tc.code), "%s: %v", name, err)
		assert.True(t, removed(rctx), "%s: the cookie is removed: %q", name, rctx.Response.Headers.Values("Set-Cookie"))
	}

	// Not gone: the client still needs its cookie, or has none.
	rctx, err := request(sm, types.RequireSession, pendingToken, "")
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionPending), "%v", err)
	assert.Empty(t, rctx.Response.Headers, "a session that waits for its second factor keeps its cookie")

	rctx, err = request(sm, types.RequireSession, "", "")
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionMissing), "%v", err)
	assert.Empty(t, rctx.Response.Headers, "no cookie came, none is removed")

	neverFresh := manager(types.SessionConfig{FreshAge: time.Nanosecond})
	rctx, err = request(neverFresh, types.RequireFreshSession, liveToken, "")
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionNotFresh), "%v", err)
	assert.Empty(t, rctx.Response.Headers, "a session that is only too old for this route is still live")

	// Both transports: the bearer token is read first. A dead one says
	// nothing about the cookie next to it, which is another session's.
	both := manager(types.SessionConfig{Transport: types.TransportBoth})
	rctx, err = request(both, types.RequireSession, liveToken, revokedToken)
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionRevoked), "%v", err)
	assert.Empty(t, rctx.Response.Headers, "the live session's cookie stays")
	rctx, err = request(both, types.RequireSession, revokedToken, "")
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionRevoked), "%v", err)
	assert.True(t, removed(rctx), "the dead session's own cookie goes")

	// The database fails: nothing is known about the session, so nothing
	// is taken from the client.
	require.NoError(t, sqlDB.Close())
	rctx, err = request(sm, types.RequireSession, liveToken, "")
	require.Error(t, err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryDatabase), "%v", err)
	assert.Empty(t, rctx.Response.Headers, "a failed lookup removes no cookie")
}

// RequireSession runs on every authenticated request, so what it costs
// matters. With a session cache, a request whose session is not due for an
// extension is served without a statement to the database. Without a cache
// it costs the one read that validates the token.
func TestRequireSessionReadsNoMoreThanItNeeds(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		cfg    types.SessionConfig
		cached bool
		want   int // statements one request runs
	}{
		"cache, rolling off":         {types.SessionConfig{}, true, 0},
		"cache, rolling on, not due": {types.SessionConfig{UpdateAge: 30 * time.Minute}, true, 0},
		"no cache, rolling off":      {types.SessionConfig{}, false, 1},
		"no cache, not due":          {types.SessionConfig{UpdateAge: 30 * time.Minute}, false, 1},
	} {
		// The adapter logs each statement at debug, which is how they are
		// counted.
		_, rec := telemetrytest.New()
		sqlDB, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "cost.db")+"?_busy_timeout=10000")
		require.NoError(t, err, name)
		t.Cleanup(func() { sqlDB.Close() })
		_, err = sqlDB.Exec(sessionsTokensSQLite + testutils.AuditLogSQLiteSchema)
		require.NoError(t, err, name)
		var kv behemoth.KeyValueStorage
		if tc.cached {
			kv = &memoryKV{entries: map[string]string{}}
		}
		tc.cfg.ExpiresIn = time.Hour
		sm := transport.NewSessionManager(store.New(sqliteAdapter.NewSQLiteAdapter(sqlDB, nil).WithLogger(rec.Logger)),
			kv, testCrypto(t), tc.cfg, &passDispatcher{}, nil, managersAuth, nil)
		_, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
		require.NoError(t, err, name)
		require.NotEmpty(t, rec.Logger.At(slog.LevelDebug), "%s: creating the session ran statements, so they are being counted", name)

		reached := false
		handler := types.RequireSession(sm)(func(*types.RequestContext) error {
			reached = true
			return nil
		})
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: raw})
		rctx := &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		rec.Logger.Reset()
		require.NoError(t, handler(rctx), name)
		require.True(t, reached, name)
		assert.Len(t, rec.Logger.At(slog.LevelDebug), tc.want, "%s: statements run by one authenticated request", name)
	}
}

func TestSessionRevokeAllAndEviction(t *testing.T) {
	ctx := context.Background()
	sm, _ := newSessionManager(t, types.SessionConfig{MaxConcurrent: 2, EvictOldestOnLimit: true})
	first, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	second, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	third, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)

	states := func() map[string]models.SessionState {
		listed, err := sm.ListForUser(ctx, "u1")
		require.NoError(t, err)
		out := map[string]models.SessionState{}
		for _, s := range listed {
			out[s.ID] = s.State
		}
		return out
	}
	assert.Equal(t, map[string]models.SessionState{
		first.ID: models.SessionRevoked, second.ID: models.SessionActive, third.ID: models.SessionActive,
	}, states(), "the oldest session was evicted at the limit")

	require.NoError(t, sm.RevokeAllForUser(ctx, "u1", "password_changed", third.ID))
	assert.Equal(t, map[string]models.SessionState{
		first.ID: models.SessionRevoked, second.ID: models.SessionRevoked, third.ID: models.SessionActive,
	}, states(), "everything but the excepted session is revoked")
}

// The manager's own hooks get a complete HookContext: the point and phase
// being dispatched, the AuthContext, the request being handled, and Values
// that last for one operation: a create's two points share a map, a revoke's
// two share another, and both start as a copy of the caller's operation.
func TestSessionHooksGetACompleteContext(t *testing.T) {
	sm, d := newSessionManager(t, types.SessionConfig{})
	rc := &types.RequestContext{Request: httptest.NewRequest("POST", "/sign-in", nil)}
	flow := behemoth.M{"flow": "sign-in"}
	ctx := types.ContextWithHookValues(types.ContextWithRequest(context.Background(), rc), flow)
	sess, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	require.NoError(t, sm.Revoke(ctx, sess.ID, "user_logout"))

	type dispatch struct {
		point types.HookPoint
		phase types.HookPhase
	}
	var got []dispatch
	for _, h := range d.seen {
		got = append(got, dispatch{h.Point, h.Phase})
		assert.Same(t, managersAuth, h.Auth, "%s", h.Point)
		assert.Same(t, rc, h.Request, "%s", h.Point)
		assert.Nil(t, h.Tx, "%s: a Tier 2 point has no transaction", h.Point)
		require.NotNil(t, h.Values, "%s: a handler writing Values must not panic", h.Point)
		assert.Equal(t, "sign-in", h.Values["flow"], "%s: the caller's operation is visible", h.Point)
	}
	assert.Equal(t, []dispatch{
		{hooks.HookSessionBeforeCreate, types.BeforeHookPhase}, {hooks.HookSessionAfterCreate, types.AfterHookPhase},
		{hooks.HookSessionBeforeRevoke, types.BeforeHookPhase}, {hooks.HookSessionAfterRevoke, types.AfterHookPhase},
	}, got)
	beforeCreate, afterCreate, beforeRevoke, afterRevoke := d.seen[0], d.seen[1], d.seen[2], d.seen[3]
	beforeCreate.Values["note"] = "from beforeCreate"
	assert.Equal(t, "from beforeCreate", afterCreate.Values["note"], "a create's points share Values")
	beforeRevoke.Values["why"] = "from beforeRevoke"
	assert.Equal(t, "from beforeRevoke", afterRevoke.Values["why"], "a revoke's points share Values")
	assert.NotContains(t, beforeRevoke.Values, "note", "another operation's notes are not visible")
	assert.Equal(t, behemoth.M{"flow": "sign-in"}, flow, "nothing a nested operation writes reaches the caller's Values")
}

// A session records the IP address and user agent of the request on the
// context. The caller's SessionMeta overrides them, no request leaves them
// empty, and nothing is recorded unless CaptureIPAndAgent is on.
func TestSessionCreateTakesIPAndUserAgentFromTheRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "/sign-in", nil)
	req.RemoteAddr = "203.0.113.7:51234"
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	inRequest := types.ContextWithRequest(context.Background(), &types.RequestContext{Request: req})
	capture := types.SessionConfig{CaptureIPAndAgent: true}
	active := types.SessionMeta{State: types.SessionActive}

	t.Run("from the request", func(t *testing.T) {
		sm, _ := newSessionManager(t, capture)
		sess, _, err := sm.Create(inRequest, "u1", active)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.7", sess.IPAddress, "the direct peer, without its port; an untrusted peer's forwarding header is ignored")
		assert.Equal(t, "test-agent/1.0", sess.UserAgent)
	})
	t.Run("the caller's values win", func(t *testing.T) {
		sm, _ := newSessionManager(t, capture)
		sess, _, err := sm.Create(inRequest, "u1", types.SessionMeta{State: types.SessionActive, IPAddress: "192.0.2.1", UserAgent: "job"})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", sess.IPAddress)
		assert.Equal(t, "job", sess.UserAgent)
	})
	t.Run("no request", func(t *testing.T) {
		sm, _ := newSessionManager(t, capture)
		sess, _, err := sm.Create(context.Background(), "u1", active)
		require.NoError(t, err, "a session can be created outside a request")
		assert.Empty(t, sess.IPAddress)
		assert.Empty(t, sess.UserAgent)
	})
	t.Run("capture off", func(t *testing.T) {
		sm, _ := newSessionManager(t, types.SessionConfig{})
		sess, _, err := sm.Create(inRequest, "u1", active)
		require.NoError(t, err)
		assert.Empty(t, sess.IPAddress)
		assert.Empty(t, sess.UserAgent)
	})
	t.Run("a before handler's rewrite is stored", func(t *testing.T) {
		sess, err := createWithRewrite(t, capture, inRequest)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.0", sess.IPAddress)
		assert.Equal(t, "masked", sess.UserAgent)
		assert.Equal(t, "u1", sess.UserID, "the user is not read back")
		assert.Equal(t, models.SessionActive, sess.State, "the state is not read back")
	})
	t.Run("capture off ignores a before handler's rewrite", func(t *testing.T) {
		sess, err := createWithRewrite(t, types.SessionConfig{}, inRequest)
		require.NoError(t, err)
		assert.Empty(t, sess.IPAddress)
		assert.Empty(t, sess.UserAgent)
	})
	t.Run("behind a trusted proxy", func(t *testing.T) {
		ipCfg, err := types.NewClientConfig([]string{"203.0.113.0/24"}, "")
		require.NoError(t, err)
		sm := transport.NewSessionManager(store.New(sessionsTokensDB(t)), nil, testCrypto(t),
			types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, CaptureIPAndAgent: true},
			&passDispatcher{}, nil, managersAuth, ipCfg)
		sess, _, err := sm.Create(inRequest, "u1", active)
		require.NoError(t, err)
		assert.Equal(t, "198.51.100.9", sess.IPAddress, "the client the proxy forwarded for")
	})
}

// rewriteDispatcher is a passDispatcher whose before chain rewrites every key
// of the auth.session.beforeCreate payload.
type rewriteDispatcher struct{ passDispatcher }

func (d *rewriteDispatcher) RunBefore(h *types.HookContext, point types.HookPoint, p behemoth.M) (behemoth.M, error) {
	if point == hooks.HookSessionBeforeCreate {
		p[hooks.HookValueIPAddress], p[hooks.HookValueUserAgent] = "203.0.113.0", "masked"
		p[hooks.HookValueUserID], p[hooks.HookValueState] = "someone-else", string(types.SessionPending)
	}
	return p, nil
}

// createWithRewrite creates an active session for u1 under a rewriteDispatcher.
func createWithRewrite(t *testing.T, cfg types.SessionConfig, ctx context.Context) (*models.Session, error) {
	t.Helper()
	cfg.ExpiresIn, cfg.PendingExpiresIn = time.Hour, time.Minute
	sm := transport.NewSessionManager(store.New(sessionsTokensDB(t)), nil, testCrypto(t), cfg,
		&rewriteDispatcher{}, nil, managersAuth, nil)
	sess, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	return sess, err
}

// The token manager's hooks get the same: issue, a consume, and a failed
// second consume each dispatch with their own point and phase.
func TestTokenHooksGetACompleteContext(t *testing.T) {
	catalog := bmth.NewDefaultTokenCatalog()
	require.NoError(t, catalog.Declare(types.TokenKindDef{Kind: kindReset, SingleUse: true, DefaultTTL: time.Hour, Backend: types.TokenBackendDB, Owner: "core"}))
	d := &passDispatcher{}
	tm := transport.NewDefaultTokenManager(store.New(sessionsTokensDB(t)), nil, catalog, testCrypto(t), d, types.TokenConfig{}, managersAuth)

	ctx := context.Background()
	_, raw, err := tm.Issue(ctx, kindReset, "u1", nil)
	require.NoError(t, err)
	_, err = tm.Consume(ctx, kindReset, raw)
	require.NoError(t, err)
	_, err = tm.Consume(ctx, kindReset, raw)
	require.Error(t, err)

	type dispatch struct {
		point types.HookPoint
		phase types.HookPhase
	}
	var got []dispatch
	for _, h := range d.seen {
		got = append(got, dispatch{h.Point, h.Phase})
		assert.Same(t, managersAuth, h.Auth, "%s", h.Point)
		assert.NotNil(t, h.Values, "%s", h.Point)
		assert.Nil(t, h.Request, "%s: no request outside one", h.Point)
	}
	assert.Equal(t, []dispatch{
		{hooks.HookTokenBeforeIssue, types.BeforeHookPhase}, {hooks.HookTokenAfterIssue, types.AfterHookPhase},
		{hooks.HookTokenConsumed, types.AfterHookPhase},
		{hooks.HookTokenFailed, types.FailedHookPhase},
	}, got)
}

// ---- token manager ----

const kindReset types.TokenKind = "password_reset"
const kindAPI types.TokenKind = "api_key"

func newTokenManager(t *testing.T) (types.TokenManager, *store.Store) {
	t.Helper()
	catalog := bmth.NewDefaultTokenCatalog()
	require.NoError(t, catalog.Declare(types.TokenKindDef{Kind: kindReset, SingleUse: true, DefaultTTL: time.Hour, Backend: types.TokenBackendDB, Owner: "core"}))
	require.NoError(t, catalog.Declare(types.TokenKindDef{Kind: kindAPI, Backend: types.TokenBackendDB, Owner: "core"}))
	st := store.New(sessionsTokensDB(t))
	return transport.NewDefaultTokenManager(st, nil, catalog, testCrypto(t), &passDispatcher{}, types.TokenConfig{}, managersAuth), st
}

func TestTokenIssueVerifyConsume(t *testing.T) {
	ctx := context.Background()
	tm, _ := newTokenManager(t)

	tok, raw, err := tm.Issue(ctx, kindReset, "u1", behemoth.M{"redirect": "/reset"})
	require.NoError(t, err)
	assert.NotEmpty(t, tok.ID)

	verified, err := tm.Verify(ctx, kindReset, raw)
	require.NoError(t, err)
	assert.Equal(t, "/reset", verified.MetadataJSON["redirect"], "metadata round-trips through the database")
	assert.Equal(t, "u1", verified.Subject)

	consumed, err := tm.Consume(ctx, kindReset, raw)
	require.NoError(t, err)
	require.NotNil(t, consumed.ConsumedAt)

	_, err = tm.Consume(ctx, kindReset, raw)
	assert.True(t, behemotherr.IsCode(err, "token_already_consumed"), "%v", err)
	_, err = tm.Verify(ctx, kindReset, raw)
	assert.Error(t, err, "a consumed token no longer verifies")
}

func TestTokenConsumeConcurrently(t *testing.T) {
	ctx := context.Background()
	tm, _ := newTokenManager(t)
	_, raw, err := tm.Issue(ctx, kindReset, "u1", nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tm.Consume(ctx, kindReset, raw); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, wins, "a single-use token is consumed exactly once")
}

func TestTokenRevoke(t *testing.T) {
	ctx := context.Background()
	tm, _ := newTokenManager(t)

	tok, raw, err := tm.Issue(ctx, kindAPI, "u1", nil)
	require.NoError(t, err)
	require.NoError(t, tm.Revoke(ctx, tok.ID))
	require.NoError(t, tm.Revoke(ctx, tok.ID), "revoking twice is a no-op")
	_, err = tm.Verify(ctx, kindAPI, raw)
	assert.True(t, behemotherr.IsCode(err, "token_revoked"), "%v", err)

	_, a, err := tm.Issue(ctx, kindAPI, "u2", nil)
	require.NoError(t, err)
	_, b, err := tm.Issue(ctx, kindAPI, "u2", nil)
	require.NoError(t, err)
	_, other, err := tm.Issue(ctx, kindAPI, "u3", nil)
	require.NoError(t, err)
	require.NoError(t, tm.RevokeAllForSubject(ctx, kindAPI, "u2"))
	for _, r := range []string{a, b} {
		_, err := tm.Verify(ctx, kindAPI, r)
		assert.Error(t, err, "u2's tokens are revoked")
	}
	_, err = tm.Verify(ctx, kindAPI, other)
	assert.NoError(t, err, "another subject's token is untouched")
}

// ListForSubject returns what a subject can still use of one kind, oldest
// first: a consumed, a revoked and an expired token are left out, and so are
// another subject's and another kind's.
func TestTokenListForSubject(t *testing.T) {
	ctx := context.Background()
	catalog := bmth.NewDefaultTokenCatalog()
	const kindShort types.TokenKind = "short_lived"
	for _, def := range []types.TokenKindDef{
		{Kind: kindReset, SingleUse: true, DefaultTTL: time.Hour, Backend: types.TokenBackendDB, Owner: "core"},
		{Kind: kindShort, SingleUse: true, DefaultTTL: time.Millisecond, Backend: types.TokenBackendDB, Owner: "core"},
		{Kind: "in_kv", SingleUse: true, DefaultTTL: time.Hour, Backend: types.TokenBackendKV, Owner: "core"},
	} {
		require.NoError(t, catalog.Declare(def))
	}
	tm := transport.NewDefaultTokenManager(store.New(sessionsTokensDB(t)), nil, catalog, testCrypto(t), &passDispatcher{}, types.TokenConfig{}, managersAuth)

	issue := func(kind types.TokenKind, subject string) (*types.Token, string) {
		tok, raw, err := tm.Issue(ctx, kind, subject, behemoth.M{"n": subject})
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond) // distinct creation times
		return tok, raw
	}
	first, _ := issue(kindReset, "u1")
	_, usedRaw := issue(kindReset, "u1")
	revoked, _ := issue(kindReset, "u1")
	last, _ := issue(kindReset, "u1")
	issue(kindReset, "u2")
	issue(kindShort, "u1") // expired by the time it is listed
	_, err := tm.Consume(ctx, kindReset, usedRaw)
	require.NoError(t, err)
	require.NoError(t, tm.Revoke(ctx, revoked.ID))

	listed, err := tm.ListForSubject(ctx, kindReset, "u1")
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.Equal(t, []string{first.ID, last.ID}, []string{listed[0].ID, listed[1].ID}, "oldest first")
	assert.Equal(t, behemoth.M{"n": "u1"}, listed[0].MetadataJSON, "the record, with its metadata")

	expired, err := tm.ListForSubject(ctx, kindShort, "u1")
	require.NoError(t, err)
	assert.Empty(t, expired)
	none, err := tm.ListForSubject(ctx, kindReset, "nobody")
	require.NoError(t, err)
	assert.Empty(t, none)

	_, err = tm.ListForSubject(ctx, "in_kv", "u1")
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "a kind in the key-value storage can't be listed: %v", err)
	_, err = tm.ListForSubject(ctx, "undeclared", "u1")
	assert.Error(t, err)
}

// A session is fresh for FreshAge after it was created or promoted.
// RequireFreshSession lets a fresh one through and refuses one that is
// still valid but older.
func TestSessionFreshness(t *testing.T) {
	ctx := context.Background()
	sm, _ := newSessionManager(t, types.SessionConfig{FreshAge: 150 * time.Millisecond, Transport: types.TransportHeader})
	active, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	pending, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)
	assert.True(t, sm.IsFresh(active), "just created")
	assert.False(t, sm.IsFresh(pending), "a pending session has not finished signing in")
	assert.False(t, sm.IsFresh(nil))

	reached := 0
	handler := types.RequireFreshSession(sm)(func(rctx *types.RequestContext) error {
		reached++
		assert.NotNil(t, rctx.Values["session"], "it does what RequireSession does first")
		return nil
	})
	request := func(header string) (*types.RequestContext, error) {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rctx := &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		return rctx, handler(rctx)
	}
	_, err = request("Bearer " + raw)
	require.NoError(t, err)
	require.Equal(t, 1, reached)

	time.Sleep(250 * time.Millisecond)
	stale, err := sm.Validate(ctx, raw)
	require.NoError(t, err, "the session is still valid")
	assert.False(t, sm.IsFresh(stale))
	_, err = request("Bearer " + raw)
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionNotFresh), "%v", err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategorySession), "a session error, answered with 401: %v", err)
	_, err = request("")
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionMissing), "without a session it answers as RequireSession does: %v", err)
	assert.Equal(t, 1, reached, "neither request reached the handler")

	promoted, err := sm.Promote(ctx, pending.ID)
	require.NoError(t, err)
	assert.True(t, sm.IsFresh(promoted), "passing the second factor is a credential check")

	// Left at zero, FreshAge is 15 minutes.
	byDefault, _ := newSessionManager(t, types.SessionConfig{})
	session, _, err := byDefault.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	assert.True(t, byDefault.IsFresh(session))
	session.FreshAt = time.Now().Add(-types.DefaultFreshAge - time.Second)
	assert.False(t, byDefault.IsFresh(session))
}

// A session manager built with a zero SessionConfig works: sessions last
// the documented default, and the token travels in the default cookie.
func TestSessionManagerWithAZeroConfig(t *testing.T) {
	ctx := context.Background()
	sm := transport.NewSessionManager(store.New(sessionsTokensDB(t)), nil, testCrypto(t), types.SessionConfig{}, &passDispatcher{}, nil, managersAuth, nil)

	active, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(types.DefaultSessionExpiresIn), active.ExpiresAt, time.Minute)
	pending, _, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(types.DefaultSessionPendingExpiresIn), pending.ExpiresAt, time.Minute)
	_, err = sm.Validate(ctx, raw)
	require.NoError(t, err, "the session did not expire the moment it was created")

	rctx := &types.RequestContext{Response: types.NewResponseRecorder(), Values: behemoth.M{}}
	assert.False(t, sm.WriteToken(rctx, raw, active))
	assert.Contains(t, rctx.Response.Headers.Get("Set-Cookie"), "session_token="+raw, "the default transport is the cookie")
}

// Each transport hands the token over in its own place, and reads it back
// from where its client sends it.
func TestSessionTokenTransports(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		cfg        types.SessionConfig
		cookie     string // the cookie's name when one is set, "" when none is
		header     bool   // the token is in Set-Auth-Token
		inBody     bool   // the route is told to put it in the body
		readCookie bool   // a request's cookie is accepted
		readBearer bool   // a request's Authorization header is accepted
	}{
		"cookie":        {types.SessionConfig{Transport: types.TransportCookie}, "session_token", false, false, true, false},
		"cookie, named": {types.SessionConfig{Transport: types.TransportCookie, CookieName: "sid"}, "sid", false, false, true, false},
		"header":        {types.SessionConfig{Transport: types.TransportHeader}, "", true, false, false, true},
		"body":          {types.SessionConfig{Transport: types.TransportBody}, "", false, true, false, true},
		"both":          {types.SessionConfig{Transport: types.TransportBoth, CookieName: "sid"}, "sid", true, false, true, true},
	} {
		sm, _ := newSessionManager(t, tc.cfg)
		session, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
		require.NoError(t, err, name)

		rctx := &types.RequestContext{Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		assert.Equal(t, tc.inBody, sm.WriteToken(rctx, raw, session), "%s: in the body", name)
		setCookie := rctx.Response.Headers.Get("Set-Cookie")
		if tc.cookie == "" {
			assert.Empty(t, setCookie, "%s: no cookie", name)
		} else {
			assert.True(t, strings.HasPrefix(setCookie, tc.cookie+"="+raw+";"), "%s: Set-Cookie = %q", name, setCookie)
			assert.Contains(t, setCookie, "HttpOnly", name)
		}
		wantHeader := ""
		if tc.header {
			wantHeader = raw
		}
		assert.Equal(t, wantHeader, rctx.Response.Headers.Get(types.SessionTokenHeader), "%s: %s", name, types.SessionTokenHeader)
		assert.Empty(t, rctx.Values, "%s: nothing is parked in the request's values", name)

		cookieName := tc.cfg.CookieName
		if cookieName == "" {
			cookieName = "session_token"
		}
		withCookie := httptest.NewRequest(http.MethodGet, "/x", nil)
		withCookie.AddCookie(&http.Cookie{Name: cookieName, Value: raw})
		got, ok := sm.ExtractToken(withCookie)
		assert.Equal(t, tc.readCookie, ok, "%s: reads the cookie", name)
		if tc.readCookie {
			assert.Equal(t, raw, got, name)
		}
		withBearer := httptest.NewRequest(http.MethodGet, "/x", nil)
		withBearer.Header.Set("Authorization", "Bearer "+raw)
		got, ok = sm.ExtractToken(withBearer)
		assert.Equal(t, tc.readBearer, ok, "%s: reads the Authorization header", name)
		if tc.readBearer {
			assert.Equal(t, raw, got, name)
		}
		_, ok = sm.ExtractToken(httptest.NewRequest(http.MethodGet, "/x", nil))
		assert.False(t, ok, "%s: a request without a token", name)

		// ClearToken takes back what WriteToken handed over, from the
		// request that presented it. A browser replaces a cookie only with
		// one of the same name and path, so the cookie it sets is the one
		// above, emptied and expired. A transport without a cookie has
		// nothing to take back.
		clear := func(req *http.Request) *types.RequestContext {
			cleared := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
			sm.ClearToken(cleared)
			return cleared
		}
		cleared := clear(withCookie)
		if tc.cookie == "" {
			assert.Empty(t, cleared.Response.Headers, "%s: ClearToken writes nothing", name)
		} else {
			written := (&http.Response{Header: rctx.Response.Headers}).Cookies()
			gone := (&http.Response{Header: cleared.Response.Headers}).Cookies()
			require.Len(t, written, 1, name)
			require.Len(t, gone, 1, name)
			assert.Equal(t, written[0].Name, gone[0].Name, "%s: the same cookie", name)
			assert.Equal(t, written[0].Path, gone[0].Path, "%s: the same path", name)
			assert.Empty(t, gone[0].Value, "%s: no token in it", name)
			assert.Negative(t, gone[0].MaxAge, "%s: Max-Age=0, which deletes it", name)
			assert.True(t, gone[0].Expires.Before(time.Now()), "%s: and an Expires in the past", name)
			assert.True(t, gone[0].HttpOnly && gone[0].Secure, "%s: with the attributes of the cookie it replaces", name)
			assert.Equal(t, written[0].SameSite, gone[0].SameSite, name)
			assert.Empty(t, cleared.Response.Headers.Get(types.SessionTokenHeader), "%s: no token header", name)
		}
		// A request that did not present its token in the cookie keeps
		// whatever cookie it has: under TransportBoth the token may come as
		// a bearer token next to the cookie of another session.
		assert.Empty(t, clear(withBearer).Response.Headers, "%s: no cookie in the request, none to remove", name)
		otherCookie := httptest.NewRequest(http.MethodGet, "/x", nil)
		otherCookie.Header.Set("Authorization", "Bearer "+raw)
		otherCookie.AddCookie(&http.Cookie{Name: cookieName, Value: "another-sessions-token"})
		if tc.readBearer {
			assert.Empty(t, clear(otherCookie).Response.Headers, "%s: the cookie is another session's", name)
		}
	}
}

// RequireSession applies the rolling expiration, and the cookie has to
// follow it: a browser drops a cookie at the date it was set with, however
// long the session lasts on the server.
func TestRequireSessionExtendsTheCookieOfARollingSession(t *testing.T) {
	ctx := context.Background()
	const ownCacheControl = "private, max-age=60"
	// request sends one request through RequireSession to a handler that
	// sets a Cache-Control of its own. It returns the response and the
	// session the handler saw.
	request := func(sm types.SessionManager, cookie, bearer string) (*types.RequestContext, *models.Session) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "session_token", Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		var seen *models.Session
		handler := types.RequireSession(sm)(func(rctx *types.RequestContext) error {
			seen, _ = rctx.Values["session"].(*models.Session)
			rctx.Response.SetHeader("Cache-Control", ownCacheControl)
			return rctx.Response.JSON(http.StatusOK, behemoth.M{})
		})
		rctx := &types.RequestContext{Ctx: req.Context(), Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}}
		require.NoError(t, handler(rctx))
		require.NotNil(t, seen, "the request reached the handler")
		return rctx, seen
	}
	cookies := func(rctx *types.RequestContext) []*http.Cookie {
		return (&http.Response{Header: rctx.Response.Headers}).Cookies()
	}
	alwaysDue := 2 * time.Hour // above the hour a session of newSessionManager lasts

	// A session that is due: the cookie comes back with the new date.
	rolling, _ := newSessionManager(t, types.SessionConfig{UpdateAge: alwaysDue})
	created, raw, err := rolling.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	rctx, seen := request(rolling, raw, "")
	assert.True(t, seen.ExpiresAt.After(created.ExpiresAt), "the handler sees the session with its new expiry")
	set := cookies(rctx)
	require.Len(t, set, 1)
	assert.Equal(t, "session_token", set[0].Name)
	assert.Equal(t, raw, set[0].Value, "the same token")
	assert.True(t, seen.ExpiresAt.UTC().Truncate(time.Second).Equal(set[0].Expires), "the cookie expires with the extended session: %s", set[0].Expires)
	assert.Equal(t, "/", set[0].Path)
	assert.True(t, set[0].HttpOnly && set[0].Secure, "the attributes of the cookie it replaces")
	assert.Equal(t, "no-store", rctx.Response.Headers.Get("Cache-Control"), "the response carries the token, so it is not cached, whatever the handler set")

	// A session that is not due: nothing is written, and the handler's
	// Cache-Control stands.
	fixed, _ := newSessionManager(t, types.SessionConfig{})
	created, raw, err = fixed.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	rctx, seen = request(fixed, raw, "")
	assert.True(t, seen.ExpiresAt.Equal(created.ExpiresAt))
	assert.Empty(t, cookies(rctx))
	assert.Equal(t, ownCacheControl, rctx.Response.Headers.Get("Cache-Control"))

	// The header transport: the session is extended, and its client keeps
	// the token without a date, so the response hands out nothing.
	byHeader, _ := newSessionManager(t, types.SessionConfig{Transport: types.TransportHeader, UpdateAge: alwaysDue})
	created, raw, err = byHeader.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	rctx, seen = request(byHeader, "", raw)
	assert.True(t, seen.ExpiresAt.After(created.ExpiresAt))
	assert.Empty(t, cookies(rctx))
	assert.Empty(t, rctx.Response.Headers.Get(types.SessionTokenHeader))
	assert.Equal(t, ownCacheControl, rctx.Response.Headers.Get("Cache-Control"))

	// Both transports: the cookie is extended for the client that sent the
	// token in it. A bearer token is read first, and the cookie next to it
	// may be another session's, which must not be overwritten.
	both, _ := newSessionManager(t, types.SessionConfig{Transport: types.TransportBoth, UpdateAge: alwaysDue})
	_, asBearer, err := both.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	_, inCookie, err := both.Create(ctx, "u2", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	rctx, seen = request(both, inCookie, asBearer)
	assert.Equal(t, "u1", seen.UserID, "the bearer token's session")
	assert.Empty(t, cookies(rctx), "the cookie is another session's")
	assert.Equal(t, ownCacheControl, rctx.Response.Headers.Get("Cache-Control"))
	rctx, seen = request(both, inCookie, "")
	assert.Equal(t, "u2", seen.UserID)
	set = cookies(rctx)
	require.Len(t, set, 1)
	assert.Equal(t, inCookie, set[0].Value)
}

// Under a real Boot the session manager dispatches through the default
// dispatcher, which rejects undeclared points. Create and Revoke each fire a
// before and an after point, and core declares all four.
func TestSessionPointsAreDeclaredUnderBoot(t *testing.T) {
	ctx := context.Background()
	app, err := bmth.Prepare(nil, bmth.PrepareConfig{})
	require.NoError(t, err)

	var fired []types.HookPoint
	var auths []*types.AuthContext
	before := func(hctx *types.HookContext, p behemoth.M) (behemoth.M, error) {
		fired, auths = append(fired, hctx.Point), append(auths, hctx.Auth)
		return p, nil
	}
	after := func(hctx *types.HookContext, _ any) error {
		fired, auths = append(fired, hctx.Point), append(auths, hctx.Auth)
		return nil
	}
	ac, err := bmth.Boot(ctx, app, sessionsTokensDB(t), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("cd", 32)}, Current: 1},
		},
		Session: types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: 5 * time.Minute},
		Hooks: func(reg types.HookRegistry) error {
			if err := reg.OnBefore(hooks.HookSessionBeforeCreate, before, nil); err != nil {
				return err
			}
			if err := reg.OnAfter(hooks.HookSessionAfterCreate, after, nil); err != nil {
				return err
			}
			if err := reg.OnBefore(hooks.HookSessionBeforeRevoke, before, nil); err != nil {
				return err
			}
			return reg.OnAfter(hooks.HookSessionAfterRevoke, after, nil)
		},
	})
	require.NoError(t, err)

	sess, _, err := ac.SessionManager.Create(ctx, "u1", types.SessionMeta{State: types.SessionActive})
	require.NoError(t, err)
	require.NoError(t, ac.SessionManager.Revoke(ctx, sess.ID, "user_logout"))
	assert.Equal(t, []types.HookPoint{
		hooks.HookSessionBeforeCreate, hooks.HookSessionAfterCreate,
		hooks.HookSessionBeforeRevoke, hooks.HookSessionAfterRevoke,
	}, fired)
	for i, got := range auths {
		assert.Same(t, ac, got, "%s: handlers get the booted AuthContext", fired[i])
	}
}
