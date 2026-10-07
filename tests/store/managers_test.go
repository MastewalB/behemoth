package store_test

import (
	"context"
	"database/sql"
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
	require.NoError(t, sm.Touch(ctx, sess.ID))
	got, err := sm.Get(ctx, raw)
	require.NoError(t, err)
	assert.True(t, got.ExpiresAt.After(sess.ExpiresAt), "expiry moved forward")
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
