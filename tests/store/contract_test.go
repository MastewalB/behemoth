package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/models"
	bunAdapter "github.com/MastewalB/behemoth/storage/adapters/bun"
	gormAdapter "github.com/MastewalB/behemoth/storage/adapters/gorm"
	mongoAdapter "github.com/MastewalB/behemoth/storage/adapters/mongo"
	mysqlAdapter "github.com/MastewalB/behemoth/storage/adapters/mysql"
	pgAdapter "github.com/MastewalB/behemoth/storage/adapters/postgres"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	sqlserverAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlserver"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/transport"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	gormpostgres "gorm.io/driver/postgres"
	gormsqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// coreSchema is what Prepare would freeze: core's tables, plus two plugin
// contributions to users (plan stored under another physical name).
func coreSchema(t *testing.T) ([]schema.Table, behemoth.SchemaResolver) {
	t.Helper()
	reg := schema.NewRegistry()
	require.NoError(t, reg.Declare(&models.User{}, models.UserTableSchema()))
	require.NoError(t, reg.Declare(&models.Session{}, models.SessionTableSchema()))
	require.NoError(t, reg.Declare(&models.Token{}, models.TokenTableSchema()))
	require.NoError(t, reg.Declare(&models.Account{}, models.AccountTableSchema()))
	require.NoError(t, reg.Declare(&models.RateLimit{}, models.RateLimitTableSchema()))
	require.NoError(t, reg.Declare(&models.AuditLog{}, models.AuditLogTableSchema()))
	tfa := twoFactorEnabled.Contribution(schema.Column{Type: schema.ColTypeBoolean, Default: false})
	tfa.Owner = "two-factor"
	require.NoError(t, reg.ExtendColumn(tfa))
	p := plan.Contribution(schema.Column{Type: schema.ColTypeString, Length: 32, Nullable: true, PhysicalName: "subscription_plan"})
	p.Owner = "billing"
	require.NoError(t, reg.ExtendColumn(p))
	require.NoError(t, reg.Freeze())

	resolver := core.NewSchemaResolver()
	resolver.Freeze(core.BuildSchemaResolverTable(reg, core.NewMigrationConfig(core.MigrationConfig{})))
	var tables []schema.Table
	for _, name := range []string{models.UserTable, models.SessionTable, models.TokenTable, models.AccountTable, models.RateLimitTable, models.AuditLogTable} {
		t, _ := reg.Lookup(name)
		t.ForeignKeys = nil // created without them: the contract doesn't depend on FK enforcement
		tables = append(tables, t)
	}
	return tables, resolver
}

func createTables(t *testing.T, driver core.SchemaDriver, tables []schema.Table) {
	t.Helper()
	m := core.Migration{ID: "0001"}
	snapshot := core.SchemaSnapshot{Version: m.ID, Tables: map[string]schema.Table{}}
	for _, table := range tables {
		m.Up = append(m.Up, core.SchemaOperation{ID: "create_" + table.Name, Kind: core.OpCreateTable, Table: table.Name, NewTable: &table})
		for _, idx := range table.Indexes { // CreateTable doesn't: a generated migration adds them as their own operations
			m.Up = append(m.Up, core.SchemaOperation{ID: "add_" + idx.Name, Kind: core.OpAddIndex, Table: table.Name, Index: &idx})
		}
		snapshot.Tables[table.Name] = table
	}
	require.NoError(t, driver.ApplyMigration(context.Background(), core.MigrationRequest{
		Migration:      m,
		LedgerEntry:    core.MigrationLedgerEntry{ID: m.ID, AppliedAt: time.Now()},
		SnapshotUpdate: snapshot,
		LedgerTable:    "behemoth_auth_schema",
		SnapshotTable:  "behemoth_auth_schema_snapshot",
	}))
}

// contractBackends open a database with core's tables and return an adapter
// over it. The raw adapters are the control: the contract holds for them.
func contractBackends() map[string]func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
	openSQLite := func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) *sql.DB {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "contract.db")+"?_busy_timeout=10000")
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })
		createTables(t, sqliteAdapter.NewSQLiteDriver(db, r), tables)
		return db
	}
	openPostgres := func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) *sql.DB {
		if testing.Short() {
			t.Skip("starts a Postgres container")
		}
		ctx := context.Background()
		db, cleanup := testutils.SetupPostgresTestDB(t, ctx)
		t.Cleanup(cleanup)
		require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)
		createTables(t, pgAdapter.NewPostgreSQLDriver(db, r), tables)
		return db
	}
	openMySQL := func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) *sql.DB {
		if testing.Short() {
			t.Skip("starts a MySQL container")
		}
		ctx := context.Background()
		db, cleanup := testutils.SetupMySQLTestDB(t, ctx)
		t.Cleanup(cleanup)
		require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)
		createTables(t, mysqlAdapter.NewMySQLDriver(db, r), tables)
		return db
	}
	openSQLServer := func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) *sql.DB {
		if testing.Short() {
			t.Skip("starts a SQL Server container")
		}
		db, cleanup := testutils.SetupMSSQLTestDB(t)
		t.Cleanup(cleanup)
		require.Eventually(t, func() bool { return db.PingContext(context.Background()) == nil }, 30*time.Second, 200*time.Millisecond)
		createTables(t, sqlserverAdapter.NewSQLServerDriver(db, r), tables)
		return db
	}
	quiet := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}

	return map[string]func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database{
		"sql/sqlite": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return sqliteAdapter.NewSQLiteAdapter(openSQLite(t, tables, r), r)
		},
		"sql/postgres": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return pgAdapter.NewPostgresAdapter(openPostgres(t, tables, r), r)
		},
		"sql/mysql": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return mysqlAdapter.NewMySQLAdapter(openMySQL(t, tables, r), r)
		},
		"sql/sqlserver": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return sqlserverAdapter.NewSQLServerAdapter(openSQLServer(t, tables, r), r)
		},
		"gorm/sqlite": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			gdb, err := gorm.Open(gormsqlite.New(gormsqlite.Config{Conn: openSQLite(t, tables, r)}), quiet)
			require.NoError(t, err)
			return gormAdapter.NewGormAdapter(gdb, r)
		},
		"gorm/postgres": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			gdb, err := gorm.Open(gormpostgres.New(gormpostgres.Config{Conn: openPostgres(t, tables, r)}), quiet)
			require.NoError(t, err)
			return gormAdapter.NewGormAdapter(gdb, r)
		},
		"bun/sqlite": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return bunAdapter.NewBunAdapter(bun.NewDB(openSQLite(t, tables, r), sqlitedialect.New()), r)
		},
		"bun/postgres": func(t *testing.T, tables []schema.Table, r behemoth.SchemaResolver) behemoth.Database {
			return bunAdapter.NewBunAdapter(bun.NewDB(openPostgres(t, tables, r), pgdialect.New()), r)
		},
	}
}

// TestStoreContract runs the store and the managers over every backend with
// behemoth's own models — the shapes the store really persists.
func TestStoreContract(t *testing.T) {
	tables, resolver := coreSchema(t)
	for name, open := range contractBackends() {
		t.Run(name, func(t *testing.T) {
			db := open(t, tables, resolver)
			st := store.New(db, store.WithSchema(resolver), store.WithEncryptor(testCrypto(t).AtRest))
			t.Run("Users", func(t *testing.T) { usersContract(t, st) })
			t.Run("Sessions", func(t *testing.T) { sessionsContract(t, st) })
			t.Run("Tokens", func(t *testing.T) { tokensContract(t, st) })
			t.Run("Accounts", func(t *testing.T) { accountsContract(t, st, db) })
			t.Run("RateLimits", func(t *testing.T) { rateLimitsContract(t, db, resolver) })
			t.Run("AuditLog", func(t *testing.T) { auditLogContract(t, st) })
		})
	}
}

// TestStoreAuditLogMongo runs the audit log part of the contract on MongoDB.
// The rest of the contract is not run there: MongoDB has no migration driver,
// so nothing creates the unique indexes the other parts rely on.
func TestStoreAuditLogMongo(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a MongoDB container")
	}
	ctx := context.Background()
	_, resolver := coreSchema(t)
	client, cleanup := testutils.SetupMongoTestDB(ctx, t)
	t.Cleanup(cleanup)
	db := mongoAdapter.NewMongoAdapter(client, "contract", resolver)
	auditLogContract(t, store.New(db, store.WithSchema(resolver), store.WithEncryptor(testCrypto(t).AtRest)))
}

func usersContract(t *testing.T, st *store.Store) {
	ctx := context.Background()
	u := &models.User{Email: " Ada@Example.com", Firstname: "Ada"}
	require.NoError(t, plan.Set(u, "pro"))
	require.NoError(t, st.CreateUser(ctx, u))
	var found *models.User
	err := st.CreateUser(ctx, &models.User{Email: "ada@example.com"})
	assert.True(t, behemotherr.IsDuplicateKey(err), "duplicate email: %v", err)

	found, err = st.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Equal(t, "Ada", found.Firstname)
	assert.False(t, found.CreatedAt.IsZero(), "timestamps read back as time.Time")
	p, _, err := plan.Get(found)
	require.NoError(t, err)
	assert.Equal(t, "pro", p, "a contributed column under another physical name round-trips")

	changes, err := twoFactorEnabled.Update(true)
	require.NoError(t, err)
	updated, err := st.UpdateUser(ctx, u.ID, changes)
	require.NoError(t, err)
	on, _, err := twoFactorEnabled.Get(updated)
	require.NoError(t, err)
	assert.True(t, on)

	_, err = st.UpdateUser(ctx, "no-such-user", behemoth.M{models.UserFirstname: "x"})
	assert.True(t, behemotherr.IsNotFound(err), "update of a missing row: %v", err)
	require.NoError(t, st.DeleteUser(ctx, u.ID))
	assert.True(t, behemotherr.IsNotFound(st.DeleteUser(ctx, u.ID)), "second delete is NotFound")
	_, err = st.FindUserByID(ctx, u.ID)
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)
}

func sessionsContract(t *testing.T, st *store.Store) {
	ctx := context.Background()
	sm := transport.NewSessionManager(st, nil, testCrypto(t),
		types.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute}, &passDispatcher{}, nil, nil, nil)

	sess, raw, err := sm.Create(ctx, "u1", types.SessionMeta{State: types.SessionPending})
	require.NoError(t, err)
	got, err := sm.Get(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	promoted, err := sm.Promote(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, models.SessionActive, promoted.State)
	require.NoError(t, sm.Revoke(ctx, sess.ID, "user_logout"))
	_, err = sm.Get(ctx, raw)
	assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeSessionRevoked), "%v", err)
	listed, err := sm.ListForUser(ctx, "u1")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.NotNil(t, listed[0].RevokedAt)
}

func tokensContract(t *testing.T, st *store.Store) {
	ctx := context.Background()
	catalog := bmth.NewDefaultTokenCatalog()
	require.NoError(t, catalog.Declare(types.TokenKindDef{Kind: kindReset, SingleUse: true, DefaultTTL: time.Hour, Backend: types.TokenBackendDB, Owner: "core"}))
	tm := transport.NewDefaultTokenManager(st, nil, catalog, testCrypto(t), &passDispatcher{}, types.TokenConfig{}, nil)

	_, raw, err := tm.Issue(ctx, kindReset, "u1", behemoth.M{"redirect": "/reset"})
	require.NoError(t, err)
	verified, err := tm.Verify(ctx, kindReset, raw)
	require.NoError(t, err)
	assert.Equal(t, "/reset", verified.MetadataJSON["redirect"], "metadata round-trips")

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 20 {
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

func accountsContract(t *testing.T, st *store.Store, db behemoth.Database) {
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	google := &models.Account{UserID: "u1", ProviderID: "google", AccountID: "g-123",
		AccessToken: "access-1", RefreshToken: "refresh-1", AccessTokenExpiresAt: &expires, Scope: "openid email"}
	require.NoError(t, st.CreateAccount(ctx, google))
	assert.Equal(t, "access-1", google.AccessToken, "the caller's account keeps the plaintext")

	raw, err := db.FindOne(ctx, &models.Account{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.AccountID, Operator: clause.OpEqual, Value: google.ID}}})
	require.NoError(t, err)
	stored := raw.(*models.Account)
	assert.NotContains(t, stored.AccessToken, "access-1", "tokens are encrypted at rest")
	version, err := store.SealedKeyVersion(stored.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "the key version travels with the ciphertext")
	assert.Empty(t, stored.IDToken, "an absent token is NULL, not a sealed empty string")

	found, err := st.FindAccount(ctx, "google", "g-123")
	require.NoError(t, err)
	assert.Equal(t, google.ID, found.ID)
	assert.Equal(t, "access-1", found.AccessToken)
	assert.Equal(t, "refresh-1", found.RefreshToken)
	assert.Equal(t, "openid email", found.Scope)
	require.NotNil(t, found.AccessTokenExpiresAt)
	assert.True(t, found.AccessTokenExpiresAt.Equal(expires), "expiry round-trips: %v", found.AccessTokenExpiresAt)
	assert.Nil(t, found.RefreshTokenExpiresAt)

	err = st.CreateAccount(ctx, &models.Account{UserID: "u2", ProviderID: "google", AccountID: "g-123"})
	assert.True(t, behemotherr.IsDuplicateKey(err), "one account per (provider, account id): %v", err)

	updated, err := st.UpdateAccount(ctx, google.ID, behemoth.M{models.AccountAccessToken: "access-2", models.AccountIDToken: ""})
	require.NoError(t, err)
	assert.Equal(t, "access-2", updated.AccessToken)
	assert.Equal(t, "refresh-1", updated.RefreshToken, "a token that wasn't updated is still readable")
	cleared, err := st.UpdateAccount(ctx, google.ID, behemoth.M{models.AccountRefreshToken: nil})
	require.NoError(t, err)
	assert.Empty(t, cleared.RefreshToken)

	credential := &models.Account{UserID: "u1", ProviderID: models.ProviderCredential, AccountID: "u1", PasswordHash: "hash"}
	require.NoError(t, st.CreateAccount(ctx, credential))
	listed, err := st.ListAccountsForUser(ctx, "u1")
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.Equal(t, "access-2", listed[0].AccessToken, "oldest first, tokens opened")
	assert.Equal(t, "hash", listed[1].PasswordHash)

	noCrypto := store.New(db)
	err = noCrypto.CreateAccount(ctx, &models.Account{UserID: "u3", ProviderID: "github", AccountID: "gh-1", AccessToken: "t"})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "no encryptor, no plaintext token on disk: %v", err)
	_, err = st.FindAccount(ctx, "github", "gh-1")
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)

	// A stored value that isn't a valid ciphertext is an error, not a panic.
	require.NoError(t, db.UpdateOne(ctx, &models.Account{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.AccountID, Operator: clause.OpEqual, Value: google.ID}}}, behemoth.M{models.AccountAccessToken: "v1:AAAA"}))
	_, err = st.FindAccountByID(ctx, google.ID)
	assert.True(t, behemotherr.IsCode(err, "short_cipher_length"), "truncated ciphertext: %v", err)

	require.NoError(t, st.DeleteAccount(ctx, google.ID))
	_, err = st.FindAccountByID(ctx, google.ID)
	assert.True(t, behemotherr.IsNotFound(err), "%v", err)
}

func rateLimitsContract(t *testing.T, db behemoth.Database, resolver behemoth.SchemaResolver) {
	ctx := context.Background()
	var clock atomic.Int64 // seconds past t0
	st := store.New(db, store.WithSchema(resolver), store.WithClock(func() time.Time {
		return t0.Add(time.Duration(clock.Load()) * time.Second)
	}))

	const calls = 20
	counts := make(chan int64, calls)
	var wg sync.WaitGroup
	for range calls {
		wg.Go(func() {
			n, err := st.IncrementRateLimit(ctx, "signin:1.2.3.4", time.Minute)
			assert.NoError(t, err)
			counts <- n
		})
	}
	wg.Wait()
	close(counts)
	seen := map[int64]bool{}
	for n := range counts {
		seen[n] = true
	}
	assert.Len(t, seen, calls, "concurrent attempts each get their own count")
	assert.True(t, seen[1] && seen[calls], "counts run 1..%d: %v", calls, seen)

	other, err := st.IncrementRateLimit(ctx, "signin:5.6.7.8", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, 1, other, "keys count independently")

	clock.Store(59)
	n, err := st.IncrementRateLimit(ctx, "signin:1.2.3.4", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, calls+1, n, "still inside the window")

	clock.Store(61)
	n, err = st.IncrementRateLimit(ctx, "signin:1.2.3.4", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "a passed window starts again")

	clock.Store(100) // 1.2.3.4's new window runs to 121; 5.6.7.8's ended at 60
	require.NoError(t, st.PurgeExpiredRateLimits(ctx))
	left, err := db.Count(ctx, &models.RateLimit{}, clause.Expression{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, left, "only passed windows are purged")
}

// auditLogContract records events and reads them back: every field
// round-trips, filters select, pages are newest first and don't overlap, and
// a purge removes what is older than its cutoff.
func auditLogContract(t *testing.T, st *store.Store) {
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	full := telemetry.AuditEvent{
		Type: "auth.signIn.failed", Outcome: telemetry.OutcomeFailure,
		ActorType:   telemetry.ActorAnonymous,
		SubjectType: models.UserTable, SubjectID: "user-1",
		SessionID: "sess-1", RequestID: "req-1", IPAddress: "203.0.113.7", UserAgent: "curl/8",
		Metadata:  behemoth.M{"code": "invalidCredentials", "email": "ada@example.com"},
		Timestamp: base,
	}
	require.NoError(t, st.RecordAuditEvent(ctx, full))
	// Five sign-ins by user-1, one minute apart, then one by user-2.
	for i := 1; i <= 5; i++ {
		require.NoError(t, st.RecordAuditEvent(ctx, telemetry.AuditEvent{
			Type: "auth.signIn.after", Outcome: telemetry.OutcomeSuccess, ActorType: telemetry.ActorUser, ActorID: "user-1",
			SubjectType: models.UserTable, SubjectID: "user-1", Timestamp: base.Add(time.Duration(i) * time.Minute),
		}))
	}
	require.NoError(t, st.RecordAuditEvent(ctx, telemetry.AuditEvent{
		Type: "auth.signIn.after", Outcome: telemetry.OutcomeSuccess, ActorType: telemetry.ActorUser, ActorID: "user-2",
		SubjectType: models.UserTable, SubjectID: "user-2", Timestamp: base.Add(10 * time.Minute),
	}))

	// Every field of the first event round-trips. Optional fields that were
	// empty read back empty.
	page, err := st.QueryAuditEvents(ctx, telemetry.AuditFilter{RequestID: "req-1"})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	got := page.Events[0]
	assert.NotEmpty(t, got.ID)
	assert.True(t, got.Timestamp.Equal(base), "timestamp: %v", got.Timestamp)
	got.ID, got.Timestamp, full.Timestamp = "", time.Time{}, time.Time{}
	assert.Equal(t, full, got)

	all, err := st.QueryAuditEvents(ctx, telemetry.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, all.Events, 7)
	assert.Empty(t, all.NextCursor)
	assert.Equal(t, "user-2", all.Events[0].ActorID, "newest first")
	assert.Equal(t, "auth.signIn.failed", all.Events[6].Type, "oldest last")
	assert.Empty(t, all.Events[0].RequestID)
	assert.Nil(t, all.Events[0].Metadata)

	count := func(f telemetry.AuditFilter) int {
		p, err := st.QueryAuditEvents(ctx, f)
		require.NoError(t, err)
		return len(p.Events)
	}
	assert.Equal(t, 5, count(telemetry.AuditFilter{ActorID: "user-1"}))
	assert.Equal(t, 6, count(telemetry.AuditFilter{SubjectType: models.UserTable, SubjectID: "user-1"}))
	assert.Equal(t, 1, count(telemetry.AuditFilter{Outcome: telemetry.OutcomeFailure}))
	assert.Equal(t, 6, count(telemetry.AuditFilter{Types: []string{"auth.signIn.after"}}))
	assert.Equal(t, 7, count(telemetry.AuditFilter{Types: []string{"auth.signIn.after", "auth.signIn.failed"}}))
	assert.Equal(t, 0, count(telemetry.AuditFilter{Types: []string{"auth.signOut.after"}}))
	assert.Equal(t, 1, count(telemetry.AuditFilter{SessionID: "sess-1"}))
	// From is inclusive, To exclusive: minutes 2, 3 and 4.
	assert.Equal(t, 3, count(telemetry.AuditFilter{From: base.Add(2 * time.Minute), To: base.Add(5 * time.Minute)}))

	// Paging: 7 events in pages of 3 are 3 + 3 + 1, without overlap, and in
	// the same order as the unpaged query.
	var paged []string
	filter := telemetry.AuditFilter{Limit: 3}
	for pages := 0; ; pages++ {
		require.Less(t, pages, 4, "paging does not end")
		p, err := st.QueryAuditEvents(ctx, filter)
		require.NoError(t, err)
		for _, e := range p.Events {
			paged = append(paged, e.ID)
		}
		if p.NextCursor == "" {
			break
		}
		require.Len(t, p.Events, 3)
		filter.Cursor = p.NextCursor
	}
	var unpaged []string
	for _, e := range all.Events {
		unpaged = append(unpaged, e.ID)
	}
	assert.Equal(t, unpaged, paged)

	// Purge removes what was recorded before the cutoff and keeps the rest.
	require.NoError(t, st.PurgeAuditEvents(ctx, base.Add(3*time.Minute)))
	assert.Equal(t, 4, count(telemetry.AuditFilter{}), "minutes 3, 4, 5 and 10 remain")
}
