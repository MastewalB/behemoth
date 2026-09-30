package migrations

import (
	"context"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/migration/plugins/postgres"
	"github.com/MastewalB/behemoth/migration/plugins/sqlite"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"
)

// TestSQLiteDriver runs the database-agnostic suite against SQLite.
func TestSQLiteDriver(t *testing.T) {
	db := openSQLite(t)
	RunDriverTests(t,
		func(r core.SchemaResolver) core.SchemaDriver { return sqlite.NewSQLiteDriver(db, r) },
		NewSQLiteTestManager(db),
	)
}

// TestPostgreSQLDriver runs the database-agnostic suite, then the
// Postgres-specific introspector tests, against one Postgres container.
func TestPostgreSQLDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a Postgres container")
	}
	ctx := context.Background()
	db, cleanup := testutils.SetupPostgresTestDB(t, ctx)
	t.Cleanup(cleanup)

	// The container's port opens before Postgres finishes its init restart.
	require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)

	tm := NewPostgresTestManager(db, nil) // the container is torn down by t.Cleanup, after every subtest
	RunDriverTests(t,
		func(r core.SchemaResolver) core.SchemaDriver { return postgres.NewPostgreSQLDriver(db, r) },
		tm,
	)
	runPostgresIntrospectorTests(t, db, tm)
}
