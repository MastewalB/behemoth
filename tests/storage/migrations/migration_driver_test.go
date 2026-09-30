package migrations

import (
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/migration/plugins/sqlite"
)

// TestSQLiteDriver runs the database-agnostic suite against SQLite.
func TestSQLiteDriver(t *testing.T) {
	db := openSQLite(t)
	RunDriverTests(t,
		func(r core.SchemaResolver) core.SchemaDriver { return sqlite.NewSQLiteDriver(db, r) },
		NewSQLiteTestManager(db),
	)
}

// TestPostgreSQLDriver runs the same suite against Postgres once the
// postgres plugin is on par with core.SchemaDriver. Intended wiring:
//
//	db, cleanup := testutils.SetupPostgresTestDB(t, ctx)
//	RunDriverTests(t,
//		func(r core.SchemaResolver) core.SchemaDriver { return postgres.NewPostgreSQLDriver(db, r) },
//		NewPostgresTestManager(db, cleanup),
//	)
func TestPostgreSQLDriver(t *testing.T) {
	t.Skip("postgres plugin has no constructor and does not create its ledger/snapshot tables yet")
}
