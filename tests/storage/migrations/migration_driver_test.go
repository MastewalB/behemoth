package migrations

import (
	"context"
	"database/sql"
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	_ "github.com/MastewalB/behemoth/migration/plugins/postgres"
	_ "github.com/MastewalB/behemoth/migration/plugins/sqlite"
	"github.com/MastewalB/behemoth/tests/testutils"

	_ "github.com/mattn/go-sqlite3"

	_ "github.com/lib/pq"
)

// TestSQLiteDriver runs tests against SQLite
func TestSQLiteDriver(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	config := &core.Config{
		DB: db,
	}

	driver, err := core.Open("sqlite", config)
	if err != nil {
		t.Fatal(err)
	}

	driverTestManager := NewSQLiteTestHelpers(db)

	RunDriverTests(t, driver, driverTestManager)
}

func TestPostgreSQLDriver(t *testing.T) {
	ctx := context.Background()
	db, cleanup := testutils.SetupPostgresTestDB(t, ctx)

	config := &core.Config{
		DB: db,
	}

	driver, err := core.Open("postgres", config)
	if err != nil {
		t.Fatal(err)
	}

	driverTestManager := NewPostgresTestManager(db, cleanup)
	RunDriverTests(t, driver, driverTestManager)
}
