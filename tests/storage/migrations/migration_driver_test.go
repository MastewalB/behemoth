package migrations

import (
	"database/sql"
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	_ "github.com/MastewalB/behemoth/migration/plugins/sqlite"

	_ "github.com/mattn/go-sqlite3"
)

// TestSQLiteDriver runs tests against SQLite
func TestSQLiteDriver(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	config := map[string]any{
		"db": db,
	}

	driver, err := core.Open("sqlite", config)
	if err != nil {
		t.Fatal(err)
	}

	driverTestManager := NewSQLiteTestHelpers(db)

	RunDriverTests(t, driver, driverTestManager)
}
