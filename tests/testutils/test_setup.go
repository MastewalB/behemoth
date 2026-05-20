package testutils

import (
	"database/sql"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
)

func SetupTestDB(t *testing.T, schema *string) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	if schema != nil {
		_, err = db.Exec(*schema)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	}
	return db
}

func SetupSQLiteAdapter(t *testing.T, db *sql.DB) *adapters.SQLiteAdapter {
	adapter := &adapters.SQLiteAdapter{DB: db}
	return adapter
}

func SetupInternalAdapter(t *testing.T, db behemoth.Database) *adapters.InternalAdapter {
	return &adapters.InternalAdapter{
		DB: db,
	}
}