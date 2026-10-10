// Package auth holds the application's behemoth setup: what it declares and
// how it reaches its database.
//
// The server (../main.go) and the behemoth command line both start from
// Prepare and OpenDB, so they always see the same plugins, the same schema
// and therefore the same SchemaResolver. Nothing here exists for the command
// line alone except MigrationBackend, which is a few lines.
//
// The file is named behemoth.go because that is how the behemoth launcher
// finds this package.
package auth

import (
	"context"
	"database/sql"
	"os"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	_ "github.com/lib/pq"
)

// Prepare returns the application's declarations: its plugins, behemoth's
// own tables and the application's schema (schema.go). It opens no
// connection, so the command line can call it before it has a database.
func Prepare() (*bmth.PreparedApp, error) {
	plugins := []types.Plugin{emailpassword.New(emailpassword.Options{})}
	return bmth.Prepare(plugins, bmth.PrepareConfig{
		Migration: core.MigrationConfig{
			FolderPath: "migrations",
			// Path is left empty: PathGenerateOnly. behemoth writes the
			// migration files, and the application applies them with its
			// own tool.
		},
		Schema: declareSchema,
	})
}

// MigrationBackend opens the database the command line compares the
// declarations with. The backend takes the resolver Prepare built, the one
// the server gives its adapter.
func MigrationBackend(ctx context.Context, app *bmth.PreparedApp) (core.Backend, error) {
	db, err := OpenDB(ctx)
	if err != nil {
		return core.Backend{}, err
	}
	return postgres.MigrationBackend(db, app.Resolver), nil
}

// OpenDB opens the application's PostgreSQL database. DATABASE_URL names
// it, with a local default.
func OpenDB(ctx context.Context) (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
