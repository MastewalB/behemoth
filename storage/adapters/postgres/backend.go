package postgres

import (
	"database/sql"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/migration/core"
)

// MigrationBackend returns the migration backend of db for core.Generate, core.Migrate and the
// cli package: one PostgreSQLDriver as introspector, renderer and schema
// driver, and a PostgresAdapter over the same connection, through which the
// managed path reads its ledger.
//
// Pass the resolver Prepare built (PreparedApp.Resolver), the one the
// application's own adapter gets, so that migrations and queries agree on
// physical table and column names.
//
// The backend's Close closes db. Don't call it when db is shared with code
// that outlives the migration run.
func MigrationBackend(db *sql.DB, resolver behemoth.SchemaResolver) core.Backend {
	driver := NewPostgreSQLDriver(db, resolver)
	return core.Backend{
		Introspector: driver,
		Renderer:     driver,
		Driver:       driver,
		DB:           NewPostgresAdapter(db, resolver),
		Close:        db.Close,
	}
}
