package testutils

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/migration"
	"github.com/go-behemoth/behemoth/schema"
	"github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/stretchr/testify/require"
)

// MigrateApp creates in the SQLite database db every table prepared
// declares, core's and the plugins', in one migration, as an application's
// first migration does. The tables are the plugins' own declarations, so a
// test of a plugin with tables of its own needs no copy of them in SQL.
func MigrateApp(t *testing.T, db *sql.DB, prepared *engine.PreparedApp) {
	t.Helper()
	m := migration.Migration{ID: "0001"}
	snapshot := migration.SchemaSnapshot{Version: m.ID, Tables: map[string]schema.Table{}}
	tables := prepared.Schemas.All()
	for _, table := range tables {
		m.Up = append(m.Up, migration.SchemaOperation{ID: "create_" + table.Name, Kind: migration.OpCreateTable, Table: table.Name, NewTable: &table})
		for _, idx := range table.Indexes { // CreateTable doesn't: a generated migration adds them as their own operations
			m.Up = append(m.Up, migration.SchemaOperation{ID: "add_" + idx.Name, Kind: migration.OpAddIndex, Table: table.Name, Index: &idx})
		}
		snapshot.Tables[table.Name] = table
	}
	for _, table := range tables { // after every table exists
		for _, fk := range table.ForeignKeys {
			m.Up = append(m.Up, migration.SchemaOperation{ID: "add_" + fk.Name, Kind: migration.OpAddForeignKey, Table: table.Name, ForeignKey: &fk})
		}
	}
	require.NoError(t, sqlite.NewSQLiteDriver(db, prepared.Resolver).ApplyMigration(context.Background(), migration.MigrationRequest{
		Migration:      m,
		LedgerEntry:    migration.MigrationLedgerEntry{ID: m.ID, AppliedAt: time.Now()},
		SnapshotUpdate: snapshot,
		LedgerTable:    "behemoth_auth_schema",
		SnapshotTable:  "behemoth_auth_schema_snapshot",
	}))
}
