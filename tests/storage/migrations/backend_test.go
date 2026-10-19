package migrations

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/MastewalB/behemoth/migration"
	"github.com/MastewalB/behemoth/schema"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationBackendPostgres drives postgres.MigrationBackend the way the
// behemoth command line does, through migration.Generate, and then checks the two
// halves of it that only the managed path uses.
//
// The table has a physical name of its own and a renamed column. Rendering,
// introspection and the ledger all go through the resolver the backend was
// given, so a backend that dropped it would fail here.
func migrationBackendPostgres(t *testing.T, db *sql.DB) {
	ctx := context.Background()

	members := schema.Table{
		Name: "members", PhysicalName: "app_members",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255},
		},
	}
	registry := schema.NewRegistry()
	require.NoError(t, registry.Declare(tableModel{name: members.Name}, members))
	require.NoError(t, registry.Freeze())

	cfg := migration.NewMigrationConfig(migration.MigrationConfig{FolderPath: filepath.Join(t.TempDir(), "migrations")})
	resolver := migration.NewSchemaResolver()
	resolver.Freeze(migration.BuildSchemaResolverTable(registry, cfg))

	// Close is left uncalled: db belongs to the test.
	backend := postgres.MigrationBackend(db, resolver)
	declared := migration.Declared{Schemas: registry}

	// Without Confirm the migration is reported and nothing is written.
	res, err := migration.Generate(ctx, cfg, declared, backend, migration.RunOptions{})
	require.NoError(t, err)
	require.Equal(t, migration.StatusAwaitingConfirmation, res.Status)
	require.NoFileExists(t, filepath.Join(cfg.FolderPath, "0001_create_members.json"))

	res, err = migration.Generate(ctx, cfg, declared, backend, migration.RunOptions{Confirm: true})
	require.NoError(t, err)
	require.Equal(t, migration.StatusGenerated, res.Status)
	require.FileExists(t, filepath.Join(cfg.FolderPath, "0001_create_members.json"))

	script, err := os.ReadFile(filepath.Join(cfg.FolderPath, "0001_create_members.sql"))
	require.NoError(t, err, "the backend's renderer writes the script")
	assert.Contains(t, string(script), `"app_members"`)
	assert.Contains(t, string(script), `"email_address"`)

	// The application's own tool applies the script. Here that is one Exec.
	_, err = db.ExecContext(ctx, string(script))
	require.NoError(t, err)

	// The introspector reads the physical names back as the declared ones,
	// so the database now matches.
	res, err = migration.Generate(ctx, cfg, declared, backend, migration.RunOptions{Confirm: true})
	require.NoError(t, err)
	assert.Equal(t, migration.StatusNoChanges, res.Status, res.Message)

	// The managed path's halves: what Driver records, DB reads back.
	runner := migration.NewMigrationRunner(backend.DB, backend.Driver, cfg, nil)
	next := migration.Migration{ID: "0002", Up: []migration.SchemaOperation{
		addColumnOp(members.Name, schema.Column{Name: "nickname", Type: schema.ColTypeString, Length: 64, Nullable: true}),
	}}
	pending, err := runner.Pending(ctx, []migration.Migration{next})
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, runner.Apply(ctx, pending))

	pending, err = runner.Pending(ctx, []migration.Migration{next})
	require.NoError(t, err)
	assert.Empty(t, pending, "the adapter reads the ledger the driver wrote")
	snapshot, err := runner.LoadSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, next.ID, snapshot.Version)
}
