package migrations

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationBackendPostgres drives postgres.MigrationBackend the way the
// behemoth command line does, through core.Generate, and then checks the two
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

	cfg := core.NewMigrationConfig(core.MigrationConfig{FolderPath: filepath.Join(t.TempDir(), "migrations")})
	resolver := core.NewSchemaResolver()
	resolver.Freeze(core.BuildSchemaResolverTable(registry, cfg))

	// Close is left uncalled: db belongs to the test.
	backend := postgres.MigrationBackend(db, resolver)
	declared := core.Declared{Schemas: registry}

	// Without Confirm the migration is reported and nothing is written.
	res, err := core.Generate(ctx, cfg, declared, backend, core.RunOptions{})
	require.NoError(t, err)
	require.Equal(t, core.StatusAwaitingConfirmation, res.Status)
	require.NoFileExists(t, filepath.Join(cfg.FolderPath, "0001_create_members.json"))

	res, err = core.Generate(ctx, cfg, declared, backend, core.RunOptions{Confirm: true})
	require.NoError(t, err)
	require.Equal(t, core.StatusGenerated, res.Status)
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
	res, err = core.Generate(ctx, cfg, declared, backend, core.RunOptions{Confirm: true})
	require.NoError(t, err)
	assert.Equal(t, core.StatusNoChanges, res.Status, res.Message)

	// The managed path's halves: what Driver records, DB reads back.
	runner := core.NewMigrationRunner(backend.DB, backend.Driver, cfg, nil)
	next := core.Migration{ID: "0002", Up: []core.SchemaOperation{
		addColumnOp(members.Name, schema.Column{Name: "nickname", Type: schema.ColTypeString, Length: 64, Nullable: true}),
	}}
	pending, err := runner.Pending(ctx, []core.Migration{next})
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, runner.Apply(ctx, pending))

	pending, err = runner.Pending(ctx, []core.Migration{next})
	require.NoError(t, err)
	assert.Empty(t, pending, "the adapter reads the ledger the driver wrote")
	snapshot, err := runner.LoadSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, next.ID, snapshot.Version)
}
