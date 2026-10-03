package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/models"
	pgAdapter "github.com/MastewalB/behemoth/storage/adapters/postgres"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Columns two plugins contribute to the users table. Plan is stored under a
// different physical name, to check reads map it back.
var (
	twoFactorEnabled = schema.Field[bool]{Table: models.UserTable, Name: "two_factor_enabled"}
	plan             = schema.Field[string]{Table: models.UserTable, Name: "plan"}
)

// extendedUsers is the users table as core declares it, extended by two
// plugins, frozen into a registry and its resolver.
func extendedUsers(t *testing.T) (schema.Table, behemoth.SchemaResolver) {
	t.Helper()
	reg := schema.NewRegistry()
	require.NoError(t, reg.Declare(&models.User{}, models.UserTableSchema()))
	tfa := twoFactorEnabled.Contribution(schema.Column{Type: schema.ColTypeBoolean, Default: false})
	tfa.Owner = "two-factor"
	require.NoError(t, reg.ExtendColumn(tfa))
	p := plan.Contribution(schema.Column{Type: schema.ColTypeString, Length: 32, Nullable: true, PhysicalName: "subscription_plan"})
	p.Owner = "billing"
	require.NoError(t, reg.ExtendColumn(p))
	require.NoError(t, reg.Freeze())

	resolver := core.NewSchemaResolver()
	resolver.Freeze(core.BuildSchemaResolverTable(reg, core.NewMigrationConfig(core.MigrationConfig{})))
	users, ok := reg.Lookup(models.UserTable)
	require.True(t, ok)
	return users, resolver
}

// createTable creates table through the database's own migration driver, as
// a generated migration would.
func createTable(t *testing.T, driver core.SchemaDriver, table schema.Table) {
	t.Helper()
	m := core.Migration{ID: "0001", Up: []core.SchemaOperation{{ID: "create_" + table.Name, Kind: core.OpCreateTable, Table: table.Name, NewTable: &table}}}
	require.NoError(t, driver.ApplyMigration(context.Background(), core.MigrationRequest{
		Migration:      m,
		LedgerEntry:    core.MigrationLedgerEntry{ID: m.ID, AppliedAt: time.Now()},
		SnapshotUpdate: core.SchemaSnapshot{Version: m.ID, Tables: map[string]schema.Table{table.Name: table}},
		LedgerTable:    "behemoth_auth_schema",
		SnapshotTable:  "behemoth_auth_schema_snapshot",
	}))
}

func TestContributedColumnsReachTheModel(t *testing.T) {
	users, resolver := extendedUsers(t)

	backends := map[string]func(t *testing.T) behemoth.Database{
		"sqlite": func(t *testing.T) behemoth.Database {
			db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "ext.db"))
			require.NoError(t, err)
			t.Cleanup(func() { db.Close() })
			createTable(t, sqliteAdapter.NewSQLiteDriver(db, resolver), users)
			return sqliteAdapter.NewSQLiteAdapter(db, resolver)
		},
		"postgres": func(t *testing.T) behemoth.Database {
			if testing.Short() {
				t.Skip("starts a Postgres container")
			}
			ctx := context.Background()
			db, cleanup := testutils.SetupPostgresTestDB(t, ctx)
			t.Cleanup(cleanup)
			require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)
			createTable(t, pgAdapter.NewPostgreSQLDriver(db, resolver), users)
			return pgAdapter.NewPostgresAdapter(db, resolver)
		},
	}

	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db := open(t)
			s := store.New(db, store.WithSchema(resolver))

			u := &models.User{Email: "ada@example.com"}
			require.NoError(t, plan.Set(u, "pro"))
			require.NoError(t, s.CreateUser(ctx, u))

			found, err := s.FindUserByID(ctx, u.ID)
			require.NoError(t, err)
			p, ok, err := plan.Get(found)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, "pro", p, "a contributed column is written and read back (physical name mapped)")
			on, ok, err := twoFactorEnabled.Get(found)
			require.NoError(t, err)
			assert.True(t, ok, "an unset contributed column is still read — with its default")
			assert.False(t, on)

			changes, err := twoFactorEnabled.Update(true)
			require.NoError(t, err)
			updated, err := s.UpdateUser(ctx, u.ID, changes)
			require.NoError(t, err)
			on, _, err = twoFactorEnabled.Get(updated)
			require.NoError(t, err)
			assert.True(t, on, "a contributed column can be updated, and converts from the driver's representation")

			_, err = s.UpdateUser(ctx, u.ID, behemoth.M{"two_factor_enabld": true})
			assert.True(t, behemotherr.IsValidationError(err), "a typo is still rejected: %v", err)

			many, err := db.FindMany(ctx, &models.User{}, clause.Expression{}, nil)
			require.NoError(t, err)
			require.Len(t, many, 1)
			p, _, err = plan.Get(many[0].(*models.User))
			require.NoError(t, err)
			assert.Equal(t, "pro", p, "FindMany reads contributed columns too")
		})
	}
}

// A data hook can set a contributed column on create — how a plugin fills
// its own column — while a made-up column is still rejected.
func TestHooksCanSetContributedColumns(t *testing.T) {
	ctx := context.Background()
	users, resolver := extendedUsers(t)
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "hooks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	createTable(t, sqliteAdapter.NewSQLiteDriver(db, resolver), users)
	adapter := sqliteAdapter.NewSQLiteAdapter(db, resolver)

	h := &recordingHooks{rewrite: behemoth.M{"two_factor_enabled": true}}
	s := store.New(adapter, store.WithSchema(resolver), store.WithHooks(h))
	u := &models.User{Email: "hook@example.com"}
	require.NoError(t, s.CreateUser(ctx, u))
	on, _, err := twoFactorEnabled.Get(u)
	require.NoError(t, err)
	assert.True(t, on, "the hook's contributed value reached the model")

	h.rewrite = behemoth.M{"made_up": 1}
	err = s.CreateUser(ctx, &models.User{Email: "other@example.com"})
	assert.True(t, behemotherr.IsValidationError(err), "%v", err)

	// Without the schema, the store only knows the model's own columns.
	plain := store.New(adapter)
	changes, _ := plan.Update("free")
	_, err = plain.UpdateUser(ctx, u.ID, changes)
	assert.True(t, behemotherr.IsValidationError(err), "without WithSchema a contributed column is unknown: %v", err)
}
