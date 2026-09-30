package migrations

import (
	"context"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/migration/plugins/sqlite"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLedgerEntrySerializable(t *testing.T) {
	applied := time.Date(2026, 9, 30, 12, 30, 45, 123456789, time.UTC)
	entry := &core.MigrationLedgerEntry{ID: "0001_init", AppliedAt: applied}

	m, err := entry.ToMap()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"id": "0001_init", "applied_at": applied}, m)

	var back core.MigrationLedgerEntry
	require.NoError(t, back.FromMap(m))
	assert.Equal(t, *entry, back)

	// Every column is present on a zero value: adapters build their column list from it.
	zero, err := (&core.MigrationLedgerEntry{}).ToMap()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"id", "applied_at"}, keys(zero))

	// Driver-dependent encodings.
	for name, raw := range map[string]any{
		"rfc3339":        "2026-09-30T12:30:45.123456789Z",
		"mattn sqlite":   "2026-09-30 12:30:45.123456789+00:00",
		"bytes":          []byte("2026-09-30T12:30:45.123456789Z"),
		"sqlite no zone": "2026-09-30 12:30:45.123456789",
	} {
		var e core.MigrationLedgerEntry
		require.NoError(t, e.FromMap(map[string]any{"id": []byte("0001_init"), "applied_at": raw}), name)
		assert.True(t, applied.Equal(e.AppliedAt), "%s: got %v", name, e.AppliedAt)
		assert.Equal(t, "0001_init", e.ID)
	}

	for name, bad := range map[string]map[string]any{
		"missing id":    {"applied_at": applied},
		"bad timestamp": {"id": "0001", "applied_at": "yesterday"},
		"no timestamp":  {"id": "0001"},
		"non-text id":   {"id": 42, "applied_at": applied},
	} {
		err := (&core.MigrationLedgerEntry{}).FromMap(bad)
		assert.True(t, behemotherr.IsCode(err, "invalid_ledger_entry"), "%s: %v", name, err)
	}

	assert.Equal(t, core.LedgerCanonicalName, entry.SchemaName())
	assert.Equal(t, "id", entry.PrimaryKeyName())
	assert.Equal(t, "0001_init", entry.PrimaryKeyField())
	assert.IsType(t, &core.MigrationLedgerEntry{}, entry.New())
}

func TestSchemaSnapshotSerializable(t *testing.T) {
	users := usersTable()
	users.Columns[0].Overrides = map[string]core.ColumnOverride{"postgres": {Default: "now()"}}
	snap := &core.SchemaSnapshot{Version: "0002_posts", Tables: map[string]core.TableSchema{"users": users, "posts": postsTable()}}

	m, err := snap.ToMap()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"id", "version", "tables"}, keys(m))
	assert.IsType(t, "", m["tables"], "tables is JSON text")

	var back core.SchemaSnapshot
	require.NoError(t, back.FromMap(m))
	assert.Equal(t, snap.Version, back.Version)
	require.Len(t, back.Tables, 2)
	assert.Equal(t, users.Columns[1], back.Tables["users"].Columns[1])
	assert.Equal(t, "now()", back.Tables["users"].Columns[0].Overrides["postgres"].Default)
	assert.Equal(t, "active", back.Tables["users"].Columns[3].Default)

	// []byte (e.g. JSONB via lib/pq) and already-decoded documents.
	var fromBytes core.SchemaSnapshot
	require.NoError(t, fromBytes.FromMap(map[string]any{"version": []byte("v"), "tables": []byte(m["tables"].(string))}))
	assert.Equal(t, back.Tables, fromBytes.Tables)
	var fromDoc core.SchemaSnapshot
	require.NoError(t, fromDoc.FromMap(map[string]any{"version": "v", "tables": map[string]any{
		"users": map[string]any{"Name": "users", "Columns": []any{map[string]any{"Name": "id", "Type": "int", "PrimaryKey": true}}},
	}}))
	assert.Equal(t, core.ColTypeInteger, fromDoc.Tables["users"].Columns[0].Type)

	// A zero value still lists every column, with "{}" rather than "null".
	zero, err := (&core.SchemaSnapshot{}).ToMap()
	require.NoError(t, err)
	assert.Equal(t, "{}", zero["tables"])
	var empty core.SchemaSnapshot
	require.NoError(t, empty.FromMap(map[string]any{"version": "", "tables": "null"}))
	assert.NotNil(t, empty.Tables)

	// Unreadable tables must never degrade to an empty (= greenfield) snapshot.
	for name, bad := range map[string]map[string]any{
		"missing tables": {"version": "v"},
		"corrupt json":   {"version": "v", "tables": "{not json"},
		"wrong shape":    {"version": "v", "tables": "[1, 2]"},
	} {
		err := (&core.SchemaSnapshot{}).FromMap(bad)
		assert.True(t, behemotherr.IsCode(err, "invalid_snapshot"), "%s: %v", name, err)
	}

	assert.Equal(t, core.SnapshotCanonicalName, snap.SchemaName())
	assert.Equal(t, "id", snap.PrimaryKeyName())
	assert.Equal(t, 1, snap.PrimaryKeyField())
	assert.IsType(t, &core.SchemaSnapshot{}, snap.New())
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// readBackThroughAdapter: the driver writes ledger/snapshot rows, and a
// behemoth.Database adapter reads them back through the models — the path
// MigrationRunner.Pending / LoadSnapshot take. Bookkeeping tables are given
// their canonical names here, since adapters address tables by SchemaName().
func readBackThroughAdapter(t *testing.T, driver core.SchemaDriver, database behemoth.Database) {
	ctx := context.Background()
	users := usersTable()
	for i, id := range []string{"0001_users", "0002_posts"} {
		tables := map[string]core.TableSchema{"users": users}
		up := []core.SchemaOperation{createTableOp(users)}
		if i == 1 {
			tables["posts"] = postsTable()
			up = []core.SchemaOperation{createTableOp(postsTable())}
		}
		require.NoError(t, driver.ApplyMigration(ctx, core.MigrationRequest{
			Migration:      core.Migration{ID: id, Up: up},
			LedgerEntry:    core.MigrationLedgerEntry{ID: id, AppliedAt: time.Now()},
			SnapshotUpdate: core.SchemaSnapshot{Version: id, Tables: tables},
			LedgerTable:    core.LedgerCanonicalName,
			SnapshotTable:  core.SnapshotCanonicalName,
		}))
	}

	found, err := database.FindMany(ctx, &core.MigrationLedgerEntry{}, clause.Expression{}, nil)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, f := range found {
		e := f.(*core.MigrationLedgerEntry)
		ids[e.ID] = true
		assert.WithinDuration(t, time.Now(), e.AppliedAt, time.Minute, e.ID)
	}
	assert.Equal(t, map[string]bool{"0001_users": true, "0002_posts": true}, ids)

	// Selected by primary key, as MigrationRunner.LoadSnapshot does.
	snapModel := &core.SchemaSnapshot{}
	one, err := database.FindOne(ctx, snapModel, clause.Expression{
		Logic:      clause.OpAnd,
		Conditions: []clause.Condition{{Field: snapModel.PrimaryKeyName(), Operator: clause.OpEqual, Value: snapModel.PrimaryKeyField()}},
	})
	require.NoError(t, err)
	snap := one.(*core.SchemaSnapshot)
	assert.Equal(t, "0002_posts", snap.Version)
	require.Len(t, snap.Tables, 2)
	assert.Equal(t, users.Columns, snap.Tables["users"].Columns)
}

func TestSQLiteLedgerReadsBackThroughAdapter(t *testing.T) {
	db := openSQLite(t)
	readBackThroughAdapter(t, sqlite.NewSQLiteDriver(db, nil), testutils.SetupSQLiteAdapter(t, db))
}
