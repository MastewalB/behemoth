package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PostgresTestManager implements DriverTestManager for Postgres, scoped to
// the connection's current schema.
type PostgresTestManager struct {
	db          *sql.DB
	cleanupFunc func()
}

func NewPostgresTestManager(db *sql.DB, cleanupFunc func()) *PostgresTestManager {
	return &PostgresTestManager{db: db, cleanupFunc: cleanupFunc}
}

func (m *PostgresTestManager) TableExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	err := m.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_name = $1 AND table_type = 'BASE TABLE'
	)`, table).Scan(&exists)
	return exists, err
}

func (m *PostgresTestManager) Columns(ctx context.Context, table string) ([]ColumnInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT c.column_name, c.is_nullable = 'YES', c.column_default IS NOT NULL OR c.is_identity = 'YES',
			EXISTS (
				SELECT 1 FROM information_schema.table_constraints tc
				JOIN information_schema.key_column_usage k
					ON k.constraint_name = tc.constraint_name AND k.table_schema = tc.table_schema
				WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = c.table_schema
					AND tc.table_name = c.table_name AND k.column_name = c.column_name
			)
		FROM information_schema.columns c
		WHERE c.table_schema = current_schema() AND c.table_name = $1
		ORDER BY c.ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		if err := rows.Scan(&c.Name, &c.Nullable, &c.HasDefault, &c.PrimaryKey); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (m *PostgresTestManager) Indexes(ctx context.Context, table string) ([]IndexInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT i.relname, ix.indisunique, a.attname
		FROM pg_class t
		JOIN pg_index ix ON ix.indrelid = t.oid
		JOIN pg_class i ON i.oid = ix.indexrelid
		JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE t.relname = $1 AND t.relnamespace = current_schema()::regnamespace
		ORDER BY i.relname, k.ord`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IndexInfo
	for rows.Next() {
		var name, col string
		var unique bool
		if err := rows.Scan(&name, &unique, &col); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].Name == name {
			out[n-1].Columns = append(out[n-1].Columns, col)
			continue
		}
		out = append(out, IndexInfo{Name: name, Unique: unique, Columns: []string{col}})
	}
	return out, rows.Err()
}

func (m *PostgresTestManager) ForeignKeys(ctx context.Context, table string) ([]ForeignKeyInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT c.conname, c.confdeltype::text, rt.relname, a.attname, ra.attname
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN pg_class rt ON rt.oid = c.confrelid
		JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY AS k(col, refcol, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.col
		JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.refcol
		WHERE c.contype = 'f' AND t.relname = $1 AND t.relnamespace = current_schema()::regnamespace
		ORDER BY c.conname, k.ord`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ForeignKeyInfo
	for rows.Next() {
		var name, action, refTable, col, refCol string
		if err := rows.Scan(&name, &action, &refTable, &col, &refCol); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].Name == name {
			out[n-1].Columns = append(out[n-1].Columns, col)
			out[n-1].RefColumns = append(out[n-1].RefColumns, refCol)
			continue
		}
		out = append(out, ForeignKeyInfo{
			Name: name, Columns: []string{col}, RefTable: refTable, RefColumns: []string{refCol},
			OnDelete: pgFKAction(action),
		})
	}
	return out, rows.Err()
}

// pgFKAction maps pg_constraint.confdeltype codes.
func pgFKAction(code string) schema.ForeignKeyAction {
	switch code {
	case "c":
		return schema.FKCascade
	case "n":
		return schema.FKSetNull
	case "r":
		return schema.FKRestrict
	default:
		return schema.ForeignKeyAction("no_action")
	}
}

func (m *PostgresTestManager) Insert(ctx context.Context, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		quoted[i], marks[i], args[i] = quote(c), fmt.Sprintf("$%d", i+1), row[c]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", quote(table), strings.Join(quoted, ", "), strings.Join(marks, ", "))
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}

func (m *PostgresTestManager) Delete(ctx context.Context, table, column string, value any) error {
	_, err := m.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s = $1", quote(table), quote(column)), value)
	return err
}

func (m *PostgresTestManager) Rows(ctx context.Context, table, orderBy string) ([]map[string]any, error) {
	return scanRows(m.db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s ORDER BY %s", quote(table), quote(orderBy))))
}

func (m *PostgresTestManager) RowCount(ctx context.Context, table string) (int64, error) {
	var n int64
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quote(table)).Scan(&n)
	return n, err
}

func (m *PostgresTestManager) LedgerIDs(ctx context.Context, ledgerTable string) ([]string, error) {
	if exists, err := m.TableExists(ctx, ledgerTable); err != nil || !exists {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT id FROM "+quote(ledgerTable)+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (m *PostgresTestManager) Snapshot(ctx context.Context, snapshotTable string) (core.SchemaSnapshot, bool, error) {
	if exists, err := m.TableExists(ctx, snapshotTable); err != nil || !exists {
		return core.SchemaSnapshot{}, false, err
	}
	var snap core.SchemaSnapshot
	var tables []byte
	err := m.db.QueryRowContext(ctx, "SELECT version, tables FROM "+quote(snapshotTable)+" WHERE id = 1").Scan(&snap.Version, &tables)
	if errors.Is(err, sql.ErrNoRows) {
		return core.SchemaSnapshot{}, false, nil
	}
	if err != nil {
		return core.SchemaSnapshot{}, false, err
	}
	if err := json.Unmarshal(tables, &snap.Tables); err != nil {
		return core.SchemaSnapshot{}, false, err
	}
	return snap, true, nil
}

func (m *PostgresTestManager) DropAllTables(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	return err
}

func (m *PostgresTestManager) CleanupDatabase(ctx context.Context) {
	if m.cleanupFunc != nil {
		m.cleanupFunc()
	}
}

// ---- Postgres-specific: core.SchemaIntrospector ----

// tableModel is the minimal behemoth.Model the schema.Registry needs to accept
// a declaration; only SchemaName is ever called.
type tableModel struct {
	behemoth.Model
	name string
}

func (m tableModel) SchemaName() string { return m.name }

// allTypesTable exercises every canonical type the driver renders distinctly,
// plus the column features the introspector has to map back.
func allTypesTable() schema.Table {
	return schema.Table{
		Name: "all_types",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeBigInt, PrimaryKey: true, AutoInc: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40, Unique: true},
			{Name: "t", Type: schema.ColTypeText, Nullable: true, Default: "it's"},
			{Name: "i", Type: schema.ColTypeInteger, Default: 7},
			{Name: "r", Type: schema.ColTypeReal, Nullable: true},
			{Name: "n", Type: schema.ColTypeNumeric, Nullable: true},
			{Name: "b", Type: schema.ColTypeBoolean, Default: true},
			{Name: "dt", Type: schema.ColTypeDateTime, Nullable: true},
			{Name: "ts", Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{postgres.DriverName: {Default: "now()"}}},
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			{Name: "j", Type: schema.ColTypeJson, Nullable: true},
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},
			{Name: "owner_id", Type: schema.ColTypeInteger, Nullable: true},
		},
		Indexes: []schema.Index{
			{Name: "idx_all_types_i_b", Columns: []string{"i", "b"}},
			{Name: "uq_all_types_r_n", Columns: []string{"r", "n"}, Unique: true},
		},
		ForeignKeys: []schema.ForeignKey{
			{Name: "fk_all_types_owner", Columns: []string{"owner_id"}, RefTable: "users", RefColumns: []string{"id"}, OnDelete: schema.FKSetNull},
		},
	}
}

func runPostgresIntrospectorTests(t *testing.T, db *sql.DB, tm *PostgresTestManager) {
	ctx := context.Background()
	driver := postgres.NewPostgreSQLDriver(db, nil)

	// setup creates users + all_types through the driver exactly as a
	// generated migration would: tables, then indexes and FKs as own operations.
	setup := func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		var ops []core.SchemaOperation
		for _, table := range []schema.Table{usersTable(), allTypesTable()} {
			bare := table
			bare.Indexes, bare.ForeignKeys = nil, nil
			ops = append(ops, createTableOp(bare))
			for _, idx := range table.Indexes {
				ops = append(ops, addIndexOp(table.Name, idx))
			}
			for _, fk := range table.ForeignKeys {
				ops = append(ops, addForeignKeyOp(table.Name, fk))
			}
		}
		require.NoError(t, driver.ApplyMigration(ctx, request(core.Migration{ID: "0001_test", Up: ops}, nil)))
	}

	t.Run("IntrospectRoundTripsDeclaredSchema", func(t *testing.T) {
		setup(t)
		declared := allTypesTable()
		live, err := driver.Introspect(ctx, "all_types")
		require.NoError(t, err)
		require.True(t, live.Exists)
		assert.Equal(t, core.ObjectTable, live.Kind)
		assert.Empty(t, live.Ambiguities)

		require.Len(t, live.Schema.Columns, len(declared.Columns))
		for i, want := range declared.Columns {
			got := live.Schema.Columns[i]
			assert.Equal(t, want.Name, got.Name)
			assert.Equal(t, want.Type, got.Type, want.Name)
			assert.Equal(t, want.Nullable, got.Nullable, want.Name)
			assert.Equal(t, want.PrimaryKey, got.PrimaryKey, want.Name)
			assert.Equal(t, want.Unique, got.Unique, want.Name)
			assert.Equal(t, want.AutoInc, got.AutoInc, want.Name)
			if want.Type == schema.ColTypeString {
				assert.Equal(t, want.Length, got.Length, want.Name)
			}
		}
		byName := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			byName[c.Name] = c
		}
		assert.Equal(t, "it's", byName["t"].Default, "quoted literal with an escaped quote")
		assert.Equal(t, int64(7), byName["i"].Default)
		assert.Equal(t, true, byName["b"].Default)
		assert.Equal(t, "now()", byName["ts"].Overrides[postgres.DriverName].Default, "expression default is kept verbatim")
		assert.Nil(t, byName["ts"].Default)

		assert.ElementsMatch(t, declared.Indexes, live.Schema.Indexes, "constraint-backing indexes are excluded")
		assert.Equal(t, declared.ForeignKeys, live.Schema.ForeignKeys)
	})

	// The real contract: what the driver creates, the introspector reads back
	// with no divergence, so a generate-only run right after produces nothing.
	t.Run("NoDivergenceAgainstDeclaredRegistry", func(t *testing.T) {
		setup(t)
		registry := schema.NewRegistry()
		for _, table := range []schema.Table{usersTable(), allTypesTable()} {
			require.NoError(t, registry.Declare(tableModel{name: table.Name}, table))
		}
		require.NoError(t, registry.Freeze())

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		require.NoError(t, core.RejectAmbiguousTypes(report))
		require.Len(t, report.Tables, 2)
		for name, ti := range report.Tables {
			assert.True(t, ti.ExistsLive, name)
			assert.Empty(t, ti.Renames, name)
			for _, f := range ti.Columns {
				assert.Equal(t, core.ColMatch, f.Kind, "%s.%s", name, f.Name)
			}
			for _, f := range ti.Indexes {
				assert.Equal(t, core.IdxMatch, f.Kind, "%s index %s", name, f.Name)
			}
			for _, f := range ti.ForeignKeys {
				assert.Equal(t, core.FKMatch, f.Kind, "%s fk %s", name, f.Name)
			}
		}
	})

	// Declarations the DDL can't preserve exactly — each reads back changed —
	// still match once normalized (core.ColumnNormalizer).
	t.Run("NormalizedDeclarationsMatch", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		normalized := schema.Table{Name: "normalized", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, Nullable: true, Unique: true}, // reads back NOT NULL, not UNIQUE
			{Name: "s", Type: schema.ColTypeString},                                                   // VARCHAR(255)
			{Name: "bl", Type: schema.ColTypeBlob, Nullable: true},                                    // BYTEA, reads back as bytes
			{Name: "t", Type: schema.ColTypeText, Length: 10, Nullable: true},                         // TEXT has no length
			{Name: "o", Type: schema.ColTypeString, Length: 40, Nullable: true, // override: TEXT
				Overrides: map[string]schema.ColumnOverride{postgres.DriverName: {Type: schema.ColTypeText}}},
		}}
		require.NoError(t, driver.ApplyMigration(ctx, request(core.Migration{ID: "0001_test", Up: []core.SchemaOperation{createTableOp(normalized)}}, nil)))
		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "normalized"}, normalized))
		require.NoError(t, registry.Freeze())

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		require.NoError(t, core.RejectAmbiguousTypes(report))
		require.Len(t, report.Tables["normalized"].Columns, len(normalized.Columns))
		for _, f := range report.Tables["normalized"].Columns {
			assert.Equal(t, core.ColMatch, f.Kind, f.Name)
		}

		// Normalization is what makes them match: hidden from the type
		// assertion, every one of these columns differs.
		unnormalized := struct{ core.SchemaIntrospector }{driver}
		report, err = core.RunIntrospection(ctx, registry, unnormalized, true)
		require.NoError(t, err)
		for _, f := range report.Tables["normalized"].Columns {
			assert.Equal(t, core.ColDiffers, f.Kind, "%s should differ without normalization", f.Name)
		}
	})

	// Normalization only absorbs what the DDL itself changes; a real change
	// between the declaration and the live column is still a change.
	t.Run("RealChangesStillDiffer", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `CREATE TABLE changed (id INTEGER PRIMARY KEY, s VARCHAR(255) NOT NULL, n TEXT NOT NULL, b BYTEA NOT NULL)`)
		require.NoError(t, err)
		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "changed"}, schema.Table{Name: "changed", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40},   // live is 255
			{Name: "n", Type: schema.ColTypeInteger},              // live is text
			{Name: "b", Type: schema.ColTypeBlob, Nullable: true}, // same type after normalization, but nullability changed
		}}))
		require.NoError(t, registry.Freeze())

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		kinds := map[string]core.ColumnDivergenceKind{}
		for _, f := range report.Tables["changed"].Columns {
			kinds[f.Name] = f.Kind
		}
		assert.Equal(t, map[string]core.ColumnDivergenceKind{
			"id": core.ColMatch, "s": core.ColDiffers, "n": core.ColDiffers, "b": core.ColDiffers,
		}, kinds)
	})

	t.Run("CompositePrimaryKeyAndSerial", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `
			CREATE TABLE legacy (a INTEGER, b INTEGER, seq SERIAL, note VARCHAR, PRIMARY KEY (a, b));
			CREATE INDEX idx_legacy_expr ON legacy (lower(note))`)
		require.NoError(t, err)

		live, err := driver.Introspect(ctx, "legacy")
		require.NoError(t, err)
		assert.Empty(t, live.Ambiguities)
		cols := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			cols[c.Name] = c
		}
		assert.True(t, cols["a"].PrimaryKey)
		assert.True(t, cols["b"].PrimaryKey)
		assert.True(t, cols["seq"].AutoInc, "serial maps to AutoInc")
		assert.Nil(t, cols["seq"].Overrides)
		assert.Equal(t, schema.ColTypeText, cols["note"].Type, "unbounded VARCHAR is TEXT")
		assert.Empty(t, live.Schema.Indexes, "expression indexes can't be represented")
	})

	t.Run("UnknownTypeIsAmbiguous", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `CREATE TYPE mood AS ENUM ('ok', 'meh'); CREATE TABLE feelings (id INTEGER PRIMARY KEY, m mood, p POINT)`)
		require.NoError(t, err)

		live, err := driver.Introspect(ctx, "feelings")
		require.NoError(t, err)
		require.Len(t, live.Ambiguities, 2)
		assert.Equal(t, "m", live.Ambiguities[0].Column)
		assert.Contains(t, live.Ambiguities[0].Reason, `"mood"`)
		assert.Equal(t, "p", live.Ambiguities[1].Column)
	})

	// An unmappable live column must stop generation — whether it's declared,
	// an undeclared column the baseline would record, or one that a guessed
	// type would otherwise pair up as a rename.
	t.Run("UnmappableColumnsAreRejected", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `CREATE TYPE mood AS ENUM ('ok', 'meh');
			CREATE TABLE feelings (id INTEGER PRIMARY KEY, m mood, p POINT, note TEXT)`)
		require.NoError(t, err)

		introspect := func(t *testing.T, cols []schema.Column, trackExtra bool) (*core.IntrospectionReport, error) {
			registry := schema.NewRegistry()
			require.NoError(t, registry.Declare(tableModel{name: "feelings"}, schema.Table{Name: "feelings", Columns: cols}))
			report, err := core.RunIntrospection(ctx, registry, driver, trackExtra)
			require.NoError(t, err)
			return report, core.RejectAmbiguousTypes(report)
		}
		id := schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true}
		note := schema.Column{Name: "note", Type: schema.ColTypeText, Nullable: true}

		// m is declared (as text), p is not.
		_, err = introspect(t, []schema.Column{id, {Name: "m", Type: schema.ColTypeText, Nullable: true}, note}, true)
		require.Error(t, err)
		assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationUnmappableColumnType))
		assert.Contains(t, err.Error(), "feelings.m")
		assert.Contains(t, err.Error(), "feelings.p", "undeclared column recorded by a baseline is rejected too")

		_, err = introspect(t, []schema.Column{id, {Name: "m", Type: schema.ColTypeText, Nullable: true}, note}, false)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "feelings.p", "undeclared columns are ignored when extras aren't tracked")

		// A declared-only text column would pair with m's guessed text type as a rename.
		report, err := introspect(t, []schema.Column{id, {Name: "feeling", Type: schema.ColTypeText, Nullable: true}, note}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "feelings.m")
		assert.Empty(t, report.Tables["feelings"].Renames, "an unmappable column is never a rename candidate")

		// Only mappable columns: nothing to reject.
		_, err = introspect(t, []schema.Column{id, note}, false)
		assert.NoError(t, err)
	})

	// Tables and columns whose physical names differ from their canonical ones
	// must still diff as matches: RunIntrospection maps live (physical) names
	// back through the declared PhysicalName fields — the same fields the
	// DefaultSchemaResolver that created them was built from.
	t.Run("PhysicalNamesMapBackToCanonical", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))

		users := schema.Table{
			Name: "users", PhysicalName: "app_users",
			Columns: []schema.Column{
				{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
				{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true},
				{Name: "name", Type: schema.ColTypeText, Nullable: true},
			},
			Indexes: []schema.Index{{Name: "idx_users_email_name", Columns: []string{"email", "name"}}},
		}
		posts := schema.Table{
			Name: "posts", PhysicalName: "app_posts",
			Columns: []schema.Column{
				{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
				{Name: "user_id", PhysicalName: "author_id", Type: schema.ColTypeInteger, Nullable: true},
			},
			ForeignKeys: []schema.ForeignKey{{Name: "fk_posts_user", Columns: []string{"user_id"}, RefTable: "users", RefColumns: []string{"id"}, OnDelete: schema.FKCascade}},
		}

		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "users"}, users))
		require.NoError(t, registry.Declare(tableModel{name: "posts"}, posts))
		require.NoError(t, registry.Freeze())
		resolver := core.NewSchemaResolver()
		resolver.Freeze(core.BuildSchemaResolverTable(registry, core.NewMigrationConfig(core.MigrationConfig{})))
		mapped := postgres.NewPostgreSQLDriver(db, resolver)

		bareUsers, barePosts := users, posts
		bareUsers.Indexes, barePosts.ForeignKeys = nil, nil
		require.NoError(t, mapped.ApplyMigration(ctx, request(core.Migration{ID: "0001_test", Up: []core.SchemaOperation{
			createTableOp(bareUsers), createTableOp(barePosts),
			addIndexOp("users", users.Indexes[0]),
			addForeignKeyOp("posts", posts.ForeignKeys[0]),
		}}, nil)))

		// Physically, only the physical names exist.
		exists, err := tm.TableExists(ctx, "app_users")
		require.NoError(t, err)
		require.True(t, exists)
		cols, err := tm.Columns(ctx, "app_posts")
		require.NoError(t, err)
		assert.Equal(t, "author_id", cols[1].Name)

		report, err := core.RunIntrospection(ctx, registry, mapped, true)
		require.NoError(t, err)
		require.Len(t, report.Tables, 2)
		for name, ti := range report.Tables {
			assert.True(t, ti.ExistsLive, name)
			assert.Empty(t, ti.Renames, "%s: a physical name must not look like a rename", name)
			for _, f := range ti.Columns {
				assert.Equal(t, core.ColMatch, f.Kind, "%s.%s", name, f.Name)
			}
			for _, f := range ti.Indexes {
				assert.Equal(t, core.IdxMatch, f.Kind, "%s index %s", name, f.Name)
			}
			for _, f := range ti.ForeignKeys {
				assert.Equal(t, core.FKMatch, f.Kind, "%s fk %s", name, f.Name)
			}
		}

		// The live physical name is kept, not lost.
		for _, f := range report.Tables["users"].Columns {
			if f.Name == "email" {
				assert.Equal(t, "email_address", f.Live.PhysicalName)
			}
		}
	})

	t.Run("ViewsAndMissingTables", func(t *testing.T) {
		setup(t)
		_, err := db.ExecContext(ctx, `CREATE VIEW active_users AS SELECT * FROM users`)
		require.NoError(t, err)

		exists, err := driver.TableExists(ctx, "active_users")
		require.NoError(t, err)
		assert.True(t, exists)
		live, err := driver.Introspect(ctx, "active_users")
		require.NoError(t, err)
		assert.Equal(t, core.ObjectView, live.Kind)

		exists, err = driver.TableExists(ctx, "nope")
		require.NoError(t, err)
		assert.False(t, exists)
		live, err = driver.Introspect(ctx, "nope")
		require.NoError(t, err)
		assert.False(t, live.Exists)
	})

	t.Run("ResolverMapsTableNames", func(t *testing.T) {
		setup(t)
		mapped := postgres.NewPostgreSQLDriver(db, mapResolver{tables: map[string]string{"accounts": "users"}})
		exists, err := mapped.TableExists(ctx, "accounts")
		require.NoError(t, err)
		assert.True(t, exists)
		live, err := mapped.Introspect(ctx, "accounts")
		require.NoError(t, err)
		assert.Equal(t, "accounts", live.Schema.Name)
		assert.Equal(t, "users", live.Schema.PhysicalName)
	})

	t.Run("AlterColumnUsesPrevColumnForUniqueness", func(t *testing.T) {
		setup(t)
		prev := schema.Column{Name: "name", Type: schema.ColTypeText, Nullable: true}
		next := schema.Column{Name: "name", Type: schema.ColTypeText, Nullable: true, Unique: true}
		op := alterColumnOp("users", next)
		op.PrevColumn = &prev
		require.NoError(t, driver.ApplyMigration(ctx, request(core.Migration{ID: "0002_test", Up: []core.SchemaOperation{op}}, nil)))

		require.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 1, "email": "a@example.com", "name": "Ada"}))
		assert.Error(t, tm.Insert(ctx, "users", map[string]any{"id": 2, "email": "b@example.com", "name": "Ada"}), "UNIQUE added")

		back := alterColumnOp("users", prev)
		back.PrevColumn = &next
		require.NoError(t, driver.ApplyMigration(ctx, request(core.Migration{ID: "0003_test", Up: []core.SchemaOperation{back}}, nil)))
		assert.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 4, "email": "d@example.com", "name": "Ada"}), "UNIQUE dropped")
	})
}
