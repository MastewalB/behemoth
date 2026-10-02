package migrations

import (
	"context"
	"testing"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- SQLite-specific: core.SchemaIntrospector ----

// sqliteAllTypesTable exercises every canonical type the SQLite renderer keeps
// distinct, plus the column features the introspector has to map back. uuid,
// json and bytes are left out: they render to the same declared types as blob
// and text, so they only match after normalization
// (see TestSQLiteIntrospector/NormalizedDeclarationsMatch).
func sqliteAllTypesTable() schema.Table {
	return schema.Table{
		Name: "all_types",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, AutoInc: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40, Unique: true},
			{Name: "t", Type: schema.ColTypeText, Nullable: true, Default: "it's"},
			{Name: "i", Type: schema.ColTypeInteger, Default: 7},
			{Name: "big", Type: schema.ColTypeBigInt, Nullable: true},
			{Name: "r", Type: schema.ColTypeReal, Nullable: true},
			{Name: "n", Type: schema.ColTypeNumeric, Nullable: true},
			{Name: "b", Type: schema.ColTypeBoolean, Default: true},
			{Name: "dt", Type: schema.ColTypeDateTime, Nullable: true},
			{Name: "ts", Type: schema.ColTypeTimestamp, Overrides: map[string]schema.ColumnOverride{sqlite.DriverName: {Default: "CURRENT_TIMESTAMP"}}},
			{Name: "bl", Type: schema.ColTypeBlob, Nullable: true},
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

func TestSQLiteIntrospector(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	tm := NewSQLiteTestManager(db)
	driver := sqlite.NewSQLiteDriver(db, nil)

	exec := func(t *testing.T, stmts ...string) {
		t.Helper()
		for _, stmt := range stmts {
			_, err := db.ExecContext(ctx, stmt)
			require.NoError(t, err, stmt)
		}
	}

	// setup creates the given tables through the driver exactly as a generated
	// migration would: tables, then indexes and FKs as their own operations.
	setup := func(t *testing.T, tables ...schema.Table) {
		t.Helper()
		require.NoError(t, tm.DropAllTables(ctx))
		var ops []core.SchemaOperation
		for _, table := range tables {
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
		setup(t, usersTable(), sqliteAllTypesTable())
		declared := sqliteAllTypesTable()
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
			assert.Equal(t, want.Length, got.Length, want.Name)
			assert.Equal(t, want.Nullable, got.Nullable, want.Name)
			assert.Equal(t, want.PrimaryKey, got.PrimaryKey, want.Name)
			assert.Equal(t, want.Unique, got.Unique, want.Name)
			assert.Equal(t, want.AutoInc, got.AutoInc, want.Name)
		}
		byName := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			byName[c.Name] = c
		}
		assert.Equal(t, "it's", byName["t"].Default, "quoted literal with an escaped quote")
		assert.Equal(t, int64(7), byName["i"].Default)
		assert.Equal(t, true, byName["b"].Default, "0/1 default on a boolean column reads back as a bool")
		assert.Equal(t, "CURRENT_TIMESTAMP", byName["ts"].Overrides[sqlite.DriverName].Default, "expression default is kept verbatim, without the renderer's parentheses")
		assert.Nil(t, byName["ts"].Default)

		assert.ElementsMatch(t, declared.Indexes, live.Schema.Indexes, "the primary key's and UNIQUE columns' own indexes are excluded")
		assert.Equal(t, declared.ForeignKeys, live.Schema.ForeignKeys, "the constraint name comes from the table's SQL")
	})

	// The real contract: what the driver creates, the introspector reads back
	// with no divergence, so a generate-only run right after produces nothing.
	t.Run("NoDivergenceAgainstDeclaredRegistry", func(t *testing.T) {
		setup(t, usersTable(), sqliteAllTypesTable())
		registry := schema.NewRegistry()
		for _, table := range []schema.Table{usersTable(), sqliteAllTypesTable()} {
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
		normalized := schema.Table{Name: "normalized", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeBigInt, PrimaryKey: true, AutoInc: true, Nullable: true, Unique: true}, // INTEGER rowid alias: integer, never NULL, not UNIQUE
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},                                                   // BLOB
			{Name: "j", Type: schema.ColTypeJson, Nullable: true},                                                   // TEXT
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},                                                 // BLOB
			{Name: "s", Type: schema.ColTypeString, Nullable: true},                                                 // VARCHAR(255)
			{Name: "t", Type: schema.ColTypeText, Length: 10, Nullable: true},                                       // TEXT has no length
			{Name: "o", Type: schema.ColTypeUuid, Nullable: true, // override: TEXT
				Overrides: map[string]schema.ColumnOverride{sqlite.DriverName: {Type: schema.ColTypeText}}},
		}}
		setup(t, normalized)
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
		exec(t, `CREATE TABLE changed (id INTEGER PRIMARY KEY, s VARCHAR(255) NOT NULL, n TEXT NOT NULL, b BLOB NOT NULL)`)
		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "changed"}, schema.Table{Name: "changed", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40},   // live is 255
			{Name: "n", Type: schema.ColTypeInteger},              // live is text
			{Name: "b", Type: schema.ColTypeUuid, Nullable: true}, // same type after normalization, but nullability changed
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

	// Defaults as SQLite stores them — the expression text as written,
	// wrapped in the renderer's parentheses — still match their declarations,
	// whatever case or spacing they were declared with.
	t.Run("DefaultsMatch", func(t *testing.T) {
		expr := func(e string) map[string]schema.ColumnOverride {
			return map[string]schema.ColumnOverride{sqlite.DriverName: {Default: e}}
		}
		defaults := schema.Table{Name: "defaults", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "neg", Type: schema.ColTypeInteger, Default: -1},
			{Name: "json_num", Type: schema.ColTypeInteger, Default: float64(7)}, // as read back from a migration file
			{Name: "dbl", Type: schema.ColTypeReal, Default: 1.5},
			{Name: "b", Type: schema.ColTypeBoolean, Default: false},
			{Name: "int_bool", Type: schema.ColTypeInteger, Default: true},
			{Name: "s", Type: schema.ColTypeString, Length: 10, Default: "it's"},
			{Name: "ts_keyword", Type: schema.ColTypeTimestamp, Overrides: expr("current_timestamp")},
			{Name: "dt_func", Type: schema.ColTypeDateTime, Overrides: expr("datetime('now')")},
			{Name: "j", Type: schema.ColTypeJson, Overrides: expr("'{}'")},
			{Name: "sum", Type: schema.ColTypeInteger, Overrides: expr("1+1")},
			{Name: "none", Type: schema.ColTypeText, Nullable: true},
		}}
		setup(t, defaults)
		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "defaults"}, defaults))
		require.NoError(t, registry.Freeze())

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		require.Len(t, report.Tables["defaults"].Columns, len(defaults.Columns))
		for _, f := range report.Tables["defaults"].Columns {
			assert.Equal(t, core.ColMatch, f.Kind, "%s: declared %#v %v, live %#v %v", f.Name, f.Declared.Default, f.Declared.Overrides, f.Live.Default, f.Live.Overrides)
		}
	})

	t.Run("DefaultChangesDiffer", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t, `CREATE TABLE changed (id INTEGER PRIMARY KEY, kept TEXT NOT NULL DEFAULT 'a', changed TEXT NOT NULL DEFAULT 'a', removed TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "changed"}, schema.Table{Name: "changed", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "kept", Type: schema.ColTypeText, Default: "a"},
			{Name: "changed", Type: schema.ColTypeText, Default: "b"},
			{Name: "removed", Type: schema.ColTypeTimestamp},
		}}))
		require.NoError(t, registry.Freeze())

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		kinds := map[string]core.ColumnDivergenceKind{}
		for _, f := range report.Tables["changed"].Columns {
			kinds[f.Name] = f.Kind
		}
		assert.Equal(t, map[string]core.ColumnDivergenceKind{
			"id": core.ColMatch, "kept": core.ColMatch, "changed": core.ColDiffers, "removed": core.ColDiffers,
		}, kinds)
	})

	// A table created outside behemoth, with common SQL type names, a
	// composite key, a named composite UNIQUE constraint, and indexes the
	// canonical model can't express.
	t.Run("ExistingDatabase", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t,
			`CREATE TABLE legacy (
				a INT, b INT, note VARCHAR, code CHAR(3), amount DECIMAL(10, 2), flag BOOL,
				created DATETIME DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (a, b),
				CONSTRAINT uq_legacy_code_note UNIQUE (code, note)
			)`,
			`CREATE INDEX idx_legacy_expr ON legacy (lower(note))`,
			`CREATE INDEX idx_legacy_partial ON legacy (code) WHERE flag`,
			`CREATE INDEX idx_legacy_amount ON legacy (amount)`,
		)

		live, err := driver.Introspect(ctx, "legacy")
		require.NoError(t, err)
		assert.Empty(t, live.Ambiguities)
		cols := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			cols[c.Name] = c
		}
		assert.True(t, cols["a"].PrimaryKey)
		assert.True(t, cols["b"].PrimaryKey)
		assert.True(t, cols["a"].Nullable, "SQLite allows NULL in a non-INTEGER primary key, and nothing forbids it here")
		assert.Equal(t, schema.ColTypeInteger, cols["a"].Type)
		assert.Equal(t, schema.ColTypeText, cols["note"].Type, "unbounded VARCHAR is TEXT")
		assert.Equal(t, schema.ColTypeString, cols["code"].Type)
		assert.Equal(t, 3, cols["code"].Length)
		assert.Equal(t, schema.ColTypeNumeric, cols["amount"].Type)
		assert.Equal(t, schema.ColTypeBoolean, cols["flag"].Type)
		assert.Equal(t, "CURRENT_TIMESTAMP", cols["created"].Overrides[sqlite.DriverName].Default)

		assert.ElementsMatch(t, []schema.Index{
			{Name: "idx_legacy_amount", Columns: []string{"amount"}},
			{Name: "uq_legacy_code_note", Columns: []string{"code", "note"}, Unique: true},
		}, live.Schema.Indexes, "expression and partial indexes are skipped; a composite UNIQUE keeps its constraint name")
	})

	t.Run("RowidAliasAndUnnamedForeignKey", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t,
			`CREATE TABLE parent (id INTEGER PRIMARY KEY)`,
			`CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent ON DELETE CASCADE)`,
		)
		live, err := driver.Introspect(ctx, "child")
		require.NoError(t, err)
		require.Len(t, live.Schema.Columns, 2)
		id := live.Schema.Columns[0]
		assert.False(t, id.Nullable, "a rowid alias can never be NULL")
		assert.False(t, id.AutoInc, "a rowid alias without AUTOINCREMENT may reuse ids")

		require.Len(t, live.Schema.ForeignKeys, 1)
		assert.Equal(t, schema.ForeignKey{
			Name: "", Columns: []string{"parent_id"}, RefTable: "parent", RefColumns: []string{"id"}, OnDelete: schema.FKCascade,
		}, live.Schema.ForeignKeys[0], "REFERENCES without columns targets the parent's primary key; an unnamed key has no name")
	})

	t.Run("UnknownTypesAreAmbiguous", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t, `CREATE TABLE odd (id INTEGER PRIMARY KEY, d DATE, x, note TEXT)`)

		live, err := driver.Introspect(ctx, "odd")
		require.NoError(t, err)
		require.Len(t, live.Ambiguities, 2)
		assert.Equal(t, "d", live.Ambiguities[0].Column)
		assert.Contains(t, live.Ambiguities[0].Reason, `"DATE"`)
		assert.Equal(t, "x", live.Ambiguities[1].Column)

		registry := schema.NewRegistry()
		require.NoError(t, registry.Declare(tableModel{name: "odd"}, schema.Table{Name: "odd", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
		}}))
		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		err = core.RejectAmbiguousTypes(report)
		require.Error(t, err)
		assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationUnmappableColumnType))
	})

	t.Run("ViewsIndexesAndMissingTables", func(t *testing.T) {
		setup(t, usersTable())
		exec(t, `CREATE VIEW active_users AS SELECT * FROM users`, `CREATE INDEX idx_users_name ON users (name)`)
		t.Cleanup(func() { db.ExecContext(ctx, `DROP VIEW IF EXISTS active_users`) })

		for name, kind := range map[string]core.ObjectKind{"active_users": core.ObjectView, "idx_users_name": core.ObjectOther} {
			exists, err := driver.TableExists(ctx, name)
			require.NoError(t, err)
			assert.True(t, exists, name)
			live, err := driver.Introspect(ctx, name)
			require.NoError(t, err)
			assert.True(t, live.Exists, name)
			assert.Equal(t, kind, live.Kind, name)
		}

		exists, err := driver.TableExists(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, exists)
		live, err := driver.Introspect(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, live.Exists)
	})

	// Tables and columns whose physical names differ from their canonical
	// ones must still diff as matches.
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
		mapped := sqlite.NewSQLiteDriver(db, resolver)

		bareUsers, barePosts := users, posts
		bareUsers.Indexes, barePosts.ForeignKeys = nil, nil
		require.NoError(t, mapped.ApplyMigration(ctx, request(core.Migration{ID: "0001_test", Up: []core.SchemaOperation{
			createTableOp(bareUsers), createTableOp(barePosts),
			addIndexOp("users", users.Indexes[0]),
			addForeignKeyOp("posts", posts.ForeignKeys[0]),
		}}, nil)))

		exists, err := tm.TableExists(ctx, "app_users")
		require.NoError(t, err)
		require.True(t, exists, "physically, only the physical names exist")

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
	})

	// The renderer is the other half of generate-only: a migration's script is
	// what the developer's own tool runs, so running it must produce exactly
	// what ApplyMigration would — read back through the introspector.
	t.Run("RenderedScriptMatchesApply", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		var ops []core.SchemaOperation
		for _, table := range []schema.Table{usersTable(), sqliteAllTypesTable()} {
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
		m := core.Migration{ID: "0001_test", Up: ops}
		script, err := driver.RenderMigration(ctx, m)
		require.NoError(t, err)
		assert.Equal(t, ".sql", driver.FileExtension())

		exists, err := driver.TableExists(ctx, "users")
		require.NoError(t, err)
		require.False(t, exists, "rendering never applies anything")

		scriptDB := openSQLite(t)
		_, err = scriptDB.ExecContext(ctx, script)
		require.NoError(t, err, script)
		require.NoError(t, driver.ApplyMigration(ctx, request(m, nil)))

		fromScript := sqlite.NewSQLiteDriver(scriptDB, nil)
		for _, table := range []string{"users", "all_types"} {
			applied, err := driver.Introspect(ctx, table)
			require.NoError(t, err)
			scripted, err := fromScript.Introspect(ctx, table)
			require.NoError(t, err)
			assert.Equal(t, applied.Schema, scripted.Schema, table)
		}
	})
}
