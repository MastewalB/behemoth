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

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/sqlserver"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SQLServerTestManager implements DriverTestManager for SQL Server, scoped to
// the connection's default schema.
type SQLServerTestManager struct {
	db *sql.DB
}

func NewSQLServerTestManager(db *sql.DB) *SQLServerTestManager {
	return &SQLServerTestManager{db: db}
}

// bracket quotes an identifier the T-SQL way.
func bracket(ident string) string {
	return "[" + strings.ReplaceAll(ident, "]", "]]") + "]"
}

func (m *SQLServerTestManager) TableExists(ctx context.Context, table string) (bool, error) {
	var n int
	err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sys.objects WHERE schema_id = SCHEMA_ID() AND name = @p1 AND type = 'U'`, table).Scan(&n)
	return n > 0, err
}

func (m *SQLServerTestManager) Columns(ctx context.Context, table string) ([]ColumnInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT c.name, c.is_nullable,
			CAST(CASE WHEN c.default_object_id <> 0 OR c.is_identity = 1 THEN 1 ELSE 0 END AS bit),
			CAST(CASE WHEN EXISTS (
				SELECT 1 FROM sys.indexes i
				JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
				WHERE i.object_id = c.object_id AND i.is_primary_key = 1 AND ic.column_id = c.column_id
			) THEN 1 ELSE 0 END AS bit)
		FROM sys.columns c
		WHERE c.object_id = OBJECT_ID(@p1)
		ORDER BY c.column_id`, bracket(table))
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

func (m *SQLServerTestManager) Indexes(ctx context.Context, table string) ([]IndexInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT i.name, i.is_unique, col.name
		FROM sys.indexes i
		JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
		JOIN sys.columns col ON col.object_id = ic.object_id AND col.column_id = ic.column_id
		WHERE i.object_id = OBJECT_ID(@p1) AND i.type > 0
		ORDER BY i.name, ic.key_ordinal`, bracket(table))
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

func (m *SQLServerTestManager) ForeignKeys(ctx context.Context, table string) ([]ForeignKeyInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT fk.name, fk.delete_referential_action_desc, OBJECT_NAME(fk.referenced_object_id), pc.name, rc.name
		FROM sys.foreign_keys fk
		JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
		JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
		JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
		WHERE fk.parent_object_id = OBJECT_ID(@p1)
		ORDER BY fk.name, fkc.constraint_column_id`, bracket(table))
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
			OnDelete: sqlServerFKAction(action),
		})
	}
	return out, rows.Err()
}

// sqlServerFKAction maps sys.foreign_keys.delete_referential_action_desc.
// SQL Server has no RESTRICT: NO_ACTION is what rejects the delete.
func sqlServerFKAction(action string) schema.ForeignKeyAction {
	switch action {
	case "CASCADE":
		return schema.FKCascade
	case "SET_NULL":
		return schema.FKSetNull
	case "NO_ACTION":
		return schema.FKRestrict
	default:
		return schema.ForeignKeyAction(strings.ToLower(action))
	}
}

func (m *SQLServerTestManager) Insert(ctx context.Context, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		quoted[i], marks[i], args[i] = bracket(c), fmt.Sprintf("@p%d", i+1), row[c]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", bracket(table), strings.Join(quoted, ", "), strings.Join(marks, ", "))
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}

func (m *SQLServerTestManager) Delete(ctx context.Context, table, column string, value any) error {
	_, err := m.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s = @p1", bracket(table), bracket(column)), value)
	return err
}

func (m *SQLServerTestManager) Rows(ctx context.Context, table, orderBy string) ([]map[string]any, error) {
	return scanRows(m.db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s ORDER BY %s", bracket(table), bracket(orderBy))))
}

func (m *SQLServerTestManager) RowCount(ctx context.Context, table string) (int64, error) {
	var n int64
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+bracket(table)).Scan(&n)
	return n, err
}

func (m *SQLServerTestManager) LedgerIDs(ctx context.Context, ledgerTable string) ([]string, error) {
	if exists, err := m.TableExists(ctx, ledgerTable); err != nil || !exists {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT id FROM "+bracket(ledgerTable)+" ORDER BY id")
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

func (m *SQLServerTestManager) Snapshot(ctx context.Context, snapshotTable string) (core.SchemaSnapshot, bool, error) {
	if exists, err := m.TableExists(ctx, snapshotTable); err != nil || !exists {
		return core.SchemaSnapshot{}, false, err
	}
	var snap core.SchemaSnapshot
	var tables string
	err := m.db.QueryRowContext(ctx, "SELECT version, tables FROM "+bracket(snapshotTable)+" WHERE id = 1").Scan(&snap.Version, &tables)
	if errors.Is(err, sql.ErrNoRows) {
		return core.SchemaSnapshot{}, false, nil
	}
	if err != nil {
		return core.SchemaSnapshot{}, false, err
	}
	if err := json.Unmarshal([]byte(tables), &snap.Tables); err != nil {
		return core.SchemaSnapshot{}, false, err
	}
	return snap, true, nil
}

// DropAllTables drops every foreign key, then every view and table, of the
// default schema.
func (m *SQLServerTestManager) DropAllTables(ctx context.Context) error {
	var drops []string
	for _, q := range []string{
		`SELECT 'ALTER TABLE ' + QUOTENAME(OBJECT_NAME(parent_object_id)) + ' DROP CONSTRAINT ' + QUOTENAME(name) FROM sys.foreign_keys WHERE schema_id = SCHEMA_ID()`,
		`SELECT 'DROP VIEW ' + QUOTENAME(name) FROM sys.objects WHERE schema_id = SCHEMA_ID() AND type = 'V'`,
		`SELECT 'DROP TABLE ' + QUOTENAME(name) FROM sys.objects WHERE schema_id = SCHEMA_ID() AND type = 'U' AND is_ms_shipped = 0`,
	} {
		rows, err := m.db.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		for rows.Next() {
			var stmt string
			if err := rows.Scan(&stmt); err != nil {
				rows.Close()
				return err
			}
			drops = append(drops, stmt)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	for _, stmt := range drops {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

func (m *SQLServerTestManager) CleanupDatabase(ctx context.Context) {}

// ---- SQL Server-specific: introspection, normalization and live-schema operations ----

func sqlServerExpr(e string) map[string]schema.ColumnOverride {
	return map[string]schema.ColumnOverride{sqlserver.DriverName: {Default: e}}
}

// sqlServerAllTypesTable exercises every canonical type, plus the column
// features the introspector has to map back.
func sqlServerAllTypesTable() schema.Table {
	return schema.Table{
		Name: "all_types",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeBigInt, PrimaryKey: true, AutoInc: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40, Unique: true},
			{Name: "s_null", Type: schema.ColTypeString, Length: 40, Nullable: true, Unique: true},
			{Name: "t", Type: schema.ColTypeText, Nullable: true, Default: "it's"},
			{Name: "i", Type: schema.ColTypeInteger, Default: 7},
			{Name: "r", Type: schema.ColTypeReal, Nullable: true},
			{Name: "n", Type: schema.ColTypeNumeric, Nullable: true},
			{Name: "b", Type: schema.ColTypeBoolean, Default: true},
			{Name: "dt", Type: schema.ColTypeDateTime, Nullable: true},
			{Name: "ts", Type: schema.ColTypeTimestamp, Overrides: sqlServerExpr("sysdatetimeoffset()")},
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			{Name: "j", Type: schema.ColTypeJson, Nullable: true},
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},
			{Name: "bl", Type: schema.ColTypeBlob, Nullable: true},
			{Name: "owner_id", Type: schema.ColTypeInteger, Nullable: true},
		},
		Indexes: []schema.Index{
			{Name: "idx_all_types_i_b", Columns: []string{"i", "b"}},
			{Name: "uq_all_types_i", Columns: []string{"i"}, Unique: true},        // NOT NULL: no filter
			{Name: "uq_all_types_r", Columns: []string{"r"}, Unique: true},        // nullable: filtered
			{Name: "uq_all_types_i_n", Columns: []string{"i", "n"}, Unique: true}, // filtered on n only
		},
		ForeignKeys: []schema.ForeignKey{
			{Name: "fk_all_types_owner", Columns: []string{"owner_id"}, RefTable: "users", RefColumns: []string{"id"}, OnDelete: schema.FKSetNull},
		},
	}
}

func runSQLServerDriverTests(t *testing.T, db *sql.DB, tm *SQLServerTestManager) {
	ctx := context.Background()
	driver := sqlserver.NewSQLServerDriver(db, nil)

	apply := func(t *testing.T, d *sqlserver.SQLServerDriver, id string, ops ...core.SchemaOperation) error {
		t.Helper()
		return d.ApplyMigration(ctx, request(core.Migration{ID: id, Up: ops}, nil))
	}
	exec := func(t *testing.T, stmts ...string) {
		t.Helper()
		for _, stmt := range stmts {
			_, err := db.ExecContext(ctx, stmt)
			require.NoError(t, err, stmt)
		}
	}
	setup := func(t *testing.T) {
		t.Helper()
		require.NoError(t, tm.DropAllTables(ctx))
		require.NoError(t, apply(t, driver, "0001_test", tableOps(usersTable(), sqlServerAllTypesTable())...))
	}
	introspect := func(t *testing.T, table string) (map[string]schema.Column, core.IntrospectedTable) {
		t.Helper()
		live, err := driver.Introspect(ctx, table)
		require.NoError(t, err)
		cols := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			cols[c.Name] = c
		}
		return cols, live
	}
	// nativeType reads a column's type as SQL Server names it.
	nativeType := func(t *testing.T, table, column string) string {
		t.Helper()
		var name string
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT TYPE_NAME(system_type_id) FROM sys.columns WHERE object_id = OBJECT_ID(@p1) AND name = @p2`, bracket(table), column).Scan(&name))
		return name
	}

	t.Run("IntrospectRoundTripsDeclaredSchema", func(t *testing.T) {
		setup(t)
		declared := sqlServerAllTypesTable()
		byName, live := introspect(t, "all_types")
		require.True(t, live.Exists)
		assert.Equal(t, core.ObjectTable, live.Kind)
		assert.Empty(t, live.Ambiguities)

		// What SQL Server can't keep apart reads back collapsed.
		collapsed := map[string]schema.ColumnType{"u": schema.ColTypeString, "j": schema.ColTypeText, "by": schema.ColTypeBlob}
		require.Len(t, live.Schema.Columns, len(declared.Columns))
		for i, want := range declared.Columns {
			got := live.Schema.Columns[i]
			wantType := want.Type
			if c, ok := collapsed[want.Name]; ok {
				wantType = c
			}
			assert.Equal(t, want.Name, got.Name)
			assert.Equal(t, wantType, got.Type, want.Name)
			assert.Equal(t, want.Nullable, got.Nullable, want.Name)
			assert.Equal(t, want.PrimaryKey, got.PrimaryKey, want.Name)
			assert.Equal(t, want.Unique, got.Unique, want.Name)
			assert.Equal(t, want.AutoInc, got.AutoInc, want.Name)
		}
		assert.Equal(t, 40, byName["s"].Length, "NVARCHAR lengths are characters, not bytes")
		assert.Equal(t, 36, byName["u"].Length, "a uuid is NCHAR(36)")
		assert.Zero(t, byName["t"].Length, "only strings carry a length")
		assert.Equal(t, "it's", byName["t"].Default)
		assert.Equal(t, int64(7), byName["i"].Default)
		assert.Equal(t, true, byName["b"].Default, "((1)) on a BIT column")
		assert.Equal(t, "sysdatetimeoffset()", byName["ts"].Overrides[sqlserver.DriverName].Default, "expression default is kept verbatim")
		assert.Nil(t, byName["ts"].Default)

		assert.ElementsMatch(t, declared.Indexes, live.Schema.Indexes, "the primary key and unique-column indexes are excluded; NULL filters don't hide an index")
		assert.Equal(t, declared.ForeignKeys, live.Schema.ForeignKeys)
	})

	// The real contract: what the driver creates, the introspector reads back
	// with no divergence, so a generate-only run right after produces nothing.
	t.Run("NoDivergenceAgainstDeclaredRegistry", func(t *testing.T) {
		setup(t)
		report, err := core.RunIntrospection(ctx, declare(t, usersTable(), sqlServerAllTypesTable()), driver, true)
		require.NoError(t, err)
		require.NoError(t, core.RejectAmbiguousTypes(report))
		require.Len(t, report.Tables, 2)
		assertNoDivergence(t, report)
	})

	// Declarations the DDL can't preserve exactly still match once normalized
	// (core.ColumnNormalizer).
	t.Run("NormalizedDeclarationsMatch", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		normalized := schema.Table{Name: "normalized", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true, Nullable: true, Unique: true}, // reads back NOT NULL, not UNIQUE
			{Name: "s", Type: schema.ColTypeString},                                                   // NVARCHAR(255)
			{Name: "long", Type: schema.ColTypeString, Length: 5000, Nullable: true},                  // NVARCHAR(MAX), reads back as text
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},                                   // VARBINARY(MAX), reads back as blob
			{Name: "t", Type: schema.ColTypeText, Length: 10, Nullable: true},                         // NVARCHAR(MAX) has no length
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},                                     // NCHAR(36), reads back as string(36)
			{Name: "j", Type: schema.ColTypeJson, Nullable: true},                                     // NVARCHAR(MAX), reads back as text
			{Name: "o", Type: schema.ColTypeString, Length: 40, Nullable: true, // override: NVARCHAR(MAX)
				Overrides: map[string]schema.ColumnOverride{sqlserver.DriverName: {Type: schema.ColTypeText}}},
		}}
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(normalized)))
		registry := declare(t, normalized)

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		require.NoError(t, core.RejectAmbiguousTypes(report))
		require.Len(t, report.Tables["normalized"].Columns, len(normalized.Columns))
		assertNoDivergence(t, report)

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
		exec(t, `CREATE TABLE changed (id INT PRIMARY KEY, s NVARCHAR(255) NOT NULL, n NVARCHAR(MAX) NOT NULL, b VARBINARY(MAX) NOT NULL)`)
		registry := declare(t, schema.Table{Name: "changed", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "s", Type: schema.ColTypeString, Length: 40},    // live is 255
			{Name: "n", Type: schema.ColTypeInteger},               // live is text
			{Name: "b", Type: schema.ColTypeBytes, Nullable: true}, // same type after normalization, but nullability changed
		}})

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		assert.Equal(t, map[string]core.ColumnDivergenceKind{
			"id": core.ColMatch, "s": core.ColDiffers, "n": core.ColDiffers, "b": core.ColDiffers,
		}, columnKinds(report, "changed"))
	})

	// Defaults as SQL Server stores them still match their declarations:
	// everything wrapped in parentheses, numbers twice, strings with an N
	// prefix, booleans as 1/0, function names lower-cased, CURRENT_TIMESTAMP
	// as getdate().
	t.Run("DefaultsMatch", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		defaults := schema.Table{Name: "defaults", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "neg", Type: schema.ColTypeInteger, Default: -1},
			{Name: "big", Type: schema.ColTypeBigInt, Default: int64(-5)},
			{Name: "json_num", Type: schema.ColTypeInteger, Default: float64(7)}, // as read back from a migration file
			{Name: "dbl", Type: schema.ColTypeReal, Default: 1.5},
			{Name: "num", Type: schema.ColTypeNumeric, Default: 1.5},
			{Name: "b", Type: schema.ColTypeBoolean, Default: false},
			{Name: "one", Type: schema.ColTypeInteger, Default: 1}, // stays a number: only BIT reads 1 as true
			{Name: "s", Type: schema.ColTypeString, Length: 10, Default: "it's"},
			{Name: "s_empty", Type: schema.ColTypeString, Length: 10, Default: ""},
			{Name: "t", Type: schema.ColTypeText, Default: `a\b (c)`},
			{Name: "j", Type: schema.ColTypeJson, Default: "{}"},
			{Name: "ts_upper", Type: schema.ColTypeTimestamp, Overrides: sqlServerExpr("SYSDATETIMEOFFSET()")},
			{Name: "ts_keyword", Type: schema.ColTypeDateTime, Overrides: sqlServerExpr("CURRENT_TIMESTAMP")},
			{Name: "ts_parens", Type: schema.ColTypeDateTime, Overrides: sqlServerExpr("(getdate())")},
			{Name: "u", Type: schema.ColTypeUuid, Overrides: sqlServerExpr("NEWID()")},
			{Name: "s_expr", Type: schema.ColTypeString, Length: 10, Overrides: sqlServerExpr("N'x'")},
			{Name: "none", Type: schema.ColTypeText, Nullable: true},
		}}
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(defaults)))

		report, err := core.RunIntrospection(ctx, declare(t, defaults), driver, true)
		require.NoError(t, err)
		require.Len(t, report.Tables["defaults"].Columns, len(defaults.Columns))
		for _, f := range report.Tables["defaults"].Columns {
			assert.Equal(t, core.ColMatch, f.Kind, "%s: declared %#v %v, live %#v %v", f.Name, f.Declared.Default, f.Declared.Overrides, f.Live.Default, f.Live.Overrides)
		}

		require.NoError(t, tm.Insert(ctx, "defaults", map[string]any{"id": 1}))
		rows, err := tm.Rows(ctx, "defaults", "id")
		require.NoError(t, err)
		assert.Equal(t, `a\b (c)`, asString(rows[0]["t"]))
		assert.Equal(t, "it's", asString(rows[0]["s"]))
	})

	t.Run("DefaultChangesDiffer", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t, `CREATE TABLE changed (id INT PRIMARY KEY, kept NVARCHAR(10) NOT NULL DEFAULT 'a', changed NVARCHAR(10) NOT NULL DEFAULT 'a', removed DATETIMEOFFSET(6) NOT NULL DEFAULT SYSDATETIMEOFFSET())`)
		registry := declare(t, schema.Table{Name: "changed", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "kept", Type: schema.ColTypeString, Length: 10, Default: "a"},
			{Name: "changed", Type: schema.ColTypeString, Length: 10, Default: "b"},
			{Name: "removed", Type: schema.ColTypeTimestamp},
		}})

		report, err := core.RunIntrospection(ctx, registry, driver, true)
		require.NoError(t, err)
		assert.Equal(t, map[string]core.ColumnDivergenceKind{
			"id": core.ColMatch, "kept": core.ColMatch, "changed": core.ColDiffers, "removed": core.ColDiffers,
		}, columnKinds(report, "changed"))
	})

	// A table nobody created through the driver: native types of every
	// family, a UNIQUE constraint, and indexes the model can't express.
	t.Run("ExistingDatabase", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t,
			`CREATE TABLE parents (id INT PRIMARY KEY)`,
			`CREATE TABLE legacy (
				a INT, b INT,
				seq BIGINT IDENTITY(100, 5) NOT NULL,
				email VARCHAR(100) NOT NULL CONSTRAINT uq_legacy_email UNIQUE,
				note VARCHAR(MAX),
				flag BIT NOT NULL DEFAULT 1,
				small TINYINT NOT NULL DEFAULT 3,
				price MONEY,
				guid UNIQUEIDENTIFIER,
				created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				parent_id INT REFERENCES parents (id),
				PRIMARY KEY (a, b)
			)`,
			`CREATE INDEX idx_legacy_small ON legacy (small DESC)`,
			`CREATE INDEX idx_legacy_include ON legacy (small) INCLUDE (price)`,
			`CREATE INDEX idx_legacy_filtered ON legacy (small) WHERE small > 1`,
		)

		cols, live := introspect(t, "legacy")
		assert.Empty(t, live.Ambiguities)
		assert.True(t, cols["a"].PrimaryKey)
		assert.True(t, cols["b"].PrimaryKey)
		assert.False(t, cols["a"].Nullable, "primary key columns are NOT NULL")
		assert.True(t, cols["seq"].AutoInc)
		assert.True(t, cols["email"].Unique, "a UNIQUE constraint on one column")
		assert.Equal(t, schema.ColTypeString, cols["email"].Type)
		assert.Equal(t, 100, cols["email"].Length, "VARCHAR lengths are bytes")
		assert.Equal(t, schema.ColTypeText, cols["note"].Type, "VARCHAR(MAX) is text")
		assert.Equal(t, schema.ColTypeBoolean, cols["flag"].Type)
		assert.Equal(t, true, cols["flag"].Default)
		assert.Equal(t, schema.ColTypeInteger, cols["small"].Type)
		assert.Equal(t, int64(3), cols["small"].Default)
		assert.Equal(t, schema.ColTypeNumeric, cols["price"].Type)
		assert.Equal(t, schema.ColTypeUuid, cols["guid"].Type)
		assert.Equal(t, schema.ColTypeDateTime, cols["created"].Type)
		assert.Equal(t, "getdate()", cols["created"].Overrides[sqlserver.DriverName].Default)

		assert.Equal(t, []schema.Index{{Name: "idx_legacy_small", Columns: []string{"small"}}}, live.Schema.Indexes,
			"indexes with included columns or a filter of their own can't be represented")
		require.Len(t, live.Schema.ForeignKeys, 1)
		fk := live.Schema.ForeignKeys[0]
		assert.Equal(t, []string{"parent_id"}, fk.Columns)
		assert.Equal(t, "parents", fk.RefTable)
		assert.Equal(t, schema.FKRestrict, fk.OnDelete, "NO ACTION is restrict")
	})

	t.Run("UnknownTypesAreAmbiguous", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t, `CREATE TABLE feelings (id INT PRIMARY KEY, d DATE, x XML, g AS (id + 1))`)

		_, live := introspect(t, "feelings")
		require.Len(t, live.Ambiguities, 3)
		assert.Equal(t, "d", live.Ambiguities[0].Column)
		assert.Contains(t, live.Ambiguities[0].Reason, `"date"`)
		assert.Equal(t, "x", live.Ambiguities[1].Column)
		assert.Equal(t, "g", live.Ambiguities[2].Column)
	})

	// Tables and columns whose physical names differ from their canonical ones
	// must still diff as matches.
	t.Run("PhysicalNamesMapBackToCanonical", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))

		users := schema.Table{
			Name: "users", PhysicalName: "app_users",
			Columns: []schema.Column{
				{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
				{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeString, Length: 255, Unique: true},
				{Name: "name", Type: schema.ColTypeString, Length: 100, Nullable: true},
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

		registry := declare(t, users, posts)
		resolver := core.NewSchemaResolver()
		resolver.Freeze(core.BuildSchemaResolverTable(registry, core.NewMigrationConfig(core.MigrationConfig{})))
		mapped := sqlserver.NewSQLServerDriver(db, resolver)
		require.NoError(t, apply(t, mapped, "0001_test", tableOps(users, posts)...))

		exists, err := tm.TableExists(ctx, "app_users")
		require.NoError(t, err)
		require.True(t, exists)
		cols, err := tm.Columns(ctx, "app_posts")
		require.NoError(t, err)
		assert.Equal(t, "author_id", cols[1].Name)

		report, err := core.RunIntrospection(ctx, registry, mapped, true)
		require.NoError(t, err)
		require.Len(t, report.Tables, 2)
		assertNoDivergence(t, report)
		for _, f := range report.Tables["users"].Columns {
			if f.Name == "email" {
				assert.Equal(t, "email_address", f.Live.PhysicalName, "the live physical name is kept")
			}
		}
	})

	t.Run("ViewsAndMissingTables", func(t *testing.T) {
		setup(t)
		exec(t, `CREATE VIEW active_users AS SELECT * FROM users`)

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
		mapped := sqlserver.NewSQLServerDriver(db, mapResolver{tables: map[string]string{"accounts": "users"}})
		exists, err := mapped.TableExists(ctx, "accounts")
		require.NoError(t, err)
		assert.True(t, exists)
		live, err := mapped.Introspect(ctx, "accounts")
		require.NoError(t, err)
		assert.Equal(t, "accounts", live.Schema.Name)
		assert.Equal(t, "users", live.Schema.PhysicalName)
	})

	// SQL Server's own unique index allows a single NULL. The driver filters
	// NULLs out, so a nullable unique column behaves as on the other databases.
	t.Run("UniqueAllowsManyNulls", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		table := schema.Table{Name: "handles", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "handle", Type: schema.ColTypeString, Length: 40, Nullable: true, Unique: true},
			{Name: "a", Type: schema.ColTypeInteger, Nullable: true},
			{Name: "b", Type: schema.ColTypeInteger},
		}, Indexes: []schema.Index{{Name: "uq_handles_a_b", Columns: []string{"a", "b"}, Unique: true}}}
		require.NoError(t, apply(t, driver, "0001_test", tableOps(table)...))

		require.NoError(t, tm.Insert(ctx, "handles", map[string]any{"id": 1, "b": 1}))
		require.NoError(t, tm.Insert(ctx, "handles", map[string]any{"id": 2, "b": 1}), "two rows with a NULL handle and a NULL in the composite key")
		require.NoError(t, tm.Insert(ctx, "handles", map[string]any{"id": 3, "handle": "x", "a": 1, "b": 1}))
		assert.Error(t, tm.Insert(ctx, "handles", map[string]any{"id": 4, "handle": "x", "b": 2}), "set values are still unique")
		assert.Error(t, tm.Insert(ctx, "handles", map[string]any{"id": 5, "a": 1, "b": 1}), "a complete composite key is still unique")
	})

	t.Run("AlterColumnUsesPrevColumnForUniqueness", func(t *testing.T) {
		setup(t)
		prev := usersTable().Columns[2] // name
		next := prev
		next.Unique = true
		op := alterColumnOp("users", next)
		op.PrevColumn = &prev
		require.NoError(t, apply(t, driver, "0002_test", op))
		cols, _ := introspect(t, "users")
		assert.True(t, cols["name"].Unique)

		require.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 1, "email": "a@example.com", "name": "Ada"}))
		assert.Error(t, tm.Insert(ctx, "users", map[string]any{"id": 2, "email": "b@example.com", "name": "Ada"}), "UNIQUE added")

		// Without PrevColumn, uniqueness is left alone.
		require.NoError(t, apply(t, driver, "0003_test", alterColumnOp("users", prev)))
		cols, _ = introspect(t, "users")
		assert.True(t, cols["name"].Unique)

		back := alterColumnOp("users", prev)
		back.PrevColumn = &next
		require.NoError(t, apply(t, driver, "0004_test", back))
		cols, _ = introspect(t, "users")
		assert.False(t, cols["name"].Unique)
		assert.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 4, "email": "d@example.com", "name": "Ada"}), "UNIQUE dropped")
	})

	// ALTER COLUMN fails while an index or a default depends on the column.
	// The driver drops them, alters, and creates them again; unique indexes
	// get the NULL filter the new nullability calls for.
	t.Run("AlterColumnWithDependentObjects", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		code := schema.Column{Name: "code", Type: schema.ColTypeString, Length: 20, Unique: true, Default: "none"}
		table := schema.Table{Name: "items", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			code,
			{Name: "kind", Type: schema.ColTypeString, Length: 20},
		}, Indexes: []schema.Index{
			{Name: "idx_items_code_kind", Columns: []string{"code", "kind"}},
			{Name: "uq_items_kind_code", Columns: []string{"kind", "code"}, Unique: true},
			{Name: "idx_items_kind", Columns: []string{"kind"}},
		}}
		require.NoError(t, apply(t, driver, "0001_test", tableOps(table)...))
		require.NoError(t, tm.Insert(ctx, "items", map[string]any{"id": 1, "code": "12", "kind": "a"}))

		// Type, length and nullability all change; the default changes too.
		next := schema.Column{Name: "code", Type: schema.ColTypeInteger, Nullable: true, Unique: true, Default: 0}
		table.Columns[1] = next
		op := alterColumnOp("items", next)
		op.PrevColumn = &code
		require.NoError(t, apply(t, driver, "0002_test", op))

		assert.Equal(t, "int", nativeType(t, "items", "code"))
		report, err := core.RunIntrospection(ctx, declare(t, table), driver, true)
		require.NoError(t, err)
		assertNoDivergence(t, report)
		rows, err := tm.Rows(ctx, "items", "id")
		require.NoError(t, err)
		assert.Equal(t, int64(12), asInt64(rows[0]["code"]), "the value is converted")

		require.NoError(t, tm.Insert(ctx, "items", map[string]any{"id": 2, "code": nil, "kind": "a"}))
		require.NoError(t, tm.Insert(ctx, "items", map[string]any{"id": 3, "code": nil, "kind": "a"}), "code is nullable now: its unique indexes are filtered")
		assert.Error(t, tm.Insert(ctx, "items", map[string]any{"id": 4, "code": 12, "kind": "b"}), "code is still unique")
	})

	// A filtered index names its column and blocks sp_rename.
	t.Run("RenameUniqueColumn", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		table := schema.Table{Name: "people", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "nick", Type: schema.ColTypeString, Length: 40, Nullable: true, Unique: true}, // filtered unique index
			{Name: "ssn", Type: schema.ColTypeString, Length: 40, Unique: true},                  // plain unique index
		}, Indexes: []schema.Index{{Name: "uq_people_nick_ssn", Columns: []string{"nick", "ssn"}, Unique: true}}}
		require.NoError(t, apply(t, driver, "0001_test", tableOps(table)...))
		require.NoError(t, apply(t, driver, "0002_test",
			renameColumnOp("people", "nick", "nickname"),
			renameColumnOp("people", "ssn", "national_id"),
		))

		table.Columns[1].Name, table.Columns[2].Name = "nickname", "national_id"
		table.Indexes[0].Columns = []string{"nickname", "national_id"}
		report, err := core.RunIntrospection(ctx, declare(t, table), driver, true)
		require.NoError(t, err)
		assertNoDivergence(t, report)
		for _, f := range report.Tables["people"].Columns {
			assert.Equal(t, core.ColMatch, f.Kind, f.Name)
		}
		require.Len(t, report.Tables["people"].Indexes, 1)
	})

	t.Run("DropColumnWithDefault", func(t *testing.T) {
		setup(t)
		require.NoError(t, apply(t, driver, "0002_test", dropColumnOp("users", "status")))
		cols, err := tm.Columns(ctx, "users")
		require.NoError(t, err)
		assert.Len(t, cols, 3)
	})

	// IDENTITY can only change through a rebuild. Everything the migration
	// doesn't touch must come out of it as it went in.
	t.Run("RebuildPreservesTheRestOfTheTable", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		exec(t,
			`CREATE TABLE owners (id INT PRIMARY KEY)`,
			`CREATE TABLE things (
				id INT NOT NULL PRIMARY KEY,
				code VARCHAR(20) NOT NULL DEFAULT 'none',
				price MONEY NULL,
				made DATETIME NOT NULL DEFAULT GETDATE(),
				nick NVARCHAR(40) NULL,
				owner_id INT NULL,
				CONSTRAINT fk_things_owner FOREIGN KEY (owner_id) REFERENCES owners (id) ON DELETE SET NULL ON UPDATE CASCADE
			)`,
			`CREATE INDEX idx_things_code ON things (code)`,
			`CREATE UNIQUE INDEX things_nick_key ON things (nick) WHERE nick IS NOT NULL`,
			`CREATE TABLE parts (id INT PRIMARY KEY, thing_id INT NOT NULL CONSTRAINT fk_parts_thing FOREIGN KEY REFERENCES things (id) ON DELETE CASCADE)`,
			`INSERT INTO owners VALUES (1)`,
			`INSERT INTO things (id, price, owner_id) VALUES (7, 1.25, 1), (3, NULL, NULL)`,
			`INSERT INTO parts VALUES (1, 7)`,
		)

		plain := schema.Column{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true}
		serial := plain
		serial.AutoInc = true
		op := alterColumnOp("things", serial)
		op.PrevColumn = &plain
		require.NoError(t, apply(t, driver, "0001_test", op))

		cols, live := introspect(t, "things")
		assert.True(t, cols["id"].AutoInc)
		assert.True(t, cols["id"].PrimaryKey)
		assert.True(t, cols["nick"].Unique)
		assert.Equal(t, "none", cols["code"].Default)
		assert.Equal(t, "varchar", nativeType(t, "things", "code"), "untouched columns keep their native type")
		assert.Equal(t, "money", nativeType(t, "things", "price"))
		assert.Equal(t, "datetime", nativeType(t, "things", "made"))
		assert.Equal(t, []schema.Index{{Name: "idx_things_code", Columns: []string{"code"}}}, live.Schema.Indexes)

		var onUpdate string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT update_referential_action_desc FROM sys.foreign_keys WHERE name = 'fk_things_owner'`).Scan(&onUpdate))
		assert.Equal(t, "CASCADE", onUpdate, "the table's own foreign key is back, ON UPDATE included")
		fks, err := tm.ForeignKeys(ctx, "parts")
		require.NoError(t, err)
		require.Len(t, fks, 1, "the foreign key another table holds on it is back")
		assert.Equal(t, schema.FKCascade, fks[0].OnDelete)

		require.NoError(t, tm.Insert(ctx, "things", map[string]any{"code": "new"}))
		rows, err := tm.Rows(ctx, "things", "id")
		require.NoError(t, err)
		require.Len(t, rows, 3)
		assert.Equal(t, int64(8), asInt64(rows[2]["id"]), "the identity continues past the copied values")
		exists, err := tm.TableExists(ctx, "things__behemoth_rebuild")
		require.NoError(t, err)
		assert.False(t, exists)

		// A check constraint can't be carried over: the rebuild refuses, and
		// nothing changes.
		exec(t, `ALTER TABLE things ADD CONSTRAINT ck_things_price CHECK (price >= 0)`)
		back := alterColumnOp("things", plain)
		back.PrevColumn = &serial
		err = apply(t, driver, "0002_test", back)
		require.Error(t, err)
		assert.True(t, behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationRebuildFailed), err)
		cols, _ = introspect(t, "things")
		assert.True(t, cols["id"].AutoInc)
	})

	// The script is what ApplyMigration executes: run by hand against an
	// empty database, it produces the declared schema.
	t.Run("RenderedScriptReproducesApply", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		m := core.Migration{ID: "0001_test", Up: tableOps(usersTable(), sqlServerAllTypesTable())}
		script, err := driver.RenderMigration(ctx, m)
		require.NoError(t, err)
		assert.Equal(t, ".sql", driver.FileExtension())
		exists, err := tm.TableExists(ctx, "users")
		require.NoError(t, err)
		require.False(t, exists, "rendering leaves the database as it was")

		for _, stmt := range strings.Split(script, ";\n") {
			if strings.TrimSpace(stmt) != "" {
				exec(t, stmt)
			}
		}
		report, err := core.RunIntrospection(ctx, declare(t, usersTable(), sqlServerAllTypesTable()), driver, true)
		require.NoError(t, err)
		assertNoDivergence(t, report)
	})

	// A baseline's tables already exist, so its statements are built without
	// being executed.
	t.Run("RenderBaseline", func(t *testing.T) {
		setup(t)
		m := core.Migration{ID: "0000_baseline", IsBaseline: true, Up: tableOps(usersTable(), sqlServerAllTypesTable())}
		script, err := driver.RenderMigration(ctx, m)
		require.NoError(t, err)
		assert.Contains(t, script, "-- Baseline")
		assert.Contains(t, script, "CREATE TABLE [users] (")
		assert.Contains(t, script, "CREATE UNIQUE INDEX [uq_all_types_r] ON [all_types] ([r]) WHERE [r] IS NOT NULL;")
		assert.Contains(t, script, "CREATE UNIQUE INDEX [uq_all_types_i] ON [all_types] ([i]);")
	})
}
