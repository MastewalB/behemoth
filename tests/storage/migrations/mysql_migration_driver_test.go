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

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/mysql"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MySQLTestManager implements DriverTestManager for MySQL, scoped to the
// connection's default database.
type MySQLTestManager struct {
	db *sql.DB
}

func NewMySQLTestManager(db *sql.DB) *MySQLTestManager {
	return &MySQLTestManager{db: db}
}

// backtick quotes an identifier the MySQL way; quote() uses double quotes,
// which MySQL reads as a string unless ANSI_QUOTES is set.
func backtick(ident string) string {
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
}

func (m *MySQLTestManager) TableExists(ctx context.Context, table string) (bool, error) {
	var n int
	err := m.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&n)
	return n > 0, err
}

func (m *MySQLTestManager) Columns(ctx context.Context, table string) ([]ColumnInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT COLUMN_NAME, IS_NULLABLE = 'YES', COLUMN_DEFAULT IS NOT NULL OR EXTRA LIKE '%auto_increment%', COLUMN_KEY = 'PRI'
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
		ORDER BY ORDINAL_POSITION`, table)
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

func (m *MySQLTestManager) Indexes(ctx context.Context, table string) ([]IndexInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT INDEX_NAME, NON_UNIQUE = 0, COALESCE(COLUMN_NAME, '')
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
		ORDER BY INDEX_NAME, SEQ_IN_INDEX`, table)
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

func (m *MySQLTestManager) ForeignKeys(ctx context.Context, table string) ([]ForeignKeyInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT k.CONSTRAINT_NAME, r.DELETE_RULE, k.REFERENCED_TABLE_NAME, k.COLUMN_NAME, k.REFERENCED_COLUMN_NAME
		FROM information_schema.KEY_COLUMN_USAGE k
		JOIN information_schema.REFERENTIAL_CONSTRAINTS r
			ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME AND r.TABLE_NAME = k.TABLE_NAME
		WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ? AND k.REFERENCED_TABLE_NAME IS NOT NULL
		ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ForeignKeyInfo
	for rows.Next() {
		var name, rule, refTable, col, refCol string
		if err := rows.Scan(&name, &rule, &refTable, &col, &refCol); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].Name == name {
			out[n-1].Columns = append(out[n-1].Columns, col)
			out[n-1].RefColumns = append(out[n-1].RefColumns, refCol)
			continue
		}
		out = append(out, ForeignKeyInfo{
			Name: name, Columns: []string{col}, RefTable: refTable, RefColumns: []string{refCol},
			OnDelete: mysqlFKAction(rule),
		})
	}
	return out, rows.Err()
}

// mysqlFKAction maps REFERENTIAL_CONSTRAINTS.DELETE_RULE.
func mysqlFKAction(rule string) schema.ForeignKeyAction {
	switch rule {
	case "CASCADE":
		return schema.FKCascade
	case "SET NULL":
		return schema.FKSetNull
	case "RESTRICT":
		return schema.FKRestrict
	default:
		return schema.ForeignKeyAction("no_action")
	}
}

func (m *MySQLTestManager) Insert(ctx context.Context, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		quoted[i], marks[i], args[i] = backtick(c), "?", row[c]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", backtick(table), strings.Join(quoted, ", "), strings.Join(marks, ", "))
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}

func (m *MySQLTestManager) Delete(ctx context.Context, table, column string, value any) error {
	_, err := m.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s = ?", backtick(table), backtick(column)), value)
	return err
}

func (m *MySQLTestManager) Rows(ctx context.Context, table, orderBy string) ([]map[string]any, error) {
	return scanRows(m.db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s ORDER BY %s", backtick(table), backtick(orderBy))))
}

func (m *MySQLTestManager) RowCount(ctx context.Context, table string) (int64, error) {
	var n int64
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+backtick(table)).Scan(&n)
	return n, err
}

func (m *MySQLTestManager) LedgerIDs(ctx context.Context, ledgerTable string) ([]string, error) {
	if exists, err := m.TableExists(ctx, ledgerTable); err != nil || !exists {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, "SELECT id FROM "+backtick(ledgerTable)+" ORDER BY id")
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

func (m *MySQLTestManager) Snapshot(ctx context.Context, snapshotTable string) (core.SchemaSnapshot, bool, error) {
	if exists, err := m.TableExists(ctx, snapshotTable); err != nil || !exists {
		return core.SchemaSnapshot{}, false, err
	}
	var snap core.SchemaSnapshot
	var tables []byte
	err := m.db.QueryRowContext(ctx, "SELECT version, tables FROM "+backtick(snapshotTable)+" WHERE id = 1").Scan(&snap.Version, &tables)
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

// DropAllTables drops every table and view. Foreign key checks are a session
// setting, so everything runs on one connection.
func (m *MySQLTestManager) DropAllTables(ctx context.Context) error {
	conn, err := m.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	rows, err := conn.QueryContext(ctx, `SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()`)
	if err != nil {
		return err
	}
	var drops []string
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			rows.Close()
			return err
		}
		if kind == "VIEW" {
			drops = append(drops, "DROP VIEW "+backtick(name))
		} else {
			drops = append(drops, "DROP TABLE "+backtick(name))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
	for _, stmt := range drops {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (m *MySQLTestManager) CleanupDatabase(ctx context.Context) {}

// ---- MySQL-specific: introspection, normalization and best-effort apply ----

func mysqlExpr(e string) map[string]schema.ColumnOverride {
	return map[string]schema.ColumnOverride{mysql.DriverName: {Default: e}}
}

// mysqlAllTypesTable exercises every canonical type, plus the column features
// the introspector has to map back.
func mysqlAllTypesTable() schema.Table {
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
			{Name: "ts", Type: schema.ColTypeTimestamp, Overrides: mysqlExpr("now(6)")},
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},
			{Name: "j", Type: schema.ColTypeJson, Nullable: true},
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},
			{Name: "bl", Type: schema.ColTypeBlob, Nullable: true},
			{Name: "owner_id", Type: schema.ColTypeInteger, Nullable: true},
		},
		Indexes: []schema.Index{
			{Name: "idx_all_types_i_b", Columns: []string{"i", "b"}},
			{Name: "idx_all_types_t", Columns: []string{"t"}}, // TEXT: indexed by prefix
			{Name: "uq_all_types_r", Columns: []string{"r"}, Unique: true},
			{Name: "uq_all_types_r_n", Columns: []string{"r", "n"}, Unique: true},
		},
		ForeignKeys: []schema.ForeignKey{
			{Name: "fk_all_types_owner", Columns: []string{"owner_id"}, RefTable: "users", RefColumns: []string{"id"}, OnDelete: schema.FKSetNull},
		},
	}
}

// tableOps builds a table the way a generated migration does: the table, then
// its indexes and foreign keys as their own operations.
func tableOps(tables ...schema.Table) []core.SchemaOperation {
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
	return ops
}

func declare(t *testing.T, tables ...schema.Table) *schema.DefaultRegistry {
	t.Helper()
	registry := schema.NewRegistry()
	for _, table := range tables {
		require.NoError(t, registry.Declare(tableModel{name: table.Name}, table))
	}
	require.NoError(t, registry.Freeze())
	return registry
}

func columnKinds(report *core.IntrospectionReport, table string) map[string]core.ColumnDivergenceKind {
	kinds := map[string]core.ColumnDivergenceKind{}
	for _, f := range report.Tables[table].Columns {
		kinds[f.Name] = f.Kind
	}
	return kinds
}

func assertNoDivergence(t *testing.T, report *core.IntrospectionReport) {
	t.Helper()
	for name, ti := range report.Tables {
		assert.True(t, ti.ExistsLive, name)
		assert.Empty(t, ti.Renames, name)
		for _, f := range ti.Columns {
			assert.Equal(t, core.ColMatch, f.Kind, "%s.%s: declared %+v, live %+v", name, f.Name, f.Declared, f.Live)
		}
		for _, f := range ti.Indexes {
			assert.Equal(t, core.IdxMatch, f.Kind, "%s index %s", name, f.Name)
		}
		for _, f := range ti.ForeignKeys {
			assert.Equal(t, core.FKMatch, f.Kind, "%s fk %s", name, f.Name)
		}
	}
}

func runMySQLDriverTests(t *testing.T, db *sql.DB, tm *MySQLTestManager) {
	ctx := context.Background()
	driver := mysql.NewMySQLDriver(db, nil)

	apply := func(t *testing.T, d *mysql.MySQLDriver, id string, ops ...core.SchemaOperation) error {
		t.Helper()
		return d.ApplyMigration(ctx, request(core.Migration{ID: id, Up: ops}, nil))
	}
	setup := func(t *testing.T) {
		t.Helper()
		require.NoError(t, tm.DropAllTables(ctx))
		require.NoError(t, apply(t, driver, "0001_test", tableOps(usersTable(), mysqlAllTypesTable())...))
	}
	columnsOf := func(t *testing.T, table string) map[string]schema.Column {
		t.Helper()
		live, err := driver.Introspect(ctx, table)
		require.NoError(t, err)
		cols := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			cols[c.Name] = c
		}
		return cols
	}

	t.Run("IntrospectRoundTripsDeclaredSchema", func(t *testing.T) {
		setup(t)
		declared := mysqlAllTypesTable()
		live, err := driver.Introspect(ctx, "all_types")
		require.NoError(t, err)
		require.True(t, live.Exists)
		assert.Equal(t, core.ObjectTable, live.Kind)
		assert.Empty(t, live.Ambiguities)

		// What MySQL can't keep apart reads back collapsed.
		collapsed := map[string]schema.ColumnType{"ts": schema.ColTypeDateTime, "u": schema.ColTypeString, "by": schema.ColTypeBlob}
		require.Len(t, live.Schema.Columns, len(declared.Columns))
		byName := map[string]schema.Column{}
		for i, want := range declared.Columns {
			got := live.Schema.Columns[i]
			byName[got.Name] = got
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
		assert.Equal(t, 40, byName["s"].Length)
		assert.Equal(t, 36, byName["u"].Length, "a uuid is CHAR(36)")
		assert.Zero(t, byName["t"].Length, "only strings carry a length")
		assert.Equal(t, "it's", byName["t"].Default, "a TEXT default is an expression, read back as the literal it is")
		assert.Equal(t, int64(7), byName["i"].Default)
		assert.Equal(t, true, byName["b"].Default)
		assert.Equal(t, "now(6)", byName["ts"].Overrides[mysql.DriverName].Default, "expression default is kept verbatim")
		assert.Nil(t, byName["ts"].Default)

		assert.ElementsMatch(t, declared.Indexes, live.Schema.Indexes, "the primary key, unique-column keys and the foreign key's own index are excluded")
		assert.Equal(t, declared.ForeignKeys, live.Schema.ForeignKeys)
	})

	// The real contract: what the driver creates, the introspector reads back
	// with no divergence, so a generate-only run right after produces nothing.
	t.Run("NoDivergenceAgainstDeclaredRegistry", func(t *testing.T) {
		setup(t)
		report, err := core.RunIntrospection(ctx, declare(t, usersTable(), mysqlAllTypesTable()), driver, true)
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
			{Name: "s", Type: schema.ColTypeString},                                                   // VARCHAR(255)
			{Name: "by", Type: schema.ColTypeBytes, Nullable: true},                                   // LONGBLOB, reads back as blob
			{Name: "t", Type: schema.ColTypeText, Length: 10, Nullable: true},                         // LONGTEXT has no length
			{Name: "u", Type: schema.ColTypeUuid, Nullable: true},                                     // CHAR(36), reads back as string(36)
			{Name: "ts", Type: schema.ColTypeTimestamp, Nullable: true},                               // DATETIME(6), reads back as datetime
			{Name: "o", Type: schema.ColTypeString, Length: 40, Nullable: true, // override: LONGTEXT
				Overrides: map[string]schema.ColumnOverride{mysql.DriverName: {Type: schema.ColTypeText}}},
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
		_, err := db.ExecContext(ctx, `CREATE TABLE changed (id INT PRIMARY KEY, s VARCHAR(255) NOT NULL, n LONGTEXT NOT NULL, b LONGBLOB NOT NULL)`)
		require.NoError(t, err)
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

	// Defaults as MySQL stores them still match their declarations: literals
	// unquoted, booleans as 1/0, TEXT and JSON literals as escaped expressions
	// with a charset introducer, function names lower-cased, CURRENT_TIMESTAMP
	// as now(), expressions re-spaced.
	t.Run("DefaultsMatch", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		defaults := schema.Table{Name: "defaults", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "neg", Type: schema.ColTypeInteger, Default: -1},
			{Name: "big", Type: schema.ColTypeBigInt, Default: int64(-5)},
			{Name: "json_num", Type: schema.ColTypeInteger, Default: float64(7)}, // as read back from a migration file
			{Name: "dbl", Type: schema.ColTypeReal, Default: 1.5},
			{Name: "num", Type: schema.ColTypeNumeric, Default: 1.5}, // stored with 30 decimals
			{Name: "b", Type: schema.ColTypeBoolean, Default: false},
			{Name: "s", Type: schema.ColTypeString, Length: 10, Default: "it's"},
			{Name: "s_empty", Type: schema.ColTypeString, Length: 10, Default: ""},
			{Name: "s_bs", Type: schema.ColTypeString, Length: 10, Default: `a\b`},
			{Name: "t", Type: schema.ColTypeText, Default: `it's a\b`},
			{Name: "t_num", Type: schema.ColTypeText, Default: -1},
			{Name: "j_lit", Type: schema.ColTypeJson, Default: "{}"},
			{Name: "ts_upper", Type: schema.ColTypeTimestamp, Overrides: mysqlExpr("NOW(6)")},
			{Name: "ts_keyword", Type: schema.ColTypeTimestamp, Overrides: mysqlExpr("CURRENT_TIMESTAMP(6)")},
			{Name: "ts_bare", Type: schema.ColTypeDateTime, Overrides: mysqlExpr("current_timestamp")},
			{Name: "u", Type: schema.ColTypeUuid, Overrides: mysqlExpr("UUID()")},
			{Name: "j", Type: schema.ColTypeJson, Overrides: mysqlExpr("JSON_OBJECT()")},
			{Name: "s_expr", Type: schema.ColTypeString, Length: 10, Overrides: mysqlExpr("'x'")},
			{Name: "sum", Type: schema.ColTypeInteger, Overrides: mysqlExpr("(1+1)")},
			{Name: "none", Type: schema.ColTypeText, Nullable: true},
		}}
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(defaults)))

		report, err := core.RunIntrospection(ctx, declare(t, defaults), driver, true)
		require.NoError(t, err)
		require.Len(t, report.Tables["defaults"].Columns, len(defaults.Columns))
		for _, f := range report.Tables["defaults"].Columns {
			assert.Equal(t, core.ColMatch, f.Kind, "%s: declared %#v %v, live %#v %v", f.Name, f.Declared.Default, f.Declared.Overrides, f.Live.Default, f.Live.Overrides)
		}

		// The defaults are the declared values, not just something that compares equal.
		require.NoError(t, tm.Insert(ctx, "defaults", map[string]any{"id": 1}))
		rows, err := tm.Rows(ctx, "defaults", "id")
		require.NoError(t, err)
		assert.Equal(t, `it's a\b`, asString(rows[0]["t"]))
		assert.Equal(t, `a\b`, asString(rows[0]["s_bs"]))
		assert.Equal(t, "-1", asString(rows[0]["t_num"]))
		assert.Equal(t, int64(2), asInt64(rows[0]["sum"]))
	})

	t.Run("DefaultChangesDiffer", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `CREATE TABLE changed (id INT PRIMARY KEY, kept VARCHAR(10) NOT NULL DEFAULT 'a', changed VARCHAR(10) NOT NULL DEFAULT 'a', removed DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6))`)
		require.NoError(t, err)
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

	// A table nobody created through the driver: MySQL's own key names, a
	// TIMESTAMP column, a functional index and an unnamed foreign key.
	t.Run("ExistingDatabase", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		for _, stmt := range []string{
			`CREATE TABLE parents (id INT PRIMARY KEY)`,
			`CREATE TABLE legacy (
				a INT, b INT,
				seq BIGINT NOT NULL AUTO_INCREMENT UNIQUE,
				email VARCHAR(100) NOT NULL UNIQUE,
				note TEXT,
				flag BOOLEAN NOT NULL DEFAULT TRUE,
				small TINYINT NOT NULL DEFAULT 3,
				created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				parent_id INT,
				PRIMARY KEY (a, b),
				KEY idx_legacy_note (note(20)),
				KEY idx_legacy_expr ((lower(email))),
				FOREIGN KEY (parent_id) REFERENCES parents (id)
			)`,
		} {
			_, err := db.ExecContext(ctx, stmt)
			require.NoError(t, err)
		}

		live, err := driver.Introspect(ctx, "legacy")
		require.NoError(t, err)
		assert.Empty(t, live.Ambiguities)
		cols := map[string]schema.Column{}
		for _, c := range live.Schema.Columns {
			cols[c.Name] = c
		}
		assert.True(t, cols["a"].PrimaryKey)
		assert.True(t, cols["b"].PrimaryKey)
		assert.False(t, cols["a"].Nullable, "primary key columns are NOT NULL")
		assert.True(t, cols["seq"].AutoInc)
		assert.True(t, cols["seq"].Unique, "an inline UNIQUE key is named after its column")
		assert.True(t, cols["email"].Unique)
		assert.Equal(t, 100, cols["email"].Length)
		assert.Equal(t, schema.ColTypeText, cols["note"].Type)
		assert.Equal(t, schema.ColTypeBoolean, cols["flag"].Type, "BOOLEAN is TINYINT(1)")
		assert.Equal(t, true, cols["flag"].Default)
		assert.Equal(t, schema.ColTypeInteger, cols["small"].Type, "any other TINYINT is an integer")
		assert.Equal(t, int64(3), cols["small"].Default)
		assert.Equal(t, schema.ColTypeDateTime, cols["created"].Type, "TIMESTAMP reads back as datetime")
		assert.Equal(t, "now()", cols["created"].Overrides[mysql.DriverName].Default, "CURRENT_TIMESTAMP is spelled as the driver would store it")

		assert.Equal(t, []schema.Index{{Name: "idx_legacy_note", Columns: []string{"note"}}}, live.Schema.Indexes,
			"functional indexes can't be represented; the foreign key's own index is not an index of the model")
		require.Len(t, live.Schema.ForeignKeys, 1)
		fk := live.Schema.ForeignKeys[0]
		assert.Equal(t, []string{"parent_id"}, fk.Columns)
		assert.Equal(t, "parents", fk.RefTable)
		assert.Equal(t, schema.FKRestrict, fk.OnDelete, "NO ACTION collapses to restrict")
	})

	t.Run("UnknownTypesAreAmbiguous", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		_, err := db.ExecContext(ctx, `CREATE TABLE feelings (id INT PRIMARY KEY, m ENUM('ok', 'meh'), d DATE, g INT GENERATED ALWAYS AS (id + 1) STORED)`)
		require.NoError(t, err)

		live, err := driver.Introspect(ctx, "feelings")
		require.NoError(t, err)
		require.Len(t, live.Ambiguities, 3)
		assert.Equal(t, "m", live.Ambiguities[0].Column)
		assert.Contains(t, live.Ambiguities[0].Reason, "enum('ok','meh')")
		assert.Equal(t, "d", live.Ambiguities[1].Column)
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

		registry := declare(t, users, posts)
		resolver := core.NewSchemaResolver()
		resolver.Freeze(core.BuildSchemaResolverTable(registry, core.NewMigrationConfig(core.MigrationConfig{})))
		mapped := mysql.NewMySQLDriver(db, resolver)
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
		mapped := mysql.NewMySQLDriver(db, mapResolver{tables: map[string]string{"accounts": "users"}})
		exists, err := mapped.TableExists(ctx, "accounts")
		require.NoError(t, err)
		assert.True(t, exists)
		live, err := mapped.Introspect(ctx, "accounts")
		require.NoError(t, err)
		assert.Equal(t, "accounts", live.Schema.Name)
		assert.Equal(t, "users", live.Schema.PhysicalName)
	})

	// name is TEXT, so its unique key covers a prefix.
	t.Run("AlterColumnUsesPrevColumnForUniqueness", func(t *testing.T) {
		setup(t)
		prev := schema.Column{Name: "name", Type: schema.ColTypeText, Nullable: true}
		next := schema.Column{Name: "name", Type: schema.ColTypeText, Nullable: true, Unique: true}
		op := alterColumnOp("users", next)
		op.PrevColumn = &prev
		require.NoError(t, apply(t, driver, "0002_test", op))
		assert.True(t, columnsOf(t, "users")["name"].Unique)

		require.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 1, "email": "a@example.com", "name": "Ada"}))
		assert.Error(t, tm.Insert(ctx, "users", map[string]any{"id": 2, "email": "b@example.com", "name": "Ada"}), "UNIQUE added")

		back := alterColumnOp("users", prev)
		back.PrevColumn = &next
		require.NoError(t, apply(t, driver, "0003_test", back))
		assert.False(t, columnsOf(t, "users")["name"].Unique)
		assert.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 4, "email": "d@example.com", "name": "Ada"}), "UNIQUE dropped")
	})

	// An index on a TEXT or BLOB column needs a prefix length. The type comes
	// from the migration's own operations when it defines the column, and
	// from the live table otherwise.
	t.Run("IndexesOnTextColumnsGetAPrefix", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		docs := schema.Table{Name: "docs", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "title", Type: schema.ColTypeString, Length: 80},
			{Name: "body", Type: schema.ColTypeText, Nullable: true},
			{Name: "raw", Type: schema.ColTypeBytes, Nullable: true},
		}}
		m := core.Migration{ID: "0001_test", Up: []core.SchemaOperation{
			createTableOp(docs),
			addIndexOp("docs", schema.Index{Name: "idx_docs_title_body", Columns: []string{"title", "body"}}),
			renameColumnOp("docs", "body", "content"),
			addIndexOp("docs", schema.Index{Name: "idx_docs_content", Columns: []string{"content"}}),
		}}

		// Rendered before the table exists: nothing can be looked up live.
		script, err := driver.RenderMigration(ctx, m)
		require.NoError(t, err)
		assert.Contains(t, script, "CREATE INDEX `idx_docs_title_body` ON `docs` (`title`, `body`(255));")
		assert.Contains(t, script, "CREATE INDEX `idx_docs_content` ON `docs` (`content`(255));")
		require.NoError(t, driver.ApplyMigration(ctx, request(m, nil)))

		// A later migration knows nothing about the columns: looked up live.
		later := core.Migration{ID: "0002_test", Up: []core.SchemaOperation{
			addIndexOp("docs", schema.Index{Name: "uq_docs_raw_title", Columns: []string{"raw", "title"}, Unique: true}),
		}}
		script, err = driver.RenderMigration(ctx, later)
		require.NoError(t, err)
		assert.Contains(t, script, "CREATE UNIQUE INDEX `uq_docs_raw_title` ON `docs` (`raw`(255), `title`);")
		require.NoError(t, driver.ApplyMigration(ctx, request(later, nil)))

		live, err := driver.Introspect(ctx, "docs")
		require.NoError(t, err)
		assert.ElementsMatch(t, []schema.Index{
			{Name: "idx_docs_title_body", Columns: []string{"title", "content"}},
			{Name: "idx_docs_content", Columns: []string{"content"}},
			{Name: "uq_docs_raw_title", Columns: []string{"raw", "title"}, Unique: true},
		}, live.Schema.Indexes)
	})

	// The script is what ApplyMigration executes: run by hand against an
	// empty database, it produces the declared schema.
	t.Run("RenderedScriptReproducesApply", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		m := core.Migration{ID: "0001_test", Up: tableOps(usersTable(), mysqlAllTypesTable())}
		script, err := driver.RenderMigration(ctx, m)
		require.NoError(t, err)
		assert.Equal(t, ".sql", driver.FileExtension())

		for _, stmt := range strings.Split(script, ";\n") {
			if stmt = strings.TrimSpace(stmt); stmt == "" {
				continue
			}
			_, err := db.ExecContext(ctx, stmt)
			require.NoError(t, err, stmt)
		}

		report, err := core.RunIntrospection(ctx, declare(t, usersTable(), mysqlAllTypesTable()), driver, true)
		require.NoError(t, err)
		assertNoDivergence(t, report)
	})

	// MySQL commits DDL as it runs. A migration that fails midway keeps what
	// already ran, is not recorded, and says so.
	t.Run("FailedMigrationKeepsEarlierOperations", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		assert.Equal(t, core.AtomicityBestEffort, driver.AtomicityLevel())

		err := apply(t, driver, "0001_test",
			createTableOp(usersTable()),
			addColumnOp("does_not_exist", schema.Column{Name: "x", Type: schema.ColTypeText, Nullable: true}),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create_table_users", "the error names the operations that stay applied")
		assert.Contains(t, err.Error(), "not recorded")

		exists, err := tm.TableExists(ctx, "users")
		require.NoError(t, err)
		assert.True(t, exists, "DDL before the failing operation is not rolled back")
		ids, err := tm.LedgerIDs(ctx, ledgerTable)
		require.NoError(t, err)
		assert.Empty(t, ids, "no ledger entry for a failed migration")
		_, found, err := tm.Snapshot(ctx, snapshotTable)
		require.NoError(t, err)
		assert.False(t, found, "no snapshot for a failed migration")
	})

	// A recorded migration is rejected before any of its DDL runs, since that
	// DDL could not be undone when the ledger insert fails afterwards.
	t.Run("RecordedMigrationRunsNoDDL", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(usersTable())))
		require.Error(t, apply(t, driver, "0001_test", createTableOp(postsTable())))

		exists, err := tm.TableExists(ctx, "posts")
		require.NoError(t, err)
		assert.False(t, exists)

		m := core.Migration{ID: "0001_test", IsBaseline: true}
		assert.Error(t, driver.RecordBaseline(ctx, request(m, nil)), "a baseline can't be recorded twice either")
	})

	// A malformed migration is rejected before its first statement.
	t.Run("MalformedMigrationRunsNoDDL", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		require.Error(t, apply(t, driver, "0001_test",
			createTableOp(usersTable()),
			core.SchemaOperation{ID: "bogus", Kind: core.OperationKind("bogus"), Table: "users"},
		))
		exists, err := tm.TableExists(ctx, "users")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	// MySQL would fill existing rows of a new NOT NULL column with '' or 0.
	// The driver refuses instead; with a default, or on an empty table, it's fine.
	t.Run("AddNotNullColumnWithoutDefault", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(usersTable())))
		required := schema.Column{Name: "required", Type: schema.ColTypeInteger}
		require.NoError(t, apply(t, driver, "0002_test", addColumnOp("users", required)), "an empty table has no rows to fill")
		require.NoError(t, apply(t, driver, "0003_test", dropColumnOp("users", "required")))

		require.NoError(t, tm.Insert(ctx, "users", map[string]any{"id": 1, "email": "a@example.com"}))
		err := apply(t, driver, "0004_test", addColumnOp("users", required))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has rows")
		cols, err := tm.Columns(ctx, "users")
		require.NoError(t, err)
		assert.Len(t, cols, 4, "the column was not added")
	})

	// The unique key of a unique column has a fixed name. MySQL rejects names
	// over 64 characters, so a long one is shortened and still found again.
	t.Run("LongUniqueKeyNames", func(t *testing.T) {
		require.NoError(t, tm.DropAllTables(ctx))
		long := schema.Table{Name: "a_table_with_quite_a_long_name_for_a_table", Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeInteger, PrimaryKey: true},
			{Name: "a_column_with_quite_a_long_name_too", Type: schema.ColTypeString, Length: 40, Unique: true},
		}}
		require.NoError(t, apply(t, driver, "0001_test", createTableOp(long)))
		assert.True(t, columnsOf(t, long.Name)[long.Columns[1].Name].Unique)

		prev, next := long.Columns[1], long.Columns[1]
		next.Unique = false
		op := alterColumnOp(long.Name, next)
		op.PrevColumn = &prev
		require.NoError(t, apply(t, driver, "0002_test", op))
		assert.False(t, columnsOf(t, long.Name)[next.Name].Unique)
	})
}
