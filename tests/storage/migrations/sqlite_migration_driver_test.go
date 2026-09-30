package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/migration/plugins/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
)

// openSQLite opens a file-backed database (":memory:" would give every pooled
// connection its own empty database) with foreign key enforcement on.
func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "migrations.db") + "?_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// SQLiteTestManager implements DriverTestManager for SQLite.
type SQLiteTestManager struct {
	db *sql.DB
}

func NewSQLiteTestManager(db *sql.DB) *SQLiteTestManager {
	return &SQLiteTestManager{db: db}
}

func (h *SQLiteTestManager) TableExists(ctx context.Context, table string) (bool, error) {
	var n int
	err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&n)
	return n > 0, err
}

func (h *SQLiteTestManager) Columns(ctx context.Context, table string) ([]ColumnInfo, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT name, "notnull", pk, dflt_value IS NOT NULL FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		var notNull, pk int
		if err := rows.Scan(&c.Name, &notNull, &pk, &c.HasDefault); err != nil {
			return nil, err
		}
		c.Nullable, c.PrimaryKey = notNull == 0, pk > 0
		out = append(out, c)
	}
	return out, rows.Err()
}

func (h *SQLiteTestManager) Indexes(ctx context.Context, table string) ([]IndexInfo, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT name, "unique" FROM pragma_index_list(?)`, table)
	if err != nil {
		return nil, err
	}
	var out []IndexInfo
	for rows.Next() {
		var idx IndexInfo
		if err := rows.Scan(&idx.Name, &idx.Unique); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, idx)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		cols, err := h.strings(ctx, "SELECT name FROM pragma_index_info(?) ORDER BY seqno", out[i].Name)
		if err != nil {
			return nil, err
		}
		out[i].Columns = cols
	}
	return out, nil
}

// fkNamePattern recovers constraint names from the stored CREATE TABLE,
// since PRAGMA foreign_key_list doesn't report them. It matches the form the
// driver emits: CONSTRAINT "name" FOREIGN KEY ("col", ...).
var fkNamePattern = regexp.MustCompile(`(?i)CONSTRAINT\s+"((?:[^"]|"")+)"\s+FOREIGN\s+KEY\s*\(([^)]*)\)`)

func (h *SQLiteTestManager) ForeignKeys(ctx context.Context, table string) ([]ForeignKeyInfo, error) {
	var createSQL string
	if err := h.db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&createSQL); err != nil {
		return nil, err
	}
	namesByCols := map[string]string{}
	for _, m := range fkNamePattern.FindAllStringSubmatch(createSQL, -1) {
		namesByCols[normalizeColList(m[2])] = strings.ReplaceAll(m[1], `""`, `"`)
	}

	rows, err := h.db.QueryContext(ctx, `SELECT id, "table", "from", "to", on_delete FROM pragma_foreign_key_list(?) ORDER BY id, seq`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byID := map[int]*ForeignKeyInfo{}
	var order []int
	for rows.Next() {
		var id int
		var refTable, from, onDelete string
		var to sql.NullString
		if err := rows.Scan(&id, &refTable, &from, &to, &onDelete); err != nil {
			return nil, err
		}
		fk, ok := byID[id]
		if !ok {
			fk = &ForeignKeyInfo{RefTable: refTable, OnDelete: sqliteFKAction(onDelete)}
			byID[id] = fk
			order = append(order, id)
		}
		fk.Columns = append(fk.Columns, from)
		fk.RefColumns = append(fk.RefColumns, to.String)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ForeignKeyInfo, 0, len(order))
	for _, id := range order {
		fk := byID[id]
		fk.Name = namesByCols[strings.ToLower(strings.Join(fk.Columns, ","))]
		out = append(out, *fk)
	}
	return out, nil
}

func normalizeColList(list string) string {
	parts := strings.Split(list, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"`[]")
		parts[i] = strings.ToLower(p)
	}
	return strings.Join(parts, ",")
}

func sqliteFKAction(a string) core.ForeignKeyAction {
	switch strings.ToUpper(a) {
	case "CASCADE":
		return core.FKCascade
	case "SET NULL":
		return core.FKSetNull
	case "RESTRICT":
		return core.FKRestrict
	default:
		return core.ForeignKeyAction(strings.ToLower(a))
	}
}

func (h *SQLiteTestManager) Insert(ctx context.Context, table string, row map[string]any) error {
	cols := make([]string, 0, len(row))
	for c := range row {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		quoted[i], marks[i], args[i] = quote(c), "?", row[c]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", quote(table), strings.Join(quoted, ", "), strings.Join(marks, ", "))
	_, err := h.db.ExecContext(ctx, query, args...)
	return err
}

func (h *SQLiteTestManager) Delete(ctx context.Context, table, column string, value any) error {
	_, err := h.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s = ?", quote(table), quote(column)), value)
	return err
}

func (h *SQLiteTestManager) Rows(ctx context.Context, table, orderBy string) ([]map[string]any, error) {
	return scanRows(h.db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s ORDER BY %s", quote(table), quote(orderBy))))
}

func (h *SQLiteTestManager) RowCount(ctx context.Context, table string) (int64, error) {
	var n int64
	err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quote(table)).Scan(&n)
	return n, err
}

func (h *SQLiteTestManager) LedgerIDs(ctx context.Context, ledgerTable string) ([]string, error) {
	if exists, err := h.TableExists(ctx, ledgerTable); err != nil || !exists {
		return nil, err
	}
	return h.strings(ctx, "SELECT id FROM "+quote(ledgerTable)+" ORDER BY id")
}

func (h *SQLiteTestManager) Snapshot(ctx context.Context, snapshotTable string) (core.SchemaSnapshot, bool, error) {
	if exists, err := h.TableExists(ctx, snapshotTable); err != nil || !exists {
		return core.SchemaSnapshot{}, false, err
	}
	var snap core.SchemaSnapshot
	var tables string
	err := h.db.QueryRowContext(ctx, "SELECT version, tables FROM "+quote(snapshotTable)+" WHERE id = 1").Scan(&snap.Version, &tables)
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

// DropAllTables disables foreign keys on a dedicated connection so tables can
// be dropped in any order.
func (h *SQLiteTestManager) DropAllTables(ctx context.Context) error {
	conn, err := h.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON")

	rows, err := conn.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	rows.Close()

	for _, name := range tables {
		if _, err := conn.ExecContext(ctx, "DROP TABLE "+quote(name)); err != nil {
			return err
		}
	}
	return nil
}

func (h *SQLiteTestManager) CleanupDatabase(ctx context.Context) {}

func (h *SQLiteTestManager) strings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v.String)
	}
	return out, rows.Err()
}

func quote(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

func scanRows(rows *sql.Rows, err error) ([]map[string]any, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = values[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---- SQLite-specific behavior ----
//
// The agnostic suite covers every operation; these pin down details only the
// SQLite table-rebuild path can get wrong.

func newSQLiteFixture(t *testing.T) (context.Context, *sql.DB, *sqlite.SQLiteDriver, func(...core.SchemaOperation) error) {
	ctx := context.Background()
	db := openSQLite(t)
	driver := sqlite.NewSQLiteDriver(db, nil)
	seq := 0
	apply := func(ops ...core.SchemaOperation) error {
		seq++
		return driver.ApplyMigration(ctx, request(core.Migration{ID: fmt.Sprintf("%04d_test", seq), Up: ops}, nil))
	}
	return ctx, db, driver, apply
}

func TestSQLiteRebuildPreservesUnmanagedSchema(t *testing.T) {
	ctx, db, _, apply := newSQLiteFixture(t)

	// A hand-written table with things the driver never emits itself.
	_, err := db.ExecContext(ctx, `CREATE TABLE accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		code TEXT COLLATE NOCASE NOT NULL CHECK (length(code) = 3), -- comment, with a comma
		balance NUMERIC NOT NULL DEFAULT 0,
		note TEXT,
		CONSTRAINT balance_positive CHECK (balance >= 0)
	)`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TABLE audit (account_id INTEGER, what TEXT)`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TRIGGER accounts_audit AFTER INSERT ON accounts BEGIN INSERT INTO audit VALUES (NEW.id, 'insert'); END`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO accounts (code, balance) VALUES ('abc', 1), ('def', 2)`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `DELETE FROM accounts WHERE id = 2`) // sequence stays at 2
	require.NoError(t, err)

	require.NoError(t, apply(alterColumnOp("accounts", core.Column{Name: "note", Type: core.ColTypeText, Nullable: true, Default: "n/a"})))

	var createSQL string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE name = 'accounts'").Scan(&createSQL))
	assert.Contains(t, createSQL, "AUTOINCREMENT")
	assert.Contains(t, createSQL, "COLLATE NOCASE")
	assert.Contains(t, createSQL, "length(code) = 3")
	assert.Contains(t, createSQL, "balance_positive")

	_, err = db.ExecContext(ctx, `INSERT INTO accounts (code, balance) VALUES ('toolong', 1)`)
	assert.Error(t, err, "column CHECK survives")
	_, err = db.ExecContext(ctx, `INSERT INTO accounts (code, balance) VALUES ('ghi', -1)`)
	assert.Error(t, err, "table CHECK survives")

	_, err = db.ExecContext(ctx, `INSERT INTO accounts (code, balance) VALUES ('ghi', 1)`)
	require.NoError(t, err)
	var id int64
	var note string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT id, note FROM accounts WHERE code = 'GHI'").Scan(&id, &note))
	assert.Equal(t, int64(3), id, "AUTOINCREMENT does not reuse the deleted id")
	assert.Equal(t, "n/a", note, "new default applies")

	var audits int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit").Scan(&audits))
	assert.Equal(t, 3, audits, "trigger survives the rebuild")
}

func TestSQLiteRebuildLeavesNoTemporaryTable(t *testing.T) {
	ctx, db, _, apply := newSQLiteFixture(t)
	require.NoError(t, apply(createTableOp(usersTable())))
	require.NoError(t, apply(alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText, Nullable: true, Default: "x"})))

	var n int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '_behemoth_rebuild_%'").Scan(&n))
	assert.Zero(t, n)
}

func TestSQLiteRestoresForeignKeyEnforcement(t *testing.T) {
	ctx, db, _, apply := newSQLiteFixture(t)
	db.SetMaxOpenConns(1) // the driver's connection is the only one; it must come back with FKs on

	require.NoError(t, apply(createTableOp(usersTable()), createTableOp(postsTable())))
	require.NoError(t, apply(addForeignKeyOp("posts", postsUserFK(core.FKCascade))))

	var enabled bool
	require.NoError(t, db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled))
	assert.True(t, enabled)
}

func TestSQLiteDeclaredTypes(t *testing.T) {
	ctx, db, _, apply := newSQLiteFixture(t)
	require.NoError(t, apply(createTableOp(core.TableSchema{
		Name: "typed",
		Columns: []core.Column{
			{Name: "id", Type: core.ColTypeInteger, PrimaryKey: true},
			{Name: "s", Type: core.ColTypeString, Length: 40},
			{Name: "flag", Type: core.ColTypeBoolean},
			{Name: "at", Type: core.ColTypeTimestamp},
			{Name: "doc", Type: core.ColTypeJson},
			{Name: "uid", Type: core.ColTypeUuid, Overrides: map[string]core.ColumnOverride{
				sqlite.DriverName: {Type: core.ColTypeText},
			}},
			{Name: "created", Type: core.ColTypeDateTime, Overrides: map[string]core.ColumnOverride{
				sqlite.DriverName: {Default: "CURRENT_TIMESTAMP"},
			}},
		},
	})))

	rows, err := db.QueryContext(ctx, "SELECT name, type, dflt_value FROM pragma_table_info('typed')")
	require.NoError(t, err)
	defer rows.Close()
	types, defaults := map[string]string{}, map[string]string{}
	for rows.Next() {
		var name, typ string
		var dflt sql.NullString
		require.NoError(t, rows.Scan(&name, &typ, &dflt))
		types[name], defaults[name] = typ, dflt.String
	}

	assert.Equal(t, map[string]string{
		"id": "INTEGER", "s": "VARCHAR(40)", "flag": "BOOLEAN", "at": "TIMESTAMP",
		"doc": "TEXT", "uid": "TEXT", "created": "DATETIME",
	}, types)
	assert.Equal(t, "CURRENT_TIMESTAMP", defaults["created"], "override default is a raw expression")
}

func TestSQLiteAutoIncrementRequiresSinglePrimaryKey(t *testing.T) {
	_, _, _, apply := newSQLiteFixture(t)
	err := apply(createTableOp(core.TableSchema{
		Name: "bad",
		Columns: []core.Column{
			{Name: "a", Type: core.ColTypeInteger, PrimaryKey: true, AutoInc: true},
			{Name: "b", Type: core.ColTypeInteger, PrimaryKey: true},
		},
	}))
	assert.Error(t, err)
}
