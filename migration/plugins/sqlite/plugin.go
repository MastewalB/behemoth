package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
)

// DriverName is the key used for per-database Column.Overrides lookups.
const DriverName = "sqlite"

// SQLiteDriver implements [core.SchemaDriver] for SQLite.
//
// The driver never imports a database/sql driver itself: the caller picks one
// (mattn/go-sqlite3, modernc.org/sqlite, ...) and hands over an opened *sql.DB.
//
// SQLite's ALTER TABLE only supports RENAME TABLE, RENAME COLUMN, ADD COLUMN
// (with restrictions) and DROP COLUMN (with restrictions). Every other change
// (altering a column, adding/dropping a foreign key, adding a UNIQUE/PK column,
// dropping a constrained column) is performed with the table-rebuild procedure
// documented at https://www.sqlite.org/lang_altertable.html#otheralter; see rebuild.go.
type SQLiteDriver struct {
	db       *sql.DB
	resolver core.SchemaResolver
}

// NewSQLiteDriver returns a driver bound to db. A nil resolver maps every
// canonical table/column name to itself.
func NewSQLiteDriver(db *sql.DB, resolver core.SchemaResolver) *SQLiteDriver {
	if resolver == nil {
		resolver = identityResolver{}
	}
	return &SQLiteDriver{db: db, resolver: resolver}
}

var _ core.SchemaDriver = (*SQLiteDriver)(nil)

type identityResolver struct{}

func (identityResolver) Resolve(canonical string) string                 { return canonical }
func (identityResolver) ResolveColumn(_ string, canonical string) string { return canonical }

// execQuerier is satisfied by *sql.Tx — every DDL helper runs inside the
// migration's transaction, since rebuilds need to read the live schema too.
type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// AtomicityLevel implements [core.SchemaDriver]. SQLite DDL is fully transactional.
func (d *SQLiteDriver) AtomicityLevel() core.AtomicityLevel { return core.AtomicityFull }

// ApplyMigration implements [core.SchemaDriver]: every Up operation, the
// ledger row and the snapshot upsert commit or roll back together.
func (d *SQLiteDriver) ApplyMigration(ctx context.Context, req core.MigrationRequest) error {
	return d.inMigrationTx(ctx, "SQLiteDriver.ApplyMigration", false, func(tx *sql.Tx) error {
		for _, op := range req.Migration.Up {
			if err := d.applyOperation(ctx, tx, op); err != nil {
				return behemotherr.WrapOp("SQLiteDriver.ApplyMigration", fmt.Sprintf("operation %q (%s on %s)", op.ID, op.Kind, op.Table), err)
			}
		}
		return d.recordTx(ctx, tx, req)
	})
}

// RecordBaseline implements [core.SchemaDriver]: the same ledger+snapshot
// write as ApplyMigration, with no DDL executed.
func (d *SQLiteDriver) RecordBaseline(ctx context.Context, req core.MigrationRequest) error {
	return d.inMigrationTx(ctx, "SQLiteDriver.RecordBaseline", false, func(tx *sql.Tx) error {
		return d.recordTx(ctx, tx, req)
	})
}

// inMigrationTx runs fn in a transaction on a single dedicated connection.
//
// Foreign key enforcement is switched off for the duration (it can't be
// toggled inside a transaction), because a table rebuild drops and recreates
// tables that other rows may reference. If enforcement was on, the whole
// database is checked with PRAGMA foreign_key_check before committing, so a
// migration can never commit data that violates a foreign key.
//
// With dryRun, fn runs under exactly the same conditions but the transaction
// is always rolled back — this is how RenderMigration observes statements.
func (d *SQLiteDriver) inMigrationTx(ctx context.Context, op string, dryRun bool, fn func(tx *sql.Tx) error) (err error) {
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationConnFailed, err)
	}
	defer conn.Close()

	var fkEnabled bool
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationPragmaFailed, err)
	}
	if fkEnabled {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationPragmaFailed, err)
		}
		defer func() {
			// context.Background: the connection returns to the pool either way,
			// and must never go back with enforcement silently disabled.
			if _, restoreErr := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON"); restoreErr != nil && err == nil {
				err = behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationPragmaFailed, restoreErr)
			}
		}()
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationBeginTxFailed, err)
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	if dryRun {
		if err := tx.Rollback(); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationRollbackFailed, err)
		}
		return nil
	}
	if fkEnabled {
		if err := checkForeignKeys(ctx, tx); err != nil {
			tx.Rollback()
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationForeignKeyViolation, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationCommitFailed, err)
	}
	return nil
}

func checkForeignKeys(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return err
		}
		return fmt.Errorf("row %d of table %q references a missing row in %q", rowid.Int64, table, parent)
	}
	return rows.Err()
}

// ---- Ledger & snapshot ----

func (d *SQLiteDriver) recordTx(ctx context.Context, tx *sql.Tx, req core.MigrationRequest) error {
	if err := d.ensureBookkeepingTables(ctx, tx, req.LedgerTable, req.SnapshotTable); err != nil {
		return err
	}
	if err := d.insertLedger(ctx, tx, req.LedgerTable, req.LedgerEntry); err != nil {
		return err
	}
	return d.upsertSnapshot(ctx, tx, req.SnapshotTable, req.SnapshotUpdate)
}

// ensureBookkeepingTables creates the ledger and snapshot tables on first use,
// inside the same transaction as the migration that needs them — the first
// migration and the tables recording it appear atomically.
func (d *SQLiteDriver) ensureBookkeepingTables(ctx context.Context, tx *sql.Tx, ledgerTable, snapshotTable string) error {
	if ledgerTable == "" || snapshotTable == "" {
		return behemotherr.NewInternalError("SQLiteDriver.ensureBookkeepingTables", fmt.Errorf("ledger table %q / snapshot table %q must both be set", ledgerTable, snapshotTable))
	}
	stmts := []string{
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY NOT NULL, applied_at TIMESTAMP NOT NULL)", quoteIdent(ledgerTable)),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY, version TEXT NOT NULL, tables TEXT NOT NULL)", quoteIdent(snapshotTable)),
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return behemotherr.NewMigrationError("SQLiteDriver.ensureBookkeepingTables", behemotherr.ErrorCodeMigrationExecFailed, err)
		}
	}
	return nil
}

func (d *SQLiteDriver) insertLedger(ctx context.Context, tx *sql.Tx, table string, entry core.MigrationLedgerEntry) error {
	query := fmt.Sprintf("INSERT INTO %s (id, applied_at) VALUES (?, ?)", quoteIdent(table))
	if _, err := tx.ExecContext(ctx, query, entry.ID, entry.AppliedAt.UTC()); err != nil {
		return behemotherr.NewMigrationError("SQLiteDriver.insertLedger", behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	return nil
}

func (d *SQLiteDriver) upsertSnapshot(ctx context.Context, tx *sql.Tx, table string, snap core.SchemaSnapshot) error {
	data, err := json.Marshal(snap.Tables)
	if err != nil {
		return behemotherr.NewMigrationError("SQLiteDriver.upsertSnapshot", behemotherr.ErrorCodeMigrationMarshalFailed, err)
	}
	query := fmt.Sprintf(`INSERT INTO %s (id, version, tables) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET version = excluded.version, tables = excluded.tables`, quoteIdent(table))
	if _, err := tx.ExecContext(ctx, query, snap.Version, string(data)); err != nil {
		return behemotherr.NewMigrationError("SQLiteDriver.upsertSnapshot", behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	return nil
}

// ---- Operation dispatch ----

// applyOperation is the one switch over op.Kind. A missing payload is an
// Internal error, never a silent no-op.
func (d *SQLiteDriver) applyOperation(ctx context.Context, tx execQuerier, op core.SchemaOperation) error {
	missing := func(field string) error {
		return behemotherr.NewInternalError("SQLiteDriver.applyOperation", fmt.Errorf("operation %q: %s missing %s", op.ID, op.Kind, field))
	}

	switch op.Kind {
	case core.OpCreateTable:
		if op.NewTable == nil {
			return missing("NewTable")
		}
		return d.createTable(ctx, tx, *op.NewTable)
	case core.OpDropTable:
		return d.dropTable(ctx, tx, op.Table)
	case core.OpAddColumn:
		if op.Column == nil {
			return missing("Column")
		}
		return d.addColumn(ctx, tx, op.Table, *op.Column)
	case core.OpDropColumn:
		return d.dropColumn(ctx, tx, op.Table, op.ColumnName)
	case core.OpRenameColumn:
		return d.renameColumn(ctx, tx, op.Table, op.ColumnName, op.NewColumnName)
	case core.OpAlterColumn:
		if op.Column == nil {
			return missing("Column")
		}
		return d.alterColumn(ctx, tx, op.Table, *op.Column)
	case core.OpAddIndex:
		if op.Index == nil {
			return missing("Index")
		}
		return d.addIndex(ctx, tx, op.Table, *op.Index)
	case core.OpDropIndex:
		return d.dropIndex(ctx, tx, op.IndexName)
	case core.OpAddForeignKey:
		if op.ForeignKey == nil {
			return missing("ForeignKey")
		}
		return d.addForeignKey(ctx, tx, op.Table, *op.ForeignKey)
	case core.OpDropForeignKey:
		return d.dropForeignKey(ctx, tx, op.Table, op.ForeignKeyName)
	default:
		return behemotherr.NewInternalError("SQLiteDriver.applyOperation", fmt.Errorf("operation %q: unknown Kind %q", op.ID, op.Kind))
	}
}

func execDDL(ctx context.Context, tx execQuerier, op, query string) error {
	if _, err := tx.ExecContext(ctx, query); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, fmt.Errorf("%w (sql: %s)", err, query))
	}
	return nil
}

func (d *SQLiteDriver) createTable(ctx context.Context, tx execQuerier, t core.TableSchema) error {
	query, err := d.buildCreateTable(t)
	if err != nil {
		return err
	}
	return execDDL(ctx, tx, "SQLiteDriver.CreateTable", query)
}

// buildCreateTable renders columns and the primary key only.
//
// t.ForeignKeys and t.Indexes are intentionally NEVER read here: foreign keys
// always arrive as their own OpAddForeignKey (enforced upstream by
// MigrationGenerator's checkNoInlineForeignKeys) and indexes as their own
// OpAddIndex, exactly as BuildBaselineMigration emits them.
func (d *SQLiteDriver) buildCreateTable(t core.TableSchema) (string, error) {
	var pkCols []string
	for _, col := range t.Columns {
		if col.PrimaryKey {
			pkCols = append(pkCols, col.Name)
		}
	}
	// A single-column key is rendered inline: that is the only form SQLite
	// accepts for AUTOINCREMENT, and it keeps INTEGER keys as rowid aliases.
	inlinePK := len(pkCols) == 1

	defs := make([]string, 0, len(t.Columns)+1)
	for _, col := range t.Columns {
		def, err := d.renderColumnDefinition(t.Name, col, inlinePK)
		if err != nil {
			return "", err
		}
		defs = append(defs, def)
	}
	if len(pkCols) > 1 {
		quoted := make([]string, len(pkCols))
		for i, c := range pkCols {
			quoted[i] = quoteIdent(d.resolver.ResolveColumn(t.Name, c))
		}
		defs = append(defs, "PRIMARY KEY ("+strings.Join(quoted, ", ")+")")
	}
	return fmt.Sprintf("CREATE TABLE %s (%s)", quoteIdent(d.resolver.Resolve(t.Name)), strings.Join(defs, ", ")), nil
}

func (d *SQLiteDriver) dropTable(ctx context.Context, tx execQuerier, table string) error {
	return execDDL(ctx, tx, "SQLiteDriver.DropTable", "DROP TABLE "+quoteIdent(d.resolver.Resolve(table)))
}

// addColumn uses native ADD COLUMN when SQLite allows it, and a rebuild
// otherwise. Native ADD COLUMN rejects PRIMARY KEY / UNIQUE columns and
// NOT NULL columns without a default; an override default is a raw
// expression that may be non-constant, which native ADD COLUMN also rejects.
func (d *SQLiteDriver) addColumn(ctx context.Context, tx execQuerier, table string, col core.Column) error {
	resolved := applyOverride(col)
	native := !resolved.PrimaryKey && !resolved.Unique && !resolved.AutoInc &&
		(resolved.Nullable || resolved.Default != nil) &&
		overrideDefault(col) == ""

	if !native {
		return d.rebuildTable(ctx, tx, table, func(s *tableSQL) error {
			def, err := d.renderColumnDefinition(table, col, !s.hasTablePrimaryKey() && !s.hasInlinePrimaryKey())
			if err != nil {
				return err
			}
			s.appendColumn(def)
			return nil
		}, nil)
	}

	def, err := d.renderColumnDefinition(table, col, false)
	if err != nil {
		return err
	}
	return execDDL(ctx, tx, "SQLiteDriver.AddColumn",
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", quoteIdent(d.resolver.Resolve(table)), def))
}

// dropColumn mirrors Postgres semantics: indexes and table constraints
// involving the column are dropped along with it. That always needs a rebuild,
// since native DROP COLUMN refuses indexed/constrained columns.
func (d *SQLiteDriver) dropColumn(ctx context.Context, tx execQuerier, table, column string) error {
	physCol := d.resolver.ResolveColumn(table, column)
	return d.rebuildTable(ctx, tx, table, func(s *tableSQL) error {
		return s.dropColumn(physCol)
	}, func(idx liveIndex) bool {
		return !containsFold(idx.columns, physCol)
	})
}

func (d *SQLiteDriver) renameColumn(ctx context.Context, tx execQuerier, table, oldName, newName string) error {
	return execDDL(ctx, tx, "SQLiteDriver.RenameColumn", fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s",
		quoteIdent(d.resolver.Resolve(table)),
		quoteIdent(d.resolver.ResolveColumn(table, oldName)),
		quoteIdent(d.resolver.ResolveColumn(table, newName))))
}

// alterColumn replaces the column's definition wholesale via a rebuild —
// type, nullability, uniqueness, default and check all take the new value.
func (d *SQLiteDriver) alterColumn(ctx context.Context, tx execQuerier, table string, col core.Column) error {
	physCol := d.resolver.ResolveColumn(table, col.Name)
	return d.rebuildTable(ctx, tx, table, func(s *tableSQL) error {
		// Keep the key where it already lives: inline if the column owned it,
		// or inline if the table has no key at all yet.
		inlinePK := s.columnHasInlinePrimaryKey(physCol) || (!s.hasTablePrimaryKey() && !s.hasInlinePrimaryKey())
		def, err := d.renderColumnDefinition(table, col, inlinePK)
		if err != nil {
			return err
		}
		return s.replaceColumn(physCol, def)
	}, nil)
}

func (d *SQLiteDriver) addIndex(ctx context.Context, tx execQuerier, table string, idx core.Index) error {
	if len(idx.Columns) == 0 {
		return behemotherr.NewMigrationError("SQLiteDriver.AddIndex", behemotherr.ErrorCodeMigrationInvalidIndex, fmt.Errorf("index %q has no columns", idx.Name))
	}
	cols := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		cols[i] = quoteIdent(d.resolver.ResolveColumn(table, c))
	}
	uniqueKw := ""
	if idx.Unique {
		uniqueKw = "UNIQUE "
	}
	return execDDL(ctx, tx, "SQLiteDriver.AddIndex", fmt.Sprintf("CREATE %sINDEX %s ON %s (%s)",
		uniqueKw, quoteIdent(idx.Name), quoteIdent(d.resolver.Resolve(table)), strings.Join(cols, ", ")))
}

// dropIndex: SQLite index names are schema-global, so the table isn't needed.
func (d *SQLiteDriver) dropIndex(ctx context.Context, tx execQuerier, indexName string) error {
	return execDDL(ctx, tx, "SQLiteDriver.DropIndex", "DROP INDEX "+quoteIdent(indexName))
}

// addForeignKey appends a named table constraint via a rebuild — the name is
// what makes a later OpDropForeignKey possible, since PRAGMA foreign_key_list
// doesn't report constraint names.
func (d *SQLiteDriver) addForeignKey(ctx context.Context, tx execQuerier, table string, fk core.ForeignKey) error {
	if len(fk.Columns) == 0 || len(fk.Columns) != len(fk.RefColumns) {
		return behemotherr.NewMigrationError("SQLiteDriver.AddForeignKey", behemotherr.ErrorCodeMigrationInvalidForeignKey,
			fmt.Errorf("foreign key %q: %d column(s) vs %d referenced column(s)", fk.Name, len(fk.Columns), len(fk.RefColumns)))
	}
	cols := make([]string, len(fk.Columns))
	for i, c := range fk.Columns {
		cols[i] = quoteIdent(d.resolver.ResolveColumn(table, c))
	}
	refCols := make([]string, len(fk.RefColumns))
	for i, c := range fk.RefColumns {
		refCols[i] = quoteIdent(d.resolver.ResolveColumn(fk.RefTable, c))
	}
	constraint := fmt.Sprintf("CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s",
		quoteIdent(fk.Name), strings.Join(cols, ", "),
		quoteIdent(d.resolver.Resolve(fk.RefTable)), strings.Join(refCols, ", "), mapFKAction(fk.OnDelete))

	return d.rebuildTable(ctx, tx, table, func(s *tableSQL) error {
		if s.findConstraint(fk.Name) >= 0 {
			return fmt.Errorf("constraint %q already exists", fk.Name)
		}
		s.appendConstraint(constraint)
		return nil
	}, nil)
}

func (d *SQLiteDriver) dropForeignKey(ctx context.Context, tx execQuerier, table, fkName string) error {
	return d.rebuildTable(ctx, tx, table, func(s *tableSQL) error {
		i := s.findConstraint(fkName)
		if i < 0 || s.items[i].kind != itemForeignKey {
			return fmt.Errorf("foreign key %q not found", fkName)
		}
		s.removeItem(i)
		return nil
	}, nil)
}

// ---- Rendering ----

// applyOverride folds Column.Overrides["sqlite"] into the column. Default is
// deliberately left alone: an override default is a raw SQL expression and is
// rendered separately by overrideDefault.
func applyOverride(col core.Column) core.Column {
	ov, ok := col.Overrides[DriverName]
	if !ok {
		return col
	}
	if ov.Type != "" {
		col.Type = ov.Type
	}
	if ov.Check != "" {
		col.Check = ov.Check
	}
	if ov.AutoInc != nil {
		col.AutoInc = *ov.AutoInc
	}
	return col
}

func overrideDefault(col core.Column) string {
	return col.Overrides[DriverName].Default
}

func (d *SQLiteDriver) renderColumnDefinition(table string, raw core.Column, inlinePK bool) (string, error) {
	col := applyOverride(raw)

	nativeType, err := renderSQLiteType(col.Type, col.Length)
	if err != nil {
		return "", err
	}
	if col.AutoInc {
		// SQLite only supports AUTOINCREMENT on a lone INTEGER PRIMARY KEY.
		if !col.PrimaryKey || !inlinePK {
			return "", behemotherr.NewMigrationError("SQLiteDriver.renderColumnDefinition", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
				fmt.Errorf("column %q: SQLite supports AUTOINCREMENT only on a single-column primary key", col.Name))
		}
		if col.Type != core.ColTypeInteger && col.Type != core.ColTypeBigInt {
			return "", behemotherr.NewMigrationError("SQLiteDriver.renderColumnDefinition", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
				fmt.Errorf("column %q: AUTOINCREMENT requires an integer column, got %q", col.Name, col.Type))
		}
		nativeType = "INTEGER"
	}

	parts := []string{quoteIdent(d.resolver.ResolveColumn(table, col.Name)), nativeType}
	if col.PrimaryKey && inlinePK {
		parts = append(parts, "PRIMARY KEY")
		if col.AutoInc {
			parts = append(parts, "AUTOINCREMENT")
		}
	}
	// SQLite (unlike the SQL standard) allows NULL in non-INTEGER primary keys,
	// so NOT NULL is emitted for key columns too — except rowid aliases, where
	// an omitted/NULL value means "assign the next rowid".
	if (!col.Nullable || col.PrimaryKey) && !col.AutoInc {
		parts = append(parts, "NOT NULL")
	}
	if col.Unique && !col.PrimaryKey {
		parts = append(parts, "UNIQUE")
	}

	if expr := overrideDefault(raw); expr != "" {
		parts = append(parts, "DEFAULT ("+expr+")")
	} else {
		defClause, err := renderDefault(col.Default)
		if err != nil {
			return "", err
		}
		if defClause != "" {
			parts = append(parts, defClause)
		}
	}
	if col.Check != "" {
		parts = append(parts, "CHECK ("+col.Check+")")
	}
	return strings.Join(parts, " "), nil
}

// renderDefault produces a literal DEFAULT clause for Column.Default. Numbers
// arrive as float64 once a migration has round-tripped through its JSON file.
func renderDefault(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "", nil
	case string:
		return "DEFAULT '" + strings.ReplaceAll(val, "'", "''") + "'", nil
	case bool:
		if val {
			return "DEFAULT 1", nil
		}
		return "DEFAULT 0", nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("DEFAULT %d", val), nil
	case float32, float64:
		return fmt.Sprintf("DEFAULT %v", val), nil
	default:
		return "", behemotherr.NewMigrationError("SQLiteDriver.renderDefault", behemotherr.ErrorCodeMigrationUnsupportedDefaultType, fmt.Errorf("cannot render default value of type %T", v))
	}
}

// renderSQLiteType maps canonical types to declared types. SQLite only has
// storage classes, but the declared type decides column affinity and is what
// database/sql drivers (e.g. mattn/go-sqlite3) use to decode values — hence
// DATETIME/TIMESTAMP/BOOLEAN rather than collapsing everything to TEXT/INTEGER.
func renderSQLiteType(ct core.ColumnType, length int) (string, error) {
	switch ct {
	case core.ColTypeString:
		if length <= 0 {
			length = 255
		}
		return fmt.Sprintf("VARCHAR(%d)", length), nil // TEXT affinity; length is informational only
	case core.ColTypeText:
		return "TEXT", nil
	case core.ColTypeJson:
		return "TEXT", nil // a declared type of JSON would get NUMERIC affinity
	case core.ColTypeInteger:
		return "INTEGER", nil
	case core.ColTypeBigInt:
		return "BIGINT", nil
	case core.ColTypeReal:
		return "REAL", nil
	case core.ColTypeNumeric:
		return "NUMERIC", nil
	case core.ColTypeBoolean:
		return "BOOLEAN", nil
	case core.ColTypeDateTime:
		return "DATETIME", nil
	case core.ColTypeTimestamp:
		return "TIMESTAMP", nil
	case core.ColTypeUuid:
		return "BLOB", nil // override with ColumnOverride{Type: ColTypeText} to store the string form
	case core.ColTypeBlob, core.ColTypeBytes:
		return "BLOB", nil
	default:
		return "", behemotherr.NewMigrationError("SQLiteDriver.renderSQLiteType", behemotherr.ErrorCodeMigrationUnsupportedCanonicalType, fmt.Errorf("no SQLite rendering for canonical type %q", ct))
	}
}

func mapFKAction(a core.ForeignKeyAction) string {
	switch a {
	case core.FKCascade:
		return "CASCADE"
	case core.FKSetNull:
		return "SET NULL"
	default:
		return "RESTRICT"
	}
}

// quoteIdent applies standard double-quote identifier escaping; every
// identifier emitted into SQL goes through it.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
