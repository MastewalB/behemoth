package sqlserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"strconv"
	"strings"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/types/schema"
)

// DriverName is the key used for per-database Column.Overrides lookups.
const DriverName = "sqlserver"

const (
	// maxIdentifierLength is SQL Server's limit for object names.
	maxIdentifierLength = 128

	// maxStringLength is the longest NVARCHAR(n). A longer string is created
	// as NVARCHAR(MAX).
	maxStringLength = 4000
)

// SQLServerDriver implements [core.SchemaDriver], [core.MigrationRenderer],
// [core.SchemaIntrospector] and [core.ColumnNormalizer] for Microsoft SQL
// Server 2016 and later.
//
// It is the migration counterpart of SQLServerAdapter: build both with the
// same resolver so queries and migrations agree on physical names.
//
// SQL Server DDL is transactional, so a migration applies atomically, as on
// Postgres. Several operations depend on the live schema, though: a default
// is a constraint with a generated name, ALTER COLUMN and DROP COLUMN refuse
// to touch a column an index depends on, and IDENTITY can only change by
// rebuilding the table. The driver therefore reads the catalog while it
// applies an operation, and RenderMigration works like SQLite's: it applies
// the migration in a transaction that is always rolled back and records the
// statements.
//
// The driver never imports a database/sql driver itself: the caller picks one
// and hands over an opened *sql.DB.
type SQLServerDriver struct {
	db       *sql.DB
	resolver core.SchemaResolver
}

// NewSQLServerDriver returns a driver bound to db, operating in the
// connection's default schema (SCHEMA_NAME()). A nil resolver maps every
// canonical table/column name to itself.
func NewSQLServerDriver(db *sql.DB, resolver core.SchemaResolver) *SQLServerDriver {
	return &SQLServerDriver{db: db, resolver: adapters.ResolverOrIdentity(resolver)}
}

var (
	_ core.SchemaDriver       = (*SQLServerDriver)(nil)
	_ core.MigrationRenderer  = (*SQLServerDriver)(nil)
	_ core.SchemaIntrospector = (*SQLServerDriver)(nil)
	_ core.ColumnNormalizer   = (*SQLServerDriver)(nil)
)

// AtomicityLevel implements [core.SchemaDriver]. SQL Server DDL is transactional.
func (d *SQLServerDriver) AtomicityLevel() core.AtomicityLevel { return core.AtomicityFull }

// ApplyMigration implements [core.SchemaDriver]: every Up operation, the
// ledger row and the snapshot write commit or roll back together.
func (d *SQLServerDriver) ApplyMigration(ctx context.Context, req core.MigrationRequest) error {
	const op = "SQLServerDriver.ApplyMigration"
	return d.inMigrationTx(ctx, op, req, func(tx *sql.Tx) error {
		r := &run{ctx: ctx, tx: tx}
		for _, o := range req.Migration.Up {
			if err := d.applyOperation(r, o); err != nil {
				return behemotherr.WrapOp(op, fmt.Sprintf("operation %q (%s on %s)", o.ID, o.Kind, o.Table), err)
			}
		}
		return nil
	})
}

// RecordBaseline implements [core.SchemaDriver]: the same ledger and snapshot
// write as ApplyMigration, with no DDL executed.
func (d *SQLServerDriver) RecordBaseline(ctx context.Context, req core.MigrationRequest) error {
	return d.inMigrationTx(ctx, "SQLServerDriver.RecordBaseline", req, func(*sql.Tx) error { return nil })
}

// inMigrationTx runs fn, then the ledger and snapshot writes, in one
// transaction.
//
// A transaction-owned application lock keyed on the ledger table serializes
// concurrent migrators (several app instances booting at once): the second
// one waits until the first commits, then fails on the duplicate ledger row
// and rolls its DDL back.
func (d *SQLServerDriver) inMigrationTx(ctx context.Context, op string, req core.MigrationRequest, fn func(tx *sql.Tx) error) error {
	if req.LedgerTable == "" || req.SnapshotTable == "" {
		return behemotherr.NewInternalError(op, fmt.Errorf("ledger table %q / snapshot table %q must both be set", req.LedgerTable, req.SnapshotTable))
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationBeginTxFailed, err)
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	work := func() error {
		// sp_getapplock reports a refused lock through its return value, not an error.
		const lock = `DECLARE @r int;
			EXEC @r = sp_getapplock @Resource = @p1, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = -1;
			IF @r < 0 THROW 50000, 'behemoth: could not take the migration lock', 1;`
		if _, err := tx.ExecContext(ctx, lock, "behemoth.migration:"+req.LedgerTable); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationLockFailed, err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		return d.recordTx(ctx, tx, op, req)
	}
	if err := work(); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationCommitFailed, err)
	}
	return nil
}

// recordTx creates the ledger and snapshot tables on first use, inserts the
// ledger row and replaces the snapshot.
func (d *SQLServerDriver) recordTx(ctx context.Context, tx *sql.Tx, op string, req core.MigrationRequest) error {
	data, err := json.Marshal(req.SnapshotUpdate.Tables)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationMarshalFailed, err)
	}
	ledger, snapshot := quoteIdent(req.LedgerTable), quoteIdent(req.SnapshotTable)
	steps := []struct {
		query string
		args  []any
	}{
		{fmt.Sprintf("IF OBJECT_ID(@p1, 'U') IS NULL CREATE TABLE %s (id NVARCHAR(255) NOT NULL PRIMARY KEY, applied_at DATETIMEOFFSET(6) NOT NULL)", ledger), []any{ledger}},
		{fmt.Sprintf("IF OBJECT_ID(@p1, 'U') IS NULL CREATE TABLE %s (id INT NOT NULL PRIMARY KEY, version NVARCHAR(255) NOT NULL, tables NVARCHAR(MAX) NOT NULL)", snapshot), []any{snapshot}},
		{fmt.Sprintf("INSERT INTO %s (id, applied_at) VALUES (@p1, @p2)", ledger), []any{req.LedgerEntry.ID, req.LedgerEntry.AppliedAt}},
		// The migration lock is held, so update-then-insert can't race.
		{fmt.Sprintf("UPDATE %[1]s SET version = @p1, tables = @p2 WHERE id = 1; IF @@ROWCOUNT = 0 INSERT INTO %[1]s (id, version, tables) VALUES (1, @p1, @p2)", snapshot),
			[]any{req.SnapshotUpdate.Version, string(data)}},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s.query, s.args...); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, err)
		}
	}
	return nil
}

// ---- core.MigrationRenderer ----

// RenderMigration implements [core.MigrationRenderer]. It applies m's Up in a
// transaction that is always rolled back and returns the statements that ran,
// in order. Statements depend on the live schema (see SQLServerDriver), so it
// has to run against the database m will be applied to. Schema, data and
// ledger are left as they were; the tables involved are locked while it runs.
//
// A baseline's Up is never executed: its tables already exist. Its statements
// are built without being run.
func (d *SQLServerDriver) RenderMigration(ctx context.Context, m core.Migration) (string, error) {
	const op = "SQLServerDriver.RenderMigration"
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationBeginTxFailed, err)
	}
	defer tx.Rollback()

	r := &run{ctx: ctx, tx: tx, dry: m.IsBaseline}
	for _, o := range m.Up {
		if err := d.applyOperation(r, o); err != nil {
			return "", behemotherr.WrapOp(op, fmt.Sprintf("operation %q (%s on %s)", o.ID, o.Kind, o.Table), err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "-- Migration: %s\n-- Generated: %s\n", m.ID, m.CreatedAt.Format(time.RFC3339))
	if m.IsBaseline {
		b.WriteString("-- Baseline: records the existing schema; never executed by the runner.\n")
	}
	b.WriteString("\n")
	for _, stmt := range r.stmts {
		fmt.Fprintf(&b, "%s;\n", stmt)
	}
	return b.String(), nil
}

// FileExtension implements [core.MigrationRenderer].
func (d *SQLServerDriver) FileExtension() string { return ".sql" }

// ---- Applying operations ----

// run is one pass over a migration's operations inside a transaction. Every
// statement goes through exec, which records it, so the rendered script is
// the list of statements an apply executes.
type run struct {
	ctx   context.Context
	tx    *sql.Tx
	stmts []string
	dry   bool // record statements without executing them (baseline rendering)
}

func (r *run) exec(stmts ...string) error {
	for _, stmt := range stmts {
		r.stmts = append(r.stmts, stmt)
		if r.dry {
			continue
		}
		if _, err := r.tx.ExecContext(r.ctx, stmt); err != nil {
			return behemotherr.NewMigrationError("SQLServerDriver.exec", behemotherr.ErrorCodeMigrationExecFailed, fmt.Errorf("%w (sql: %s)", err, stmt))
		}
	}
	return nil
}

// applyOperation is the one switch over op.Kind. An operation missing its
// required payload is an Internal error, never a silent no-op.
func (d *SQLServerDriver) applyOperation(r *run, op core.SchemaOperation) error {
	missing := func(field string) error {
		return behemotherr.NewInternalError("SQLServerDriver.applyOperation", fmt.Errorf("operation %q: %s missing %s", op.ID, op.Kind, field))
	}
	table := d.resolver.Resolve(op.Table)

	switch op.Kind {
	case core.OpCreateTable:
		if op.NewTable == nil {
			return missing("NewTable")
		}
		stmts, err := d.buildCreateTable(*op.NewTable)
		if err != nil {
			return err
		}
		return r.exec(stmts...)
	case core.OpDropTable:
		return r.exec("DROP TABLE " + quoteIdent(table))
	case core.OpAddColumn:
		if op.Column == nil {
			return missing("Column")
		}
		stmts, err := d.buildAddColumn(op.Table, *op.Column)
		if err != nil {
			return err
		}
		return r.exec(stmts...)
	case core.OpDropColumn:
		return d.dropColumn(r, table, d.resolver.ResolveColumn(op.Table, op.ColumnName))
	case core.OpRenameColumn:
		return d.renameColumn(r, table, d.resolver.ResolveColumn(op.Table, op.ColumnName), d.resolver.ResolveColumn(op.Table, op.NewColumnName))
	case core.OpAlterColumn:
		if op.Column == nil {
			return missing("Column")
		}
		return d.alterColumn(r, op.Table, *op.Column, op.PrevColumn)
	case core.OpAddIndex:
		if op.Index == nil {
			return missing("Index")
		}
		return d.addIndex(r, op.Table, *op.Index)
	case core.OpDropIndex:
		return r.exec(fmt.Sprintf("DROP INDEX %s ON %s", quoteIdent(op.IndexName), quoteIdent(table)))
	case core.OpAddForeignKey:
		if op.ForeignKey == nil {
			return missing("ForeignKey")
		}
		stmt, err := d.buildAddForeignKey(op.Table, *op.ForeignKey)
		if err != nil {
			return err
		}
		return r.exec(stmt)
	case core.OpDropForeignKey:
		return r.exec(fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", quoteIdent(table), quoteIdent(op.ForeignKeyName)))
	default:
		return behemotherr.NewInternalError("SQLServerDriver.applyOperation", fmt.Errorf("operation %q: unknown Kind %q", op.ID, op.Kind))
	}
}

// buildCreateTable renders the table with its columns and primary key, then
// one unique index per unique column (see uniqueColumnIndex).
//
// t.ForeignKeys and t.Indexes are not read here: foreign keys arrive as their
// own OpAddForeignKey (enforced upstream by MigrationGenerator's
// checkNoInlineForeignKeys) and indexes as their own OpAddIndex.
func (d *SQLServerDriver) buildCreateTable(t schema.Table) ([]string, error) {
	table := d.resolver.Resolve(t.Name)
	var defs, pkCols, uniques []string
	for _, raw := range t.Columns {
		physCol := d.resolver.ResolveColumn(t.Name, raw.Name)
		def, err := columnDefinition(raw)
		if err != nil {
			return nil, err
		}
		defs = append(defs, quoteIdent(physCol)+" "+def)
		col := applyOverride(raw)
		switch {
		case col.PrimaryKey:
			pkCols = append(pkCols, quoteIdent(physCol))
		case col.Unique:
			uniques = append(uniques, uniqueColumnIndex(table, physCol, col.Nullable))
		}
	}
	if len(pkCols) > 0 {
		defs = append(defs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}
	create := fmt.Sprintf("CREATE TABLE %s (%s)", quoteIdent(table), strings.Join(defs, ", "))
	return append([]string{create}, uniques...), nil
}

// buildAddColumn: SQL Server itself rejects a NOT NULL column without a
// default on a table that has rows.
func (d *SQLServerDriver) buildAddColumn(canonicalTable string, raw schema.Column) ([]string, error) {
	table, physCol := d.resolver.Resolve(canonicalTable), d.resolver.ResolveColumn(canonicalTable, raw.Name)
	def, err := columnDefinition(raw)
	if err != nil {
		return nil, err
	}
	col := applyOverride(raw)
	stmt := fmt.Sprintf("ALTER TABLE %s ADD %s %s", quoteIdent(table), quoteIdent(physCol), def)
	switch {
	case col.PrimaryKey:
		return []string{stmt + " PRIMARY KEY"}, nil
	case col.Unique:
		return []string{stmt, uniqueColumnIndex(table, physCol, col.Nullable)}, nil
	}
	return []string{stmt}, nil
}

// dropColumn drops what depends on the column first: SQL Server refuses to
// drop a column that has a default or is part of an index. Postgres and MySQL
// drop those along with the column, and the driver contract follows them.
func (d *SQLServerDriver) dropColumn(r *run, table, column string) error {
	if err := d.dropDefault(r, table, column); err != nil {
		return err
	}
	indexes, err := d.liveIndexes(r.ctx, r.tx, table)
	if err != nil {
		return err
	}
	for _, idx := range indexes {
		if !idx.primaryKey && slices.Contains(idx.allColumns(), column) {
			if err := r.exec(idx.dropSQL(table)); err != nil {
				return err
			}
		}
	}
	return r.exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", quoteIdent(table), quoteIdent(column)))
}

// renameColumn renames with sp_rename. A filtered index names the column in
// its predicate and blocks the rename, so the filtered indexes on the column
// are dropped and created again under the new column name. The unique index
// of a unique column is named after the column and is renamed with it.
func (d *SQLServerDriver) renameColumn(r *run, table, from, to string) error {
	indexes, err := d.liveIndexes(r.ctx, r.tx, table)
	if err != nil {
		return err
	}
	var recreate []liveIndex
	var renames []string
	for _, idx := range indexes {
		if !slices.Contains(idx.columns, from) {
			continue
		}
		columnUnique := idx.isColumnUnique(table)
		switch {
		case idx.filter != "":
			if !idx.representable {
				return behemotherr.NewMigrationError("SQLServerDriver.renameColumn", behemotherr.ErrorCodeMigrationExecFailed,
					fmt.Errorf("index %q on %s.%s has a filter the driver can't recreate; drop it before renaming the column", idx.name, table, from))
			}
			if err := r.exec(idx.dropSQL(table)); err != nil {
				return err
			}
			idx.columns = replaceString(idx.columns, from, to)
			if columnUnique {
				idx.name = uniqueKeyName(table, to)
			}
			recreate = append(recreate, idx)
		case columnUnique && idx.name == uniqueKeyName(table, from):
			renames = append(renames, fmt.Sprintf("EXEC sp_rename %s, %s, N'INDEX'",
				quoteLiteral(quoteIdent(table)+"."+quoteIdent(idx.name)), quoteLiteral(uniqueKeyName(table, to))))
		}
	}
	rename := fmt.Sprintf("EXEC sp_rename %s, %s, N'COLUMN'", quoteLiteral(quoteIdent(table)+"."+quoteIdent(from)), quoteLiteral(to))
	if err := r.exec(append([]string{rename}, renames...)...); err != nil {
		return err
	}
	return d.createIndexes(r, table, recreate)
}

// alterColumn brings one column to its declaration. SQL Server has no single
// statement for that:
//   - a change of IDENTITY needs the table rebuilt (rebuildTable)
//   - the default is a constraint: the old one is dropped, the new one added
//   - ALTER COLUMN sets type and nullability, and is skipped when neither
//     changes. It fails while an index depends on the column, except for a
//     plain widening, so the column's indexes are dropped and created again
//     around it. Their NULL filters follow the new nullability.
//
// Uniqueness is only changed when prev, the operation's PrevColumn, says it
// differs. Without prev it is left as it is.
func (d *SQLServerDriver) alterColumn(r *run, canonicalTable string, raw schema.Column, prevRaw *schema.Column) error {
	const op = "SQLServerDriver.alterColumn"
	table, column := d.resolver.Resolve(canonicalTable), d.resolver.ResolveColumn(canonicalTable, raw.Name)
	col := applyOverride(raw)
	if col.AutoInc && col.Type != schema.ColTypeInteger && col.Type != schema.ColTypeBigInt {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
			fmt.Errorf("column %q: AutoInc requires an integer column, got %q", col.Name, col.Type))
	}

	live, err := d.readTable(r.ctx, r.tx, table)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(live.columns, func(c liveColumn) bool { return c.name == column })
	if i < 0 {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, fmt.Errorf("column %q does not exist in table %q", column, table))
	}
	current, _ := live.columns[i].canonical(nil, nil)
	target := d.NormalizeColumn(canonicalTable, raw)

	wasUnique := slices.ContainsFunc(live.indexes, func(idx liveIndex) bool {
		return idx.isColumnUnique(table) && idx.columns[0] == column
	})
	wantUnique := wasUnique
	if prevRaw != nil && applyOverride(*prevRaw).Unique != col.Unique {
		wantUnique = col.Unique
	}
	wantUnique = wantUnique && !col.PrimaryKey

	if current.AutoInc != target.AutoInc {
		return d.rebuildTable(r, table, live, column, raw, wantUnique)
	}

	if err := d.dropDefault(r, table, column); err != nil {
		return err
	}

	var dependents []liveIndex
	if current.Type != target.Type || current.Length != target.Length || current.Nullable != target.Nullable {
		for _, idx := range live.indexes {
			if idx.primaryKey || !slices.Contains(idx.allColumns(), column) {
				continue
			}
			if !idx.representable {
				return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed,
					fmt.Errorf("index %q depends on %s.%s and the driver can't recreate it; drop it before altering the column", idx.name, table, column))
			}
			if err := r.exec(idx.dropSQL(table)); err != nil {
				return err
			}
			dependents = append(dependents, idx)
		}
		nativeType, err := renderSQLServerType(col.Type, col.Length)
		if err != nil {
			return err
		}
		if err := r.exec(fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s %s %s", quoteIdent(table), quoteIdent(column), nativeType, nullability(col))); err != nil {
			return err
		}
	}

	expr, err := renderDefaultExpr(raw)
	if err != nil {
		return err
	}
	if expr != "" {
		if err := r.exec(fmt.Sprintf("ALTER TABLE %s ADD DEFAULT %s FOR %s", quoteIdent(table), expr, quoteIdent(column))); err != nil {
			return err
		}
	}

	// The column's own unique index is handled below, from wantUnique.
	dependents = slices.DeleteFunc(dependents, func(idx liveIndex) bool { return idx.isColumnUnique(table) })
	if err := d.createIndexes(r, table, dependents); err != nil {
		return err
	}
	dropped := current.Type != target.Type || current.Length != target.Length || current.Nullable != target.Nullable
	switch {
	case wantUnique && (!wasUnique || dropped):
		return r.exec(uniqueColumnIndex(table, column, col.Nullable && !col.PrimaryKey))
	case !wantUnique && wasUnique && !dropped:
		for _, idx := range live.indexes {
			if idx.isColumnUnique(table) && idx.columns[0] == column {
				if err := r.exec(idx.dropSQL(table)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// addIndex creates the index. A unique index is filtered to rows whose
// nullable key columns are all set (see indexSQL), so the columns'
// nullability is read from the live table.
func (d *SQLServerDriver) addIndex(r *run, canonicalTable string, idx schema.Index) error {
	if len(idx.Columns) == 0 {
		return behemotherr.NewMigrationError("SQLServerDriver.addIndex", behemotherr.ErrorCodeMigrationInvalidIndex, fmt.Errorf("index %q has no columns", idx.Name))
	}
	table := d.resolver.Resolve(canonicalTable)
	cols := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		cols[i] = d.resolver.ResolveColumn(canonicalTable, c)
	}
	return d.createIndexes(r, table, []liveIndex{{name: idx.Name, unique: idx.Unique, columns: cols}})
}

// createIndexes creates indexes described by physical names, with the NULL
// filters the table's current nullability calls for.
func (d *SQLServerDriver) createIndexes(r *run, table string, indexes []liveIndex) error {
	if len(indexes) == 0 {
		return nil
	}
	nullable, err := d.nullableColumns(r.ctx, r.tx, table)
	if err != nil {
		return err
	}
	for _, idx := range indexes {
		if err := r.exec(indexSQL(table, idx.name, idx.columns, idx.unique, nullable)); err != nil {
			return err
		}
	}
	return nil
}

func (d *SQLServerDriver) buildAddForeignKey(canonicalTable string, fk schema.ForeignKey) (string, error) {
	if len(fk.Columns) == 0 || len(fk.Columns) != len(fk.RefColumns) {
		return "", behemotherr.NewMigrationError("SQLServerDriver.AddForeignKey", behemotherr.ErrorCodeMigrationInvalidForeignKey,
			fmt.Errorf("foreign key %q: %d column(s) vs %d referenced column(s)", fk.Name, len(fk.Columns), len(fk.RefColumns)))
	}
	cols := make([]string, len(fk.Columns))
	for i, c := range fk.Columns {
		cols[i] = d.resolver.ResolveColumn(canonicalTable, c)
	}
	refCols := make([]string, len(fk.RefColumns))
	for i, c := range fk.RefColumns {
		refCols[i] = d.resolver.ResolveColumn(fk.RefTable, c)
	}
	return foreignKeySQL(d.resolver.Resolve(canonicalTable), fk.Name, cols, d.resolver.Resolve(fk.RefTable), refCols, mapFKAction(fk.OnDelete), ""), nil
}

// dropDefault drops the column's default constraint, if it has one. The
// constraint's name is generated by SQL Server, so it is looked up.
func (d *SQLServerDriver) dropDefault(r *run, table, column string) error {
	var name sql.NullString
	err := r.tx.QueryRowContext(r.ctx, `
		SELECT (SELECT dc.name FROM sys.default_constraints dc
			JOIN sys.columns c ON c.object_id = dc.parent_object_id AND c.column_id = dc.parent_column_id
			WHERE dc.parent_object_id = OBJECT_ID(@p1) AND c.name = @p2)`, quoteIdent(table), column).Scan(&name)
	if err != nil {
		return behemotherr.NewMigrationError("SQLServerDriver.dropDefault", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	if !name.Valid {
		return nil
	}
	return r.exec(fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", quoteIdent(table), quoteIdent(name.String)))
}

// ---- Table rebuild ----

// rebuildSuffix names the table a rebuild copies into before it takes the
// original's name.
const rebuildSuffix = "__behemoth_rebuild"

// rebuildTable replaces column's definition by creating a new table, copying
// the rows, dropping the old table and renaming the new one. It is the only
// way to add or remove IDENTITY on SQL Server.
//
// Every other column is recreated from its native definition in the catalog
// (type, collation, nullability, identity, default), not from the canonical
// model, so a VARCHAR stays a VARCHAR. Indexes and foreign keys, including
// the ones other tables hold on this table, are dropped and created again.
// Copying with IDENTITY_INSERT moves a new identity past the largest copied
// value.
//
// The rebuild refuses a table carrying something it would lose: a computed
// or rowversion column, a check constraint, a trigger, or an index it can't
// describe.
func (d *SQLServerDriver) rebuildTable(r *run, table string, live liveTable, column string, raw schema.Column, unique bool) error {
	const op = "SQLServerDriver.rebuildTable"
	refuse := func(reason string) error {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationRebuildFailed,
			fmt.Errorf("changing auto-increment on %s.%s needs the table rebuilt, which would lose %s", table, column, reason))
	}
	if extra, err := d.unrebuildableObjects(r.ctx, r.tx, table); err != nil {
		return err
	} else if extra != "" {
		return refuse(extra)
	}

	target := applyOverride(raw)
	var defs, names, pkCols []string
	identity := false
	for _, c := range live.columns {
		def := c.nativeDefinition()
		switch {
		case c.name == column:
			var err error
			if def, err = columnDefinition(raw); err != nil {
				return err
			}
			identity = identity || target.AutoInc
		case c.computed || c.typeName == "timestamp":
			return refuse(fmt.Sprintf("column %q (computed or rowversion)", c.name))
		default:
			identity = identity || c.identity
		}
		defs = append(defs, quoteIdent(c.name)+" "+def)
		names = append(names, quoteIdent(c.name))
	}
	var indexes []liveIndex
	for _, idx := range live.indexes {
		switch {
		case idx.primaryKey:
			for _, c := range idx.columns {
				pkCols = append(pkCols, quoteIdent(c))
			}
		case !idx.representable:
			return refuse(fmt.Sprintf("index %q", idx.name))
		case idx.isColumnUnique(table) && idx.columns[0] == column:
			// replaced below, from unique
		default:
			indexes = append(indexes, idx)
		}
	}
	if unique {
		indexes = append(indexes, liveIndex{name: uniqueKeyName(table, column), unique: true, columns: []string{column}})
	}
	if len(pkCols) > 0 {
		defs = append(defs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}

	inbound, err := d.liveForeignKeys(r.ctx, r.tx, table, true)
	if err != nil {
		return err
	}
	for _, fk := range inbound {
		if err := r.exec(fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", quoteIdent(fk.table), quoteIdent(fk.name))); err != nil {
			return err
		}
	}

	tmp := table + rebuildSuffix
	columnList := strings.Join(names, ", ")
	copyRows := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s", quoteIdent(tmp), columnList, columnList, quoteIdent(table))
	if identity {
		copyRows = fmt.Sprintf("SET IDENTITY_INSERT %[1]s ON; %[2]s; SET IDENTITY_INSERT %[1]s OFF", quoteIdent(tmp), copyRows)
	}
	if err := r.exec(
		fmt.Sprintf("CREATE TABLE %s (%s)", quoteIdent(tmp), strings.Join(defs, ", ")),
		copyRows,
		"DROP TABLE "+quoteIdent(table),
		fmt.Sprintf("EXEC sp_rename %s, %s", quoteLiteral(quoteIdent(tmp)), quoteLiteral(table)),
	); err != nil {
		return err
	}

	if err := d.createIndexes(r, table, indexes); err != nil {
		return err
	}
	for _, fk := range append(live.foreignKeys, inbound...) {
		if err := r.exec(foreignKeySQL(fk.table, fk.name, fk.columns, fk.refTable, fk.refColumns, fk.onDelete, fk.onUpdate)); err != nil {
			return err
		}
	}
	return nil
}

// ---- Rendering ----

// applyOverride folds Column.Overrides["sqlserver"] into the column. Default
// is left alone: an override default is a raw SQL expression and is rendered
// by renderDefaultExpr.
func applyOverride(col schema.Column) schema.Column {
	ov, ok := col.Overrides[DriverName]
	if !ok {
		return col
	}
	if ov.Type != "" {
		col.Type = ov.Type
	}
	if ov.AutoInc != nil {
		col.AutoInc = *ov.AutoInc
	}
	return col
}

// columnDefinition renders everything of a column after its name: type,
// IDENTITY, nullability and default. The primary key and uniqueness are
// rendered by the callers.
func columnDefinition(raw schema.Column) (string, error) {
	col := applyOverride(raw)
	nativeType, err := renderSQLServerType(col.Type, col.Length)
	if err != nil {
		return "", err
	}
	if col.AutoInc {
		if col.Type != schema.ColTypeInteger && col.Type != schema.ColTypeBigInt {
			return "", behemotherr.NewMigrationError("SQLServerDriver.columnDefinition", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
				fmt.Errorf("column %q: AutoInc requires an integer column, got %q", col.Name, col.Type))
		}
		// An identity column can't have a default and is never NULL.
		return nativeType + " IDENTITY(1,1) NOT NULL", nil
	}
	def := nativeType + " " + nullability(col)
	expr, err := renderDefaultExpr(raw)
	if err != nil {
		return "", err
	}
	if expr != "" {
		def += " DEFAULT " + expr
	}
	return def, nil
}

func nullability(col schema.Column) string {
	if col.Nullable && !col.PrimaryKey {
		return "NULL"
	}
	return "NOT NULL"
}

// uniqueColumnIndex renders the unique index behind Column.Unique. It is an
// index rather than a UNIQUE constraint so that a nullable column can filter
// its NULLs out (see indexSQL).
func uniqueColumnIndex(table, column string, nullable bool) string {
	return indexSQL(table, uniqueKeyName(table, column), []string{column}, true, map[string]bool{column: nullable})
}

// indexSQL renders CREATE INDEX from physical names.
//
// SQL Server's unique indexes treat NULLs as equal, so a nullable unique
// column could hold a single NULL. Every other supported database lets any
// number of NULLs through. A unique index is therefore filtered to the rows
// whose nullable key columns are all set, which gives the same behavior: a
// row with a NULL in the key never conflicts.
func indexSQL(table, name string, columns []string, unique bool, nullable map[string]bool) string {
	quoted := make([]string, len(columns))
	var filter []string
	for i, c := range columns {
		quoted[i] = quoteIdent(c)
		if unique && nullable[c] {
			filter = append(filter, quoteIdent(c)+" IS NOT NULL")
		}
	}
	kw := "INDEX"
	if unique {
		kw = "UNIQUE INDEX"
	}
	stmt := fmt.Sprintf("CREATE %s %s ON %s (%s)", kw, quoteIdent(name), quoteIdent(table), strings.Join(quoted, ", "))
	if len(filter) > 0 {
		stmt += " WHERE " + strings.Join(filter, " AND ")
	}
	return stmt
}

// foreignKeySQL renders ADD CONSTRAINT ... FOREIGN KEY from physical names.
// onDelete and onUpdate are T-SQL actions; an empty one is left out.
func foreignKeySQL(table, name string, columns []string, refTable string, refColumns []string, onDelete, onUpdate string) string {
	stmt := fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s)",
		quoteIdent(table), quoteIdent(name), quoteIdents(columns), quoteIdent(refTable), quoteIdents(refColumns))
	if onDelete != "" {
		stmt += " ON DELETE " + onDelete
	}
	if onUpdate != "" {
		stmt += " ON UPDATE " + onUpdate
	}
	return stmt
}

// uniqueKeyName names the unique index behind Column.Unique, from physical
// names. A fixed name lets Introspect tell it from a unique index the
// application declared. A name over SQL Server's 128-character limit is cut
// and given a hash of the full name.
func uniqueKeyName(table, column string) string {
	name := table + "_" + column + "_key"
	if len(name) <= maxIdentifierLength {
		return name
	}
	h := fnv.New32a()
	h.Write([]byte(name))
	suffix := fmt.Sprintf("_%08x", h.Sum32())
	return name[:maxIdentifierLength-len(suffix)] + suffix
}

// renderDefaultExpr returns the DEFAULT expression for a column, or "" for
// none: the sqlserver override's raw expression if set (e.g.
// "sysutcdatetime()"), otherwise Column.Default rendered as a literal.
func renderDefaultExpr(raw schema.Column) (string, error) {
	if expr := raw.Overrides[DriverName].Default; expr != "" {
		return expr, nil
	}
	return renderLiteral(raw.Default)
}

// renderLiteral renders Column.Default, the forward counterpart of the
// introspector's sqlServerDefaultFromStored. Booleans are 1 and 0: SQL Server
// has no TRUE. Numbers arrive as float64 once a migration has round-tripped
// through its JSON file.
func renderLiteral(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "", nil
	case string:
		return quoteLiteral(val), nil
	case bool:
		if val {
			return "1", nil
		}
		return "0", nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val), nil
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32), nil
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	default:
		return "", behemotherr.NewMigrationError("SQLServerDriver.renderLiteral", behemotherr.ErrorCodeMigrationUnsupportedDefaultType, fmt.Errorf("cannot render default value of type %T", v))
	}
}

// renderSQLServerType is the forward (canonical -> native) type mapping. The
// reverse direction is mapSQLServerType in the introspector, and every type
// that doesn't survive the round trip has a rule in NormalizeColumn.
func renderSQLServerType(ct schema.ColumnType, length int) (string, error) {
	switch ct {
	case schema.ColTypeString:
		if length <= 0 {
			length = 255
		}
		if length > maxStringLength {
			return "NVARCHAR(MAX)", nil
		}
		return fmt.Sprintf("NVARCHAR(%d)", length), nil
	case schema.ColTypeText:
		return "NVARCHAR(MAX)", nil
	case schema.ColTypeInteger:
		return "INT", nil
	case schema.ColTypeBigInt:
		return "BIGINT", nil
	case schema.ColTypeReal:
		return "FLOAT", nil
	case schema.ColTypeNumeric:
		return "DECIMAL(38,10)", nil // a bare DECIMAL is DECIMAL(18,0) and drops the fraction
	case schema.ColTypeBoolean:
		return "BIT", nil
	case schema.ColTypeDateTime:
		return "DATETIME2(6)", nil
	case schema.ColTypeTimestamp:
		return "DATETIMEOFFSET(6)", nil
	case schema.ColTypeUuid:
		// Not UNIQUEIDENTIFIER: database/sql drivers scan that as 16 bytes in
		// SQL Server's mixed byte order, not as the text models hold.
		return "NCHAR(36)", nil
	case schema.ColTypeJson:
		return "NVARCHAR(MAX)", nil // the native json type only exists from SQL Server 2025
	case schema.ColTypeBytes, schema.ColTypeBlob:
		return "VARBINARY(MAX)", nil
	default:
		return "", behemotherr.NewMigrationError("SQLServerDriver.renderSQLServerType", behemotherr.ErrorCodeMigrationUnsupportedCanonicalType, fmt.Errorf("no SQL Server rendering for canonical type %q", ct))
	}
}

// mapFKAction renders a canonical action. SQL Server has no RESTRICT; NO
// ACTION rejects the delete the same way.
func mapFKAction(a schema.ForeignKeyAction) string {
	switch a {
	case schema.FKCascade:
		return "CASCADE"
	case schema.FKSetNull:
		return "SET NULL"
	default:
		return "NO ACTION"
	}
}

// quoteIdent quotes a table, column, index or constraint name with brackets,
// which works whatever the session's QUOTED_IDENTIFIER setting is.
func quoteIdent(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

func quoteIdents(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = quoteIdent(n)
	}
	return strings.Join(quoted, ", ")
}

// quoteLiteral renders s as a Unicode string literal.
func quoteLiteral(s string) string {
	return "N'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func replaceString(list []string, from, to string) []string {
	out := slices.Clone(list)
	for i, s := range out {
		if s == from {
			out[i] = to
		}
	}
	return out
}
