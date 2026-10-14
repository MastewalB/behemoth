package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/types/schema"
)

// DriverName is the key used for per-database Column.Overrides lookups.
const DriverName = "mysql"

const (
	// maxIdentifierLength is MySQL's limit for index and constraint names.
	// A longer name is an error, not a truncation as in Postgres.
	maxIdentifierLength = 64

	// keyPrefixLength is the number of characters (bytes for a BLOB) of a
	// TEXT or BLOB column that an index covers. MySQL can't index these
	// columns whole. 255 utf8mb4 characters take 1020 bytes, so three such
	// columns still fit InnoDB's 3072-byte key limit.
	keyPrefixLength = 255
)

// MySQLDriver implements [core.SchemaDriver], [core.MigrationRenderer],
// [core.SchemaIntrospector] and [core.ColumnNormalizer] for MySQL 8.0.13 and
// later (the first version with expression defaults).
//
// It is the migration counterpart of MySQLAdapter: build both with the same
// resolver so queries and migrations agree on physical names.
//
// ApplyMigration and RenderMigration build their statements through the same
// planner (plan), so the rendered script holds the statements Apply executes.
// Unlike Postgres, the planner reads the live schema in one case: an index on
// a TEXT or BLOB column needs a prefix length, so it has to know the column's
// type.
//
// The driver never imports a database/sql driver itself: the caller picks one
// and hands over an opened *sql.DB.
type MySQLDriver struct {
	db       *sql.DB
	resolver core.SchemaResolver
}

// NewMySQLDriver returns a driver bound to db, operating in the connection's
// default database (DATABASE()). A nil resolver maps every canonical
// table/column name to itself.
func NewMySQLDriver(db *sql.DB, resolver core.SchemaResolver) *MySQLDriver {
	return &MySQLDriver{db: db, resolver: adapters.ResolverOrIdentity(resolver)}
}

var (
	_ core.SchemaDriver       = (*MySQLDriver)(nil)
	_ core.MigrationRenderer  = (*MySQLDriver)(nil)
	_ core.SchemaIntrospector = (*MySQLDriver)(nil)
	_ core.ColumnNormalizer   = (*MySQLDriver)(nil)
)

// AtomicityLevel implements [core.SchemaDriver]. MySQL commits every DDL
// statement as it runs, so a migration that fails midway keeps the statements
// that already ran. Only the ledger row and the snapshot are written in a
// transaction.
func (d *MySQLDriver) AtomicityLevel() core.AtomicityLevel { return core.AtomicityBestEffort }

// ApplyMigration implements [core.SchemaDriver]. It runs every Up operation,
// then writes the ledger row and the snapshot in one transaction.
//
// Nothing is executed when the migration is malformed or already recorded:
// both are checked before the first statement. A failure after that leaves the
// earlier operations applied and the migration unrecorded; the error names
// them.
func (d *MySQLDriver) ApplyMigration(ctx context.Context, req core.MigrationRequest) error {
	const op = "MySQLDriver.ApplyMigration"
	return d.withMigrationLock(ctx, op, req, func(conn *sql.Conn) error {
		steps, err := d.plan(ctx, conn, req.Migration.Up)
		if err != nil {
			return err
		}
		if err := d.prepareLedger(ctx, conn, op, req); err != nil {
			return err
		}
		for i, st := range steps {
			if err := d.runStep(ctx, conn, st); err != nil {
				err = behemotherr.WrapOp(op, fmt.Sprintf("operation %q (%s on %s)", st.op.ID, st.op.Kind, st.op.Table), err)
				if i == 0 {
					return err
				}
				return fmt.Errorf("%w; MySQL can't roll back DDL: the %d operation(s) before it stay applied (%s) and migration %q is not recorded",
					err, i, strings.Join(operationIDs(steps[:i]), ", "), req.Migration.ID)
			}
		}
		if err := d.record(ctx, conn, op, req); err != nil {
			if len(steps) == 0 {
				return err
			}
			return fmt.Errorf("%w; the schema changes of migration %q are applied but not recorded", err, req.Migration.ID)
		}
		return nil
	})
}

// RecordBaseline implements [core.SchemaDriver]: the same ledger and snapshot
// write as ApplyMigration, with no DDL executed.
func (d *MySQLDriver) RecordBaseline(ctx context.Context, req core.MigrationRequest) error {
	const op = "MySQLDriver.RecordBaseline"
	return d.withMigrationLock(ctx, op, req, func(conn *sql.Conn) error {
		if err := d.prepareLedger(ctx, conn, op, req); err != nil {
			return err
		}
		return d.record(ctx, conn, op, req)
	})
}

// withMigrationLock runs fn on one connection while holding a named lock
// keyed on the ledger table. The lock serializes concurrent migrators (several
// app instances booting at once): the second one waits, then finds the ledger
// row and fails before running any DDL.
//
// MySQL has no transaction-scoped advisory lock, and a transaction couldn't
// hold one across DDL anyway. GET_LOCK belongs to the session, which is why
// everything runs on a single *sql.Conn. The server releases the lock itself
// if the session dies.
func (d *MySQLDriver) withMigrationLock(ctx context.Context, op string, req core.MigrationRequest, fn func(conn *sql.Conn) error) error {
	if req.LedgerTable == "" || req.SnapshotTable == "" {
		return behemotherr.NewInternalError(op, fmt.Errorf("ledger table %q / snapshot table %q must both be set", req.LedgerTable, req.SnapshotTable))
	}
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationConnFailed, err)
	}
	defer conn.Close()

	lock := migrationLockName(req.LedgerTable)
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, -1)", lock).Scan(&got); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationLockFailed, err)
	}
	if got.Int64 != 1 {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationLockFailed, fmt.Errorf("GET_LOCK(%q) was not granted", lock))
	}
	// Released even when ctx is already cancelled, so the pooled connection
	// doesn't keep the lock.
	defer conn.ExecContext(context.WithoutCancel(ctx), "DO RELEASE_LOCK(?)", lock)

	return fn(conn)
}

// migrationLockName stays within MySQL's 64-character limit for lock names
// whatever the ledger table is called.
func migrationLockName(ledgerTable string) string {
	h := fnv.New64a()
	h.Write([]byte(ledgerTable))
	return fmt.Sprintf("behemoth.migration.%x", h.Sum64())
}

func operationIDs(steps []step) []string {
	ids := make([]string, len(steps))
	for i, st := range steps {
		ids[i] = st.op.ID
	}
	return ids
}

func (d *MySQLDriver) runStep(ctx context.Context, conn *sql.Conn, st step) error {
	if st.guard != nil {
		if err := st.guard(ctx, conn); err != nil {
			return err
		}
	}
	for _, stmt := range st.stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return behemotherr.NewMigrationError("MySQLDriver.runStep", behemotherr.ErrorCodeMigrationExecFailed, fmt.Errorf("%w (sql: %s)", err, stmt))
		}
	}
	return nil
}

// ---- Ledger & snapshot ----

// prepareLedger creates the ledger and snapshot tables on first use and
// rejects a migration that is already recorded. It runs before any DDL of the
// migration, because that DDL could not be rolled back when the ledger insert
// fails on the duplicate afterwards.
func (d *MySQLDriver) prepareLedger(ctx context.Context, conn *sql.Conn, op string, req core.MigrationRequest) error {
	stmts := []string{
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id VARCHAR(255) NOT NULL, applied_at DATETIME(6) NOT NULL, PRIMARY KEY (id))", quoteIdent(req.LedgerTable)),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id INT NOT NULL, version VARCHAR(255) NOT NULL, tables JSON NOT NULL, PRIMARY KEY (id))", quoteIdent(req.SnapshotTable)),
	}
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, err)
		}
	}

	var one int
	err := conn.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE id = ?", quoteIdent(req.LedgerTable)), req.LedgerEntry.ID).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationQueryFailed, err)
	default:
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationApplyFailed, fmt.Errorf("migration %q is already recorded in %s", req.LedgerEntry.ID, req.LedgerTable))
	}
}

// record writes the ledger row and replaces the snapshot in one transaction.
func (d *MySQLDriver) record(ctx context.Context, conn *sql.Conn, op string, req core.MigrationRequest) error {
	data, err := json.Marshal(req.SnapshotUpdate.Tables)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationMarshalFailed, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationBeginTxFailed, err)
	}
	insert := fmt.Sprintf("INSERT INTO %s (id, applied_at) VALUES (?, ?)", quoteIdent(req.LedgerTable))
	// VALUES() rather than a row alias: the alias form needs MySQL 8.0.19.
	upsert := fmt.Sprintf("INSERT INTO %s (id, version, tables) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE version = VALUES(version), tables = VALUES(tables)", quoteIdent(req.SnapshotTable))

	if _, err := tx.ExecContext(ctx, insert, req.LedgerEntry.ID, req.LedgerEntry.AppliedAt); err != nil {
		tx.Rollback()
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	// Passed as text: a []byte parameter is sent as binary, which MySQL rejects for a JSON column.
	if _, err := tx.ExecContext(ctx, upsert, req.SnapshotUpdate.Version, string(data)); err != nil {
		tx.Rollback()
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationCommitFailed, err)
	}
	return nil
}

// ---- core.MigrationRenderer ----

// RenderMigration implements [core.MigrationRenderer]. It prints every
// operation's statements in Up order, as ApplyMigration executes them.
//
// It reads the live schema for the type of an indexed column the migration
// itself doesn't define (see keyPrefixes), so it should run against the
// database the migration will be applied to. It changes nothing.
//
// The check ApplyMigration makes before adding a NOT NULL column without a
// default (see buildAddColumn) is not a statement and is not in the script.
func (d *MySQLDriver) RenderMigration(ctx context.Context, m core.Migration) (string, error) {
	steps, err := d.plan(ctx, d.db, m.Up)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "-- Migration: %s\n-- Generated: %s\n", m.ID, m.CreatedAt.Format(time.RFC3339))
	if m.IsBaseline {
		b.WriteString("-- Baseline: records the existing schema; never executed by the runner.\n")
	}
	b.WriteString("\n")
	for _, st := range steps {
		for _, stmt := range st.stmts {
			fmt.Fprintf(&b, "%s;\n", stmt)
		}
	}
	return b.String(), nil
}

// FileExtension implements [core.MigrationRenderer].
func (d *MySQLDriver) FileExtension() string { return ".sql" }

// ---- Planning ----

// step is one operation with the statements that apply it.
type step struct {
	op    core.SchemaOperation
	stmts []string
	// guard, when set, runs right before stmts and stops the migration by
	// returning an error. It covers a case MySQL accepts silently and the
	// driver contract rejects.
	guard func(ctx context.Context, q adapters.Querier) error
}

// plan turns ops into statements without executing anything. An operation
// missing its required payload is an Internal error, never a silent no-op.
func (d *MySQLDriver) plan(ctx context.Context, q adapters.Querier, ops []core.SchemaOperation) ([]step, error) {
	prefixes := &keyPrefixes{ctx: ctx, q: q, resolver: d.resolver, known: map[string]map[string]bool{}}
	steps := make([]step, 0, len(ops))
	for _, op := range ops {
		st, err := d.planOperation(op, prefixes)
		if err != nil {
			return nil, err
		}
		steps = append(steps, st)
	}
	return steps, nil
}

func (d *MySQLDriver) planOperation(op core.SchemaOperation, prefixes *keyPrefixes) (step, error) {
	missing := func(field string) (step, error) {
		return step{}, behemotherr.NewInternalError("MySQLDriver.planOperation", fmt.Errorf("operation %q: %s missing %s", op.ID, op.Kind, field))
	}
	one := func(stmt string, err error) (step, error) {
		if err != nil {
			return step{}, err
		}
		return step{op: op, stmts: []string{stmt}}, nil
	}

	switch op.Kind {
	case core.OpCreateTable:
		if op.NewTable == nil {
			return missing("NewTable")
		}
		for _, col := range op.NewTable.Columns {
			prefixes.set(op.NewTable.Name, col)
		}
		return one(d.buildCreateTable(*op.NewTable))
	case core.OpDropTable:
		prefixes.forgetTable(op.Table)
		return one(d.buildDropTable(op.Table), nil)
	case core.OpAddColumn:
		if op.Column == nil {
			return missing("Column")
		}
		prefixes.set(op.Table, *op.Column)
		st, err := one(d.buildAddColumn(op.Table, *op.Column))
		if err == nil && fillsExistingRows(*op.Column) {
			st.guard = d.emptyTableGuard(op.Table, op.Column.Name)
		}
		return st, err
	case core.OpDropColumn:
		return one(d.buildDropColumn(op.Table, op.ColumnName), nil)
	case core.OpRenameColumn:
		if err := prefixes.rename(op.Table, op.ColumnName, op.NewColumnName); err != nil {
			return step{}, err
		}
		return one(d.buildRenameColumn(op.Table, op.ColumnName, op.NewColumnName), nil)
	case core.OpAlterColumn:
		if op.Column == nil {
			return missing("Column")
		}
		prefixes.set(op.Table, *op.Column)
		return one(d.buildAlterColumn(op.Table, *op.Column, op.PrevColumn))
	case core.OpAddIndex:
		if op.Index == nil {
			return missing("Index")
		}
		return one(d.buildAddIndex(op.Table, *op.Index, prefixes))
	case core.OpDropIndex:
		return one(d.buildDropIndex(op.Table, op.IndexName), nil)
	case core.OpAddForeignKey:
		if op.ForeignKey == nil {
			return missing("ForeignKey")
		}
		return one(d.buildAddForeignKey(op.Table, *op.ForeignKey))
	case core.OpDropForeignKey:
		return one(d.buildDropForeignKey(op.Table, op.ForeignKeyName), nil)
	default:
		return step{}, behemotherr.NewInternalError("MySQLDriver.planOperation", fmt.Errorf("operation %q: unknown Kind %q", op.ID, op.Kind))
	}
}

// keyPrefixes answers whether a column needs a prefix length when it is
// indexed, which is the case for TEXT and BLOB columns.
//
// Columns the migration itself creates or alters are known from its
// operations (known), so a table created and indexed by the same migration
// renders before it exists. Any other column is looked up in the live schema.
type keyPrefixes struct {
	ctx      context.Context
	q        adapters.Querier
	resolver core.SchemaResolver
	known    map[string]map[string]bool // canonical table -> canonical column -> needs a prefix
}

func (k *keyPrefixes) set(table string, col schema.Column) {
	k.put(table, col.Name, needsKeyPrefix(applyOverride(col).Type))
}

func (k *keyPrefixes) put(table, column string, needs bool) {
	if k.known[table] == nil {
		k.known[table] = map[string]bool{}
	}
	k.known[table][column] = needs
}

func (k *keyPrefixes) forgetTable(table string) { delete(k.known, table) }

func (k *keyPrefixes) rename(table, from, to string) error {
	needs, err := k.needs(table, from)
	if err != nil {
		return err
	}
	delete(k.known[table], from)
	k.put(table, to, needs)
	return nil
}

// needs reports whether table.column (canonical names) is a TEXT or BLOB
// column. A column that doesn't exist reports false: the statement using it
// fails on its own with MySQL's error.
func (k *keyPrefixes) needs(table, column string) (bool, error) {
	if needs, ok := k.known[table][column]; ok {
		return needs, nil
	}
	var dataType string
	err := k.q.QueryRowContext(k.ctx, `
		SELECT DATA_TYPE FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		k.resolver.Resolve(table), k.resolver.ResolveColumn(table, column)).Scan(&dataType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, behemotherr.NewMigrationError("MySQLDriver.keyPrefixes", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	ct, _ := mapMySQLType(dataType, dataType)
	needs := err == nil && needsKeyPrefix(ct)
	k.put(table, column, needs)
	return needs, nil
}

// needsKeyPrefix reports whether ct is rendered as a TEXT or BLOB type.
func needsKeyPrefix(ct schema.ColumnType) bool {
	switch ct {
	case schema.ColTypeText, schema.ColTypeBlob, schema.ColTypeBytes:
		return true
	}
	return false
}

// keyPart renders one indexed column, with a prefix length where MySQL needs one.
func keyPart(physicalColumn string, prefixed bool) string {
	if prefixed {
		return fmt.Sprintf("%s(%d)", quoteIdent(physicalColumn), keyPrefixLength)
	}
	return quoteIdent(physicalColumn)
}

// ---- SQL builders ----

// buildCreateTable renders columns, the primary key and one unique key per
// unique column.
//
// t.ForeignKeys and t.Indexes are not read here: foreign keys arrive as their
// own OpAddForeignKey (enforced upstream by MigrationGenerator's
// checkNoInlineForeignKeys) and indexes as their own OpAddIndex.
func (d *MySQLDriver) buildCreateTable(t schema.Table) (string, error) {
	var defs, pkCols, uniques []string
	for _, raw := range t.Columns {
		def, err := d.renderColumnDefinition(t.Name, raw)
		if err != nil {
			return "", err
		}
		defs = append(defs, def)
		col := applyOverride(raw)
		switch {
		case col.PrimaryKey:
			pkCols = append(pkCols, quoteIdent(d.resolver.ResolveColumn(t.Name, col.Name)))
		case col.Unique:
			uniques = append(uniques, d.uniqueKeyDefinition(t.Name, col))
		}
	}
	if len(pkCols) > 0 {
		defs = append(defs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}
	defs = append(defs, uniques...)
	return fmt.Sprintf("CREATE TABLE %s (%s)", quoteIdent(d.resolver.Resolve(t.Name)), strings.Join(defs, ", ")), nil
}

func (d *MySQLDriver) buildDropTable(table string) string {
	return "DROP TABLE " + quoteIdent(d.resolver.Resolve(table))
}

// buildAddColumn adds the column and, for a unique one, its unique key in the
// same ALTER TABLE, so the two succeed or fail together.
func (d *MySQLDriver) buildAddColumn(table string, raw schema.Column) (string, error) {
	def, err := d.renderColumnDefinition(table, raw)
	if err != nil {
		return "", err
	}
	col := applyOverride(raw)
	stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", quoteIdent(d.resolver.Resolve(table)), def)
	switch {
	case col.PrimaryKey:
		stmt += " PRIMARY KEY"
	case col.Unique:
		stmt += ", ADD " + d.uniqueKeyDefinition(table, col)
	}
	return stmt, nil
}

// fillsExistingRows reports whether adding col to a populated table would make
// MySQL invent a value for the existing rows: a NOT NULL column with no
// default gets the type's implicit one (” or 0) instead of an error, even in
// strict mode.
func fillsExistingRows(raw schema.Column) bool {
	col := applyOverride(raw)
	expr, err := renderDefaultExpr(raw)
	return err == nil && expr == "" && !col.AutoInc && (!col.Nullable || col.PrimaryKey)
}

// emptyTableGuard fails when table has rows. Postgres and SQLite reject adding
// a NOT NULL column without a default to a populated table; this keeps MySQL
// to the same contract instead of filling the rows silently.
func (d *MySQLDriver) emptyTableGuard(table, column string) func(context.Context, adapters.Querier) error {
	return func(ctx context.Context, q adapters.Querier) error {
		var one int
		err := q.QueryRowContext(ctx, "SELECT 1 FROM "+quoteIdent(d.resolver.Resolve(table))+" LIMIT 1").Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return behemotherr.NewMigrationError("MySQLDriver.emptyTableGuard", behemotherr.ErrorCodeMigrationQueryFailed, err)
		}
		return behemotherr.NewMigrationError("MySQLDriver.emptyTableGuard", behemotherr.ErrorCodeMigrationExecFailed,
			fmt.Errorf("column %q is NOT NULL and has no default, and table %q has rows: give it a default or make it nullable", column, table))
	}
}

// buildDropColumn: MySQL removes the column from every index it is part of,
// and drops an index left without columns.
func (d *MySQLDriver) buildDropColumn(table, column string) string {
	return fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s",
		quoteIdent(d.resolver.Resolve(table)), quoteIdent(d.resolver.ResolveColumn(table, column)))
}

func (d *MySQLDriver) buildRenameColumn(table, oldName, newName string) string {
	return fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s",
		quoteIdent(d.resolver.Resolve(table)),
		quoteIdent(d.resolver.ResolveColumn(table, oldName)),
		quoteIdent(d.resolver.ResolveColumn(table, newName)))
}

// buildAlterColumn redefines the column with MODIFY COLUMN, which replaces
// its type, nullability, default and AUTO_INCREMENT at once and keeps its
// position, its indexes and the primary key. AUTO_INCREMENT therefore follows
// the declaration; when added to a populated column MySQL continues past the
// largest existing value.
//
// Uniqueness lives in a named unique key (see uniqueKeyName) and is only
// changed when prev, the operation's PrevColumn, says it differs. Without
// prev it is left as it is.
func (d *MySQLDriver) buildAlterColumn(table string, raw schema.Column, prevRaw *schema.Column) (string, error) {
	def, err := d.renderColumnDefinition(table, raw)
	if err != nil {
		return "", err
	}
	col := applyOverride(raw)
	stmt := fmt.Sprintf("ALTER TABLE %s MODIFY COLUMN %s", quoteIdent(d.resolver.Resolve(table)), def)

	if prevRaw != nil && !col.PrimaryKey {
		switch prev := applyOverride(*prevRaw); {
		case col.Unique && !prev.Unique:
			stmt += ", ADD " + d.uniqueKeyDefinition(table, col)
		case !col.Unique && prev.Unique:
			name := uniqueKeyName(d.resolver.Resolve(table), d.resolver.ResolveColumn(table, col.Name))
			stmt += ", DROP INDEX " + quoteIdent(name)
		}
	}
	return stmt, nil
}

func (d *MySQLDriver) buildAddIndex(table string, idx schema.Index, prefixes *keyPrefixes) (string, error) {
	if len(idx.Columns) == 0 {
		return "", behemotherr.NewMigrationError("MySQLDriver.AddIndex", behemotherr.ErrorCodeMigrationInvalidIndex, fmt.Errorf("index %q has no columns", idx.Name))
	}
	cols := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		prefixed, err := prefixes.needs(table, c)
		if err != nil {
			return "", err
		}
		cols[i] = keyPart(d.resolver.ResolveColumn(table, c), prefixed)
	}
	uniqueKw := ""
	if idx.Unique {
		uniqueKw = "UNIQUE "
	}
	return fmt.Sprintf("CREATE %sINDEX %s ON %s (%s)",
		uniqueKw, quoteIdent(idx.Name), quoteIdent(d.resolver.Resolve(table)), strings.Join(cols, ", ")), nil
}

// buildDropIndex: MySQL index names are scoped to their table.
func (d *MySQLDriver) buildDropIndex(table, indexName string) string {
	return fmt.Sprintf("DROP INDEX %s ON %s", quoteIdent(indexName), quoteIdent(d.resolver.Resolve(table)))
}

// buildAddForeignKey: when no index starts with the key's columns, MySQL
// creates one named after the constraint. Introspect leaves that index out.
func (d *MySQLDriver) buildAddForeignKey(table string, fk schema.ForeignKey) (string, error) {
	if len(fk.Columns) == 0 || len(fk.Columns) != len(fk.RefColumns) {
		return "", behemotherr.NewMigrationError("MySQLDriver.AddForeignKey", behemotherr.ErrorCodeMigrationInvalidForeignKey,
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
	return fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s",
		quoteIdent(d.resolver.Resolve(table)), quoteIdent(fk.Name), strings.Join(cols, ", "),
		quoteIdent(d.resolver.Resolve(fk.RefTable)), strings.Join(refCols, ", "), mapFKAction(fk.OnDelete)), nil
}

// buildDropForeignKey drops the constraint only. The index MySQL created for
// it (see buildAddForeignKey) stays: whether it was created for the key or
// existed before can't be told from the operation.
func (d *MySQLDriver) buildDropForeignKey(table, fkName string) string {
	return fmt.Sprintf("ALTER TABLE %s DROP FOREIGN KEY %s", quoteIdent(d.resolver.Resolve(table)), quoteIdent(fkName))
}

// ---- Rendering ----

// applyOverride folds Column.Overrides["mysql"] into the column. Default is
// left alone: an override default is a raw SQL expression and is rendered by
// renderDefaultExpr.
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

// renderColumnDefinition renders one column: name, type, nullability, default
// and AUTO_INCREMENT. The primary key and uniqueness are separate key
// definitions (buildCreateTable, buildAddColumn, buildAlterColumn), so the
// same definition serves CREATE TABLE, ADD COLUMN and MODIFY COLUMN.
func (d *MySQLDriver) renderColumnDefinition(table string, raw schema.Column) (string, error) {
	col := applyOverride(raw)
	nativeType, err := renderMySQLType(col.Type, col.Length)
	if err != nil {
		return "", err
	}

	parts := []string{quoteIdent(d.resolver.ResolveColumn(table, col.Name)), nativeType}
	if !col.Nullable || col.PrimaryKey {
		parts = append(parts, "NOT NULL")
	} else {
		parts = append(parts, "NULL")
	}
	if col.AutoInc {
		if col.Type != schema.ColTypeInteger && col.Type != schema.ColTypeBigInt {
			return "", behemotherr.NewMigrationError("MySQLDriver.renderColumnDefinition", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
				fmt.Errorf("column %q: AutoInc requires an integer column, got %q", col.Name, col.Type))
		}
		// An AUTO_INCREMENT column can't have a default. MySQL also requires
		// it to be a key and reports that itself.
		return strings.Join(append(parts, "AUTO_INCREMENT"), " "), nil
	}
	expr, err := renderDefaultExpr(raw)
	if err != nil {
		return "", err
	}
	if expr != "" {
		parts = append(parts, "DEFAULT "+expr)
	}
	return strings.Join(parts, " "), nil
}

// uniqueKeyDefinition renders the unique key of a unique column.
func (d *MySQLDriver) uniqueKeyDefinition(table string, col schema.Column) string {
	physTable, physCol := d.resolver.Resolve(table), d.resolver.ResolveColumn(table, col.Name)
	return fmt.Sprintf("UNIQUE KEY %s (%s)", quoteIdent(uniqueKeyName(physTable, physCol)), keyPart(physCol, needsKeyPrefix(col.Type)))
}

// uniqueKeyName names the unique key behind Column.Unique, from physical
// names. A fixed name lets buildAlterColumn drop the key later and lets
// Introspect tell it from a unique index the application declared.
//
// A name over MySQL's 64-character limit is cut and given a hash of the full
// name, so two long names that share a prefix stay distinct.
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

// needsExpressionDefault reports whether ct is rendered as a type whose
// default MySQL only accepts as a parenthesized expression: TEXT, BLOB and
// JSON columns can't have a literal default.
func needsExpressionDefault(ct schema.ColumnType) bool {
	return needsKeyPrefix(ct) || ct == schema.ColTypeJson
}

// renderDefaultExpr returns what follows DEFAULT for a column, or "" for no
// default:
//   - the mysql override's raw expression in parentheses, e.g. "(now(6))".
//     MySQL requires the parentheses for everything except CURRENT_TIMESTAMP.
//   - otherwise Column.Default as a literal. On a TEXT, BLOB or JSON column
//     it is rendered as a quoted string in parentheses, the only form MySQL
//     accepts there.
//
// storedDefault describes what MySQL reports for each of these; the two must
// change together.
func renderDefaultExpr(raw schema.Column) (string, error) {
	if expr := raw.Overrides[DriverName].Default; expr != "" {
		return "(" + expr + ")", nil
	}
	if raw.Default == nil {
		return "", nil
	}
	text, err := literalText(raw.Default)
	if err != nil {
		return "", err
	}
	if needsExpressionDefault(applyOverride(raw).Type) {
		return "(" + quoteLiteral(text) + ")", nil
	}
	switch v := raw.Default.(type) {
	case string:
		return quoteLiteral(text), nil
	case bool:
		if v {
			return "TRUE", nil
		}
		return "FALSE", nil
	default:
		return text, nil
	}
}

// literalText returns Column.Default as MySQL reports a literal default in
// information_schema: the bare text, with booleans as 1 and 0. Numbers arrive
// as float64 once a migration has round-tripped through its JSON file.
func literalText(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
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
		return "", behemotherr.NewMigrationError("MySQLDriver.literalText", behemotherr.ErrorCodeMigrationUnsupportedDefaultType, fmt.Errorf("cannot render default value of type %T", v))
	}
}

// renderMySQLType is the forward (canonical -> native) type mapping. The
// reverse direction is mysqlTypeMapping in the introspector, and every type
// that doesn't survive the round trip has a rule in NormalizeColumn.
func renderMySQLType(ct schema.ColumnType, length int) (string, error) {
	switch ct {
	case schema.ColTypeString:
		if length <= 0 {
			length = 255
		}
		return fmt.Sprintf("VARCHAR(%d)", length), nil
	case schema.ColTypeText:
		return "LONGTEXT", nil // TEXT stops at 64KB; the canonical type has no limit
	case schema.ColTypeInteger:
		return "INT", nil
	case schema.ColTypeBigInt:
		return "BIGINT", nil
	case schema.ColTypeReal:
		return "DOUBLE", nil
	case schema.ColTypeNumeric:
		return "DECIMAL(65,30)", nil // a bare DECIMAL is DECIMAL(10,0) and drops the fraction
	case schema.ColTypeBoolean:
		return "TINYINT(1)", nil
	case schema.ColTypeDateTime, schema.ColTypeTimestamp:
		// DATETIME for both: MySQL's TIMESTAMP ends in 2038 and shifts values
		// by the session time zone.
		return "DATETIME(6)", nil
	case schema.ColTypeUuid:
		return "CHAR(36)", nil
	case schema.ColTypeJson:
		return "JSON", nil
	case schema.ColTypeBytes, schema.ColTypeBlob:
		return "LONGBLOB", nil
	default:
		return "", behemotherr.NewMigrationError("MySQLDriver.renderMySQLType", behemotherr.ErrorCodeMigrationUnsupportedCanonicalType, fmt.Errorf("no MySQL rendering for canonical type %q", ct))
	}
}

func mapFKAction(a schema.ForeignKeyAction) string {
	switch a {
	case schema.FKCascade:
		return "CASCADE"
	case schema.FKSetNull:
		return "SET NULL"
	default:
		return "RESTRICT"
	}
}

// quoteIdent quotes a table, column, index or constraint name with backticks,
// which works whatever the server's ANSI_QUOTES setting is.
func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// quoteLiteral renders s as a SQL string literal. Backslashes are doubled
// because MySQL treats them as escapes unless NO_BACKSLASH_ESCAPES is set.
func quoteLiteral(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, "'", "''").Replace(s) + "'"
}
