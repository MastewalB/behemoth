package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/types/schema"
)

// DriverName is the key used for per-database Column.Overrides lookups.
const DriverName = "postgres"

// PostgreSQLDriver implements [core.SchemaDriver], [core.MigrationRenderer]
// and [core.SchemaIntrospector] for PostgreSQL.
//
// Every operation is rendered by pure SQL builders (buildOperationSQL);
// ApplyMigration executes their output and RenderMigration prints it, so the
// rendered script is by construction exactly what gets applied.
//
// The driver never imports a database/sql driver itself: the caller picks one
// (lib/pq, pgx/stdlib, ...) and hands over an opened *sql.DB.
type PostgreSQLDriver struct {
	db       *sql.DB
	resolver core.SchemaResolver
}

// NewPostgreSQLDriver returns a driver bound to db, operating in the
// connection's current_schema(). A nil resolver maps every canonical
// table/column name to itself.
func NewPostgreSQLDriver(db *sql.DB, resolver core.SchemaResolver) *PostgreSQLDriver {
	return &PostgreSQLDriver{db: db, resolver: adapters.ResolverOrIdentity(resolver)}
}

var (
	_ core.SchemaDriver       = (*PostgreSQLDriver)(nil)
	_ core.MigrationRenderer  = (*PostgreSQLDriver)(nil)
	_ core.SchemaIntrospector = (*PostgreSQLDriver)(nil)
	_ core.ColumnNormalizer   = (*PostgreSQLDriver)(nil)
)

// AtomicityLevel implements [core.SchemaDriver]. Postgres DDL is fully transactional.
func (d *PostgreSQLDriver) AtomicityLevel() core.AtomicityLevel { return core.AtomicityFull }

// ApplyMigration implements [core.SchemaDriver]: every Up operation, the
// ledger row and the snapshot upsert commit or roll back together.
func (d *PostgreSQLDriver) ApplyMigration(ctx context.Context, req core.MigrationRequest) error {
	return d.inMigrationTx(ctx, "PostgresDriver.ApplyMigration", req, func(tx *sql.Tx) error {
		for _, op := range req.Migration.Up {
			if err := d.applyOperationTx(ctx, tx, op); err != nil {
				return behemotherr.WrapOp("PostgresDriver.ApplyMigration", fmt.Sprintf("operation %q (%s on %s)", op.ID, op.Kind, op.Table), err)
			}
		}
		return nil
	})
}

// RecordBaseline implements [core.SchemaDriver]: the same ledger+snapshot
// write as ApplyMigration, with no DDL executed.
func (d *PostgreSQLDriver) RecordBaseline(ctx context.Context, req core.MigrationRequest) error {
	return d.inMigrationTx(ctx, "PostgresDriver.RecordBaseline", req, func(*sql.Tx) error { return nil })
}

// inMigrationTx runs fn, then the ledger+snapshot writes, in one transaction.
//
// A transaction-scoped advisory lock keyed on the ledger table serializes
// concurrent migrators (e.g. several app instances booting at once): the
// second one blocks until the first commits, then fails on the duplicate
// ledger row instead of applying the same DDL twice.
func (d *PostgreSQLDriver) inMigrationTx(ctx context.Context, op string, req core.MigrationRequest, fn func(tx *sql.Tx) error) error {
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

	run := func() error {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockKey(req.LedgerTable)); err != nil {
			return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationLockFailed, err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		return d.recordTx(ctx, tx, req)
	}
	if err := run(); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationCommitFailed, err)
	}
	return nil
}

func advisoryLockKey(ledgerTable string) int64 {
	h := fnv.New64a()
	h.Write([]byte("behemoth.migration:" + ledgerTable))
	return int64(h.Sum64())
}

func (d *PostgreSQLDriver) applyOperationTx(ctx context.Context, tx *sql.Tx, op core.SchemaOperation) error {
	stmts, err := d.buildOperationSQL(op)
	if err != nil {
		return err
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return behemotherr.NewMigrationError("PostgresDriver.applyOperationTx", behemotherr.ErrorCodeMigrationExecFailed, fmt.Errorf("%w (sql: %s)", err, stmt))
		}
	}
	return nil
}

// ---- Ledger & snapshot ----

func (d *PostgreSQLDriver) recordTx(ctx context.Context, tx *sql.Tx, req core.MigrationRequest) error {
	if err := d.ensureBookkeepingTables(ctx, tx, req.LedgerTable, req.SnapshotTable); err != nil {
		return err
	}
	if err := d.insertLedgerTx(ctx, tx, req.LedgerTable, req.LedgerEntry); err != nil {
		return err
	}
	return d.upsertSnapshotTx(ctx, tx, req.SnapshotTable, req.SnapshotUpdate)
}

// ensureBookkeepingTables creates the ledger and snapshot tables on first use,
// inside the same transaction as the migration that needs them.
func (d *PostgreSQLDriver) ensureBookkeepingTables(ctx context.Context, tx *sql.Tx, ledgerTable, snapshotTable string) error {
	if ledgerTable == "" || snapshotTable == "" {
		return behemotherr.NewInternalError("PostgresDriver.ensureBookkeepingTables", fmt.Errorf("ledger table %q / snapshot table %q must both be set", ledgerTable, snapshotTable))
	}
	stmts := []string{
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)", quoteIdent(ledgerTable)),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY, version TEXT NOT NULL, tables JSONB NOT NULL)", quoteIdent(snapshotTable)),
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return behemotherr.NewMigrationError("PostgresDriver.ensureBookkeepingTables", behemotherr.ErrorCodeMigrationExecFailed, err)
		}
	}
	return nil
}

func (d *PostgreSQLDriver) insertLedgerTx(ctx context.Context, tx *sql.Tx, table string, entry core.MigrationLedgerEntry) error {
	query := fmt.Sprintf("INSERT INTO %s (id, applied_at) VALUES ($1, $2)", quoteIdent(table))
	if _, err := tx.ExecContext(ctx, query, entry.ID, entry.AppliedAt); err != nil {
		return behemotherr.NewMigrationError("PostgresDriver.insertLedger", behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	return nil
}

func (d *PostgreSQLDriver) upsertSnapshotTx(ctx context.Context, tx *sql.Tx, table string, snap core.SchemaSnapshot) error {
	data, err := json.Marshal(snap.Tables)
	if err != nil {
		return behemotherr.NewMigrationError("PostgresDriver.upsertSnapshot", behemotherr.ErrorCodeMigrationMarshalFailed, err)
	}
	// Passed as text and cast: a []byte parameter would be sent as bytea.
	query := fmt.Sprintf(`INSERT INTO %s (id, version, tables) VALUES (1, $1, $2::jsonb)
		ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, tables = EXCLUDED.tables`, quoteIdent(table))
	if _, err := tx.ExecContext(ctx, query, snap.Version, string(data)); err != nil {
		return behemotherr.NewMigrationError("PostgresDriver.upsertSnapshot", behemotherr.ErrorCodeMigrationExecFailed, err)
	}
	return nil
}

// ---- core.MigrationRenderer ----

// RenderMigration implements [core.MigrationRenderer]. It flattens every
// operation's statement(s) in Up order, each individually terminated, in the
// EXACT order ApplyMigration executes them, so the file is a truthful
// preview/record of what ran or will run. Postgres rendering is pure — no
// live schema is consulted — so ctx is unused.
func (d *PostgreSQLDriver) RenderMigration(_ context.Context, m core.Migration) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "-- Migration: %s\n-- Generated: %s\n", m.ID, m.CreatedAt.Format(time.RFC3339))
	if m.IsBaseline {
		b.WriteString("-- Baseline: records the existing schema; never executed by the runner.\n")
	}
	b.WriteString("\n")
	for _, op := range m.Up {
		stmts, err := d.buildOperationSQL(op)
		if err != nil {
			return "", err
		}
		for _, stmt := range stmts {
			fmt.Fprintf(&b, "%s;\n", stmt)
		}
	}
	return b.String(), nil
}

// FileExtension implements [core.MigrationRenderer].
func (d *PostgreSQLDriver) FileExtension() string { return ".sql" }

// ---- Pure SQL builders ----

// buildOperationSQL is the one switch over op.Kind. It is pure — no
// execution, no side effects — and an operation missing its required
// payload is an Internal error, never a silent no-op.
func (d *PostgreSQLDriver) buildOperationSQL(op core.SchemaOperation) ([]string, error) {
	missing := func(field string) ([]string, error) {
		return nil, behemotherr.NewInternalError("PostgresDriver.buildOperationSQL", fmt.Errorf("operation %q: %s missing %s", op.ID, op.Kind, field))
	}
	one := func(stmt string, err error) ([]string, error) {
		if err != nil {
			return nil, err
		}
		return []string{stmt}, nil
	}

	switch op.Kind {
	case core.OpCreateTable:
		if op.NewTable == nil {
			return missing("NewTable")
		}
		return one(d.buildCreateTable(*op.NewTable))
	case core.OpDropTable:
		return []string{d.buildDropTable(op.Table)}, nil
	case core.OpAddColumn:
		if op.Column == nil {
			return missing("Column")
		}
		return one(d.buildAddColumn(op.Table, *op.Column))
	case core.OpDropColumn:
		return []string{d.buildDropColumn(op.Table, op.ColumnName)}, nil
	case core.OpRenameColumn:
		return []string{d.buildRenameColumn(op.Table, op.ColumnName, op.NewColumnName)}, nil
	case core.OpAlterColumn:
		if op.Column == nil {
			return missing("Column")
		}
		return d.buildAlterColumn(op.Table, *op.Column, op.PrevColumn)
	case core.OpAddIndex:
		if op.Index == nil {
			return missing("Index")
		}
		return one(d.buildAddIndex(op.Table, *op.Index))
	case core.OpDropIndex:
		return []string{d.buildDropIndex(op.IndexName)}, nil
	case core.OpAddForeignKey:
		if op.ForeignKey == nil {
			return missing("ForeignKey")
		}
		return one(d.buildAddForeignKey(op.Table, *op.ForeignKey))
	case core.OpDropForeignKey:
		return []string{d.buildDropForeignKey(op.Table, op.ForeignKeyName)}, nil
	default:
		return nil, behemotherr.NewInternalError("PostgresDriver.buildOperationSQL", fmt.Errorf("operation %q: unknown Kind %q", op.ID, op.Kind))
	}
}

// buildCreateTable renders columns and the primary key only.
//
// t.ForeignKeys and t.Indexes are intentionally NEVER read here: foreign keys
// always arrive as their own OpAddForeignKey (enforced upstream by
// MigrationGenerator's checkNoInlineForeignKeys) and indexes as their own
// OpAddIndex, exactly as BuildBaselineMigration emits them.
func (d *PostgreSQLDriver) buildCreateTable(t schema.Table) (string, error) {
	var colDefs, pkCols []string
	for _, col := range t.Columns {
		def, err := d.renderColumnDefinition(t.Name, col)
		if err != nil {
			return "", err
		}
		colDefs = append(colDefs, def)
		if col.PrimaryKey {
			pkCols = append(pkCols, quoteIdent(d.resolver.ResolveColumn(t.Name, col.Name)))
		}
	}
	if len(pkCols) > 0 {
		colDefs = append(colDefs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}
	return fmt.Sprintf("CREATE TABLE %s (%s)", quoteIdent(d.resolver.Resolve(t.Name)), strings.Join(colDefs, ", ")), nil
}

func (d *PostgreSQLDriver) buildDropTable(table string) string {
	return "DROP TABLE " + quoteIdent(d.resolver.Resolve(table))
}

func (d *PostgreSQLDriver) buildAddColumn(table string, col schema.Column) (string, error) {
	def, err := d.renderColumnDefinition(table, col)
	if err != nil {
		return "", err
	}
	if applyOverride(col).PrimaryKey {
		def += " PRIMARY KEY"
	}
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", quoteIdent(d.resolver.Resolve(table)), def), nil
}

// buildDropColumn: Postgres drops indexes and table constraints involving
// the column along with it.
func (d *PostgreSQLDriver) buildDropColumn(table, column string) string {
	return fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s",
		quoteIdent(d.resolver.Resolve(table)), quoteIdent(d.resolver.ResolveColumn(table, column)))
}

func (d *PostgreSQLDriver) buildRenameColumn(table, oldName, newName string) string {
	// Both names are canonical identifiers on the same table, so both resolve
	// through ResolveColumn identically.
	return fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s",
		quoteIdent(d.resolver.Resolve(table)),
		quoteIdent(d.resolver.ResolveColumn(table, oldName)),
		quoteIdent(d.resolver.ResolveColumn(table, newName)))
}

// buildAlterColumn always sets type, nullability and default — each its own
// ALTER COLUMN clause, since Postgres can't combine them.
//
// Uniqueness lives in a named constraint (see renderColumnDefinition) and is
// only changed when prev — the OpAlterColumn's PrevColumn — says it differs;
// without prev it is left exactly as it is.
func (d *PostgreSQLDriver) buildAlterColumn(table string, raw schema.Column, prevRaw *schema.Column) ([]string, error) {
	col := applyOverride(raw)
	physTableName := d.resolver.Resolve(table)
	physTable := quoteIdent(physTableName)
	physCol := d.resolver.ResolveColumn(table, col.Name)
	qCol := quoteIdent(physCol)

	nativeType, err := renderPgType(col.Type, col.Length)
	if err != nil {
		return nil, err
	}
	alter := func(clause string) string {
		return fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s %s", physTable, qCol, clause)
	}

	var prev *schema.Column
	if prevRaw != nil {
		p := applyOverride(*prevRaw)
		prev = &p
	}
	addIdentity := prev != nil && !prev.AutoInc && col.AutoInc
	dropIdentity := prev != nil && prev.AutoInc && !col.AutoInc
	if addIdentity && col.Type != schema.ColTypeInteger && col.Type != schema.ColTypeBigInt {
		return nil, behemotherr.NewMigrationError("PostgresDriver.buildAlterColumn", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
			fmt.Errorf("column %q: AutoInc requires an integer column, got %q", col.Name, col.Type))
	}

	stmts := []string{alter(fmt.Sprintf("TYPE %s USING %s::%s", nativeType, qCol, nativeType))}
	if col.Nullable && !col.PrimaryKey {
		stmts = append(stmts, alter("DROP NOT NULL"))
	} else {
		stmts = append(stmts, alter("SET NOT NULL"))
	}
	// Postgres rejects SET DEFAULT on an identity column, so the identity
	// goes first. A serial column has no identity (IF EXISTS); it loses its
	// nextval() default through the default handling below.
	if dropIdentity {
		stmts = append(stmts, alter("DROP IDENTITY IF EXISTS"))
	}
	if !col.AutoInc { // an identity column has no DEFAULT; leave its generator alone
		expr, err := renderDefaultExpr(raw)
		if err != nil {
			return nil, err
		}
		if expr != "" {
			stmts = append(stmts, alter("SET DEFAULT "+expr))
		} else {
			stmts = append(stmts, alter("DROP DEFAULT"))
		}
	}
	// A new identity starts at 1; on a populated column it would hand out
	// values that already exist. It is moved past the largest one instead.
	// Any default is dropped first: a column can't have both.
	if addIdentity {
		stmts = append(stmts,
			alter("DROP DEFAULT"),
			alter("ADD GENERATED BY DEFAULT AS IDENTITY"),
			fmt.Sprintf("SELECT setval(pg_get_serial_sequence(%s, %s), COALESCE(MAX(%s), 0) + 1, false) FROM %s",
				quoteLiteral(physTable), quoteLiteral(physCol), qCol, physTable),
		)
	}

	if prev != nil {
		if prev.Unique != col.Unique && !col.PrimaryKey {
			name := quoteIdent(uniqueConstraintName(physTableName, physCol))
			if col.Unique {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s UNIQUE (%s)", physTable, name, qCol))
			} else {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s", physTable, name))
			}
		}
	}
	return stmts, nil
}

func (d *PostgreSQLDriver) buildAddIndex(table string, idx schema.Index) (string, error) {
	if len(idx.Columns) == 0 {
		return "", behemotherr.NewMigrationError("PostgresDriver.AddIndex", behemotherr.ErrorCodeMigrationInvalidIndex, fmt.Errorf("index %q has no columns", idx.Name))
	}
	cols := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		cols[i] = quoteIdent(d.resolver.ResolveColumn(table, c))
	}
	uniqueKw := ""
	if idx.Unique {
		uniqueKw = "UNIQUE "
	}
	return fmt.Sprintf("CREATE %sINDEX %s ON %s (%s)",
		uniqueKw, quoteIdent(idx.Name), quoteIdent(d.resolver.Resolve(table)), strings.Join(cols, ", ")), nil
}

// buildDropIndex: index names are schema-scoped, so the table isn't needed.
func (d *PostgreSQLDriver) buildDropIndex(indexName string) string {
	return "DROP INDEX " + quoteIdent(indexName)
}

func (d *PostgreSQLDriver) buildAddForeignKey(table string, fk schema.ForeignKey) (string, error) {
	if len(fk.Columns) == 0 || len(fk.Columns) != len(fk.RefColumns) {
		return "", behemotherr.NewMigrationError("PostgresDriver.AddForeignKey", behemotherr.ErrorCodeMigrationInvalidForeignKey,
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

func (d *PostgreSQLDriver) buildDropForeignKey(table, fkName string) string {
	return fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", quoteIdent(d.resolver.Resolve(table)), quoteIdent(fkName))
}

// ---- Rendering ----

// applyOverride folds Column.Overrides["postgres"] into the column. Default is
// deliberately left alone: an override default is a raw SQL expression and is
// rendered by renderDefaultExpr.
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

// renderColumnDefinition renders one column. The primary key is rendered as a
// table constraint by buildCreateTable, never inline. UNIQUE is named
// deterministically so buildAlterColumn can later drop it by name.
func (d *PostgreSQLDriver) renderColumnDefinition(table string, raw schema.Column) (string, error) {
	col := applyOverride(raw)
	physTable := d.resolver.Resolve(table)
	physCol := d.resolver.ResolveColumn(table, col.Name)

	nativeType, err := renderPgType(col.Type, col.Length)
	if err != nil {
		return "", err
	}

	parts := []string{quoteIdent(physCol), nativeType}
	if col.AutoInc {
		if col.Type != schema.ColTypeInteger && col.Type != schema.ColTypeBigInt {
			return "", behemotherr.NewMigrationError("PostgresDriver.renderColumnDefinition", behemotherr.ErrorCodeMigrationUnsupportedAutoIncrement,
				fmt.Errorf("column %q: AutoInc requires an integer column, got %q", col.Name, col.Type))
		}
		// Identity columns are the recommended replacement for serial
		// (https://wiki.postgresql.org/wiki/Don%27t_Do_This#Don.27t_use_serial).
		// BY DEFAULT (rather than ALWAYS) still accepts explicit values.
		parts = append(parts, "GENERATED BY DEFAULT AS IDENTITY")
	}
	if !col.Nullable || col.PrimaryKey {
		parts = append(parts, "NOT NULL")
	}
	if col.Unique && !col.PrimaryKey { // PK already implies uniqueness
		parts = append(parts, "CONSTRAINT "+quoteIdent(uniqueConstraintName(physTable, physCol))+" UNIQUE")
	}
	if !col.AutoInc {
		expr, err := renderDefaultExpr(raw)
		if err != nil {
			return "", err
		}
		if expr != "" {
			parts = append(parts, "DEFAULT "+expr)
		}
	}
	return strings.Join(parts, " "), nil
}

// uniqueConstraintName follows Postgres's own naming convention for unnamed
// UNIQUE column constraints. Postgres truncates identifiers to 63 bytes; since
// both CREATE and ALTER go through this function, a truncated name is still
// truncated identically on both sides.
func uniqueConstraintName(table, column string) string { return table + "_" + column + "_key" }

// renderDefaultExpr returns the DEFAULT expression for a column, or "" for
// none: the postgres override's raw expression if set (e.g. "now()"),
// otherwise Column.Default rendered as a literal.
func renderDefaultExpr(col schema.Column) (string, error) {
	if expr := col.Overrides[DriverName].Default; expr != "" {
		return expr, nil
	}
	return renderLiteral(col.Default)
}

// renderLiteral renders Column.Default. Only plain literals are supported —
// the forward counterpart of the introspector's parsePgDefault. Numbers
// arrive as float64 once a migration has round-tripped through its JSON file.
func renderLiteral(v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "", nil
	case string:
		return "'" + strings.ReplaceAll(val, "'", "''") + "'", nil
	case bool:
		if val {
			return "TRUE", nil
		}
		return "FALSE", nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val), nil
	case float32, float64:
		return fmt.Sprintf("%v", val), nil
	default:
		return "", behemotherr.NewMigrationError("PostgresDriver.renderLiteral", behemotherr.ErrorCodeMigrationUnsupportedDefaultType, fmt.Errorf("cannot render default value of type %T", v))
	}
}

// renderPgType is the FORWARD (canonical -> native) direction of type
// mapping — deliberately a separate, simpler table from the introspector's
// pgTypeMapping, which handles the harder REVERSE direction.
func renderPgType(ct schema.ColumnType, length int) (string, error) {
	switch ct {
	case schema.ColTypeString:
		if length <= 0 {
			length = 255
		}
		return fmt.Sprintf("VARCHAR(%d)", length), nil
	case schema.ColTypeText:
		return "TEXT", nil
	case schema.ColTypeInteger:
		return "INTEGER", nil
	case schema.ColTypeBigInt:
		return "BIGINT", nil
	case schema.ColTypeReal:
		return "DOUBLE PRECISION", nil
	case schema.ColTypeNumeric:
		return "NUMERIC", nil
	case schema.ColTypeBoolean:
		return "BOOLEAN", nil
	case schema.ColTypeDateTime:
		return "TIMESTAMP", nil
	case schema.ColTypeTimestamp:
		return "TIMESTAMPTZ", nil
	case schema.ColTypeUuid:
		return "UUID", nil
	case schema.ColTypeJson:
		return "JSONB", nil
	case schema.ColTypeBytes, schema.ColTypeBlob:
		return "BYTEA", nil
	default:
		return "", behemotherr.NewMigrationError("PostgresDriver.renderPgType", behemotherr.ErrorCodeMigrationUnsupportedCanonicalType, fmt.Errorf("no Postgres rendering for canonical type %q", ct))
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

// quoteIdent applies standard Postgres double-quote identifier escaping —
// used for every table/column/index/constraint name emitted into SQL, never
// string-concatenated raw. Values (defaults) go through renderLiteral instead.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// quoteLiteral renders s as a SQL string literal, for the rare statement that
// takes a name as a value (e.g. pg_get_serial_sequence).
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
