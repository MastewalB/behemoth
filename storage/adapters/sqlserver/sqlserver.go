// Package sqlserver is behemoth's Microsoft SQL Server integration, in its own
// module so the core module does not depend on go-mssqldb:
//
//   - SQLServerAdapter implements behemoth.Database (application reads/writes).
//   - SQLServerDriver implements the migration interfaces: core.SchemaDriver,
//     core.MigrationRenderer, core.SchemaIntrospector and core.ColumnNormalizer.
//
// Both take the same behemoth.SchemaResolver, so application queries and
// migrations agree on physical table and column names.
//
// The migration driver works with any database/sql SQL Server driver. The
// adapter classifies errors using go-mssqldb's error type, which is what
// makes this module depend on it.
package sqlserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/utils"
	mssql "github.com/microsoft/go-mssqldb"
)

// SQLServerAdapter implements behemoth.Database for Microsoft SQL Server.
//
// Key differences from the SQLite / MySQL adapters:
//
//  1. Placeholders   — SQL Server uses @p1 ... pN, ... (go-mssqldb convention).
//  2. TOP N          — SQL Server has no LIMIT clause; single-row queries use
//     SELECT TOP 1 and range queries use
//     OFFSET N ROWS FETCH NEXT M ROWS ONLY.
//  3. OFFSET / FETCH — Require an ORDER BY. When the caller supplies an
//     Offset or Limit without an OrderBy we inject
//     ORDER BY (SELECT NULL) so the query is valid.
//  4. SET clause     — placeholders must also be ?-style.
//  5. Error mapping  — go-mssqldb surfaces mssql.Error with a numeric
//     error code rather than SQLSTATE strings.
//
// Models are addressed by canonical names; every table and column name in the
// generated SQL goes through Resolver first. A nil Resolver maps every name to
// itself.
type SQLServerAdapter struct {
	DB       adapters.Querier
	Resolver behemoth.SchemaResolver

	// Logger receives the text of every statement at Debug. nil = none.
	// Set it with WithLogger.
	Logger telemetry.Logger
}

// NewSQLServerAdapter wraps db (a *sql.DB, or a *sql.Tx). resolver maps
// canonical names to physical ones; nil uses them as-is.
func NewSQLServerAdapter(db adapters.Querier, resolver behemoth.SchemaResolver) *SQLServerAdapter {
	return &SQLServerAdapter{DB: db, Resolver: resolver}
}

// WithLogger makes the adapter write the text of every statement it runs to
// logger at Debug, and returns the adapter. Argument values are never
// logged: they hold password hashes and token hashes. Adapters bound to a
// transaction (see Transaction) log to the same logger.
func (ms *SQLServerAdapter) WithLogger(logger telemetry.Logger) *SQLServerAdapter {
	ms.Logger = logger
	return ms
}

// q is the connection statements run on: DB, logging each statement when a
// Logger is set.
func (ms *SQLServerAdapter) q() adapters.Querier {
	return adapters.LogQueries(ms.DB, ms.Logger, "storage.sqlserver")
}

func (ms *SQLServerAdapter) names() behemoth.SchemaResolver {
	return adapters.ResolverOrIdentity(ms.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (ms *SQLServerAdapter) where(m behemoth.Model, expr *clause.Expression, options *adapters.ClauseOptions) (string, []any) {
	return adapters.BuildSQLWhereClause(adapters.PhysicalExpression(ms.names(), m, expr), options)
}

// SQL Server uses @p1, @p2, … positional named parameters. The counter N
// is threaded through recursive calls so nested expressions and multi-step
// operations (UpdateOne SET args + WHERE args) share a single sequence.
var defaultMSSQLClauseOptions = &adapters.ClauseOptions{
	Placeholder:            "@p",
	UseNumberedPlaceholder: true,
	Number:                 1,
}

// NewMSSQLClauseOptions returns clause options whose @p placeholders start
// at N, for a WHERE clause that follows N-1 earlier arguments.
func NewMSSQLClauseOptions(N int) *adapters.ClauseOptions {
	return &adapters.ClauseOptions{
		Placeholder:            "@p",
		UseNumberedPlaceholder: true,
		Number:                 N,
	}
}

func (ms *SQLServerAdapter) Create(ctx context.Context, m behemoth.Model) error {
	if _, ok := m.(behemoth.Serializable); !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	placeholders := mssqlPlaceholders(1, len(columns))

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		adapters.PhysicalTable(ms.names(), m),
		strings.Join(adapters.PhysicalColumns(ms.names(), m, columns), ", "),
		strings.Join(placeholders, ", "),
	)

	_, err := ms.q().ExecContext(ctx, query, values...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)

}

func (ms *SQLServerAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}

	// columns stay canonical: they key the map handed to FromMap.
	columns := adapters.ReadColumns(ms.names(), m, nil)
	values, valuePtrs := adapters.ScanTargets(len(columns))

	// SQL Server uses SELECT TOP 1 instead of appending LIMIT 1.
	query := fmt.Sprintf(
		"SELECT TOP 1 %s FROM %s",
		strings.Join(adapters.PhysicalColumns(ms.names(), m, columns), ", "),
		adapters.PhysicalTable(ms.names(), m),
	)
	whereClause, args := ms.where(m, &whereExpression, defaultMSSQLClauseOptions)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row := ms.q().QueryRowContext(ctx, query, args...)
	if err := row.Scan(valuePtrs...); err != nil {
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}

	return models.GenerateModelFromRows(m, columns, values)
}

func (ms *SQLServerAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
	options *behemoth.QueryOptions,
) ([]behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}

	var (
		columns        []string
		values         []any
		valuePtrs      []any
		distinctClause string
	)

	// columns stay canonical: they key the map handed to FromMap.
	var selected []string
	if options != nil {
		selected = options.Select
	}
	columns = adapters.ReadColumns(ms.names(), m, selected)
	values, valuePtrs = adapters.ScanTargets(len(columns))

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := ms.where(m, &whereExpression, defaultMSSQLClauseOptions)

	query := fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(adapters.PhysicalColumns(ms.names(), m, columns), ", "),
		adapters.PhysicalTable(ms.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		orderBy := ""
		if options.OrderBy.Field != "" {
			orderBy = adapters.PhysicalColumn(ms.names(), m, options.OrderBy.Field)
		}
		query = appendMSSQLPagination(query, orderBy, options)
	}

	rows, err := ms.q().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
		}
		result, err := models.GenerateModelFromRows(m, columns, values)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

func (ms *SQLServerAdapter) Update(ctx context.Context, m behemoth.Model) error {
	if _, ok := m.(behemoth.Serializable); !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)

	// SET clause uses @p1 ... @pN; the PK placeholder follows immediately after.
	setClause := mssqlSETClause(adapters.PhysicalColumns(ms.names(), m, columns), 1)
	pkPlaceholder := fmt.Sprintf("@p%d", len(columns)+1)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = %s",
		adapters.PhysicalTable(ms.names(), m),
		setClause,
		adapters.PhysicalColumn(ms.names(), m, m.PrimaryKeyName()),
		pkPlaceholder,
	)

	res, err := ms.q().ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	return adapters.ExpectOneRow("Update", m, n, nil)
}

func (ms *SQLServerAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)

	// SET args occupy @p1 … @pN; WHERE args start at @p(N+1).
	setClause := mssqlSETClause(adapters.PhysicalColumns(ms.names(), m, columns), 1)
	whereClause, whereArgs := ms.where(m, &expr, NewMSSQLClauseOptions(len(values)+1))

	// TOP (1) picks the one row, and expr is checked on the row as written
	// (the UpdateOne convention). The statement takes the row's update lock as
	// it finds the row, so concurrent updates of one row run one after
	// another. Selecting the row's key in a subquery first would take a shared
	// lock, which one statement can still hold while another has the update
	// lock; each then waits for the other and SQL Server ends one with a
	// deadlock error. SQL Server reports matched rows.
	query := fmt.Sprintf(
		"UPDATE TOP (1) %s SET %s",
		adapters.PhysicalTable(ms.names(), m),
		setClause,
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	args := append(values, whereArgs...)

	res, err := ms.q().ExecContext(ctx, query, args...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	return adapters.ExpectOneRow("UpdateOne", m, n, nil)
}

func (ms *SQLServerAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	setClause := mssqlSETClause(adapters.PhysicalColumns(ms.names(), m, columns), 1)
	whereClause, whereArgs := ms.where(m, &expr, NewMSSQLClauseOptions(len(values)+1))

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		adapters.PhysicalTable(ms.names(), m),
		setClause,
		whereClause,
	)

	_, err := ms.q().ExecContext(ctx, query, append(values, whereArgs...)...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

// Delete  (by primary key field on the model)
func (ms *SQLServerAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = @p1",
		adapters.PhysicalTable(ms.names(), m),
		adapters.PhysicalColumn(ms.names(), m, m.PrimaryKeyName()),
	)
	res, err := ms.q().ExecContext(ctx, query, m.PrimaryKeyField())
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	return adapters.ExpectOneRow("Delete", m, n, nil)
}

func (ms *SQLServerAdapter) DeleteOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteOne, "clause", nil)
	}

	// TOP (1) and no subquery, for the reason given in UpdateOne.
	query := fmt.Sprintf(
		"DELETE TOP (1) FROM %s WHERE %s",
		adapters.PhysicalTable(ms.names(), m),
		whereClause,
	)
	res, err := ms.q().ExecContext(ctx, query, args...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	return adapters.ExpectOneRow("DeleteOne", m, n, nil)
}

func (ms *SQLServerAdapter) DeleteMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		adapters.PhysicalTable(ms.names(), m),
		whereClause,
	)

	_, err := ms.q().ExecContext(ctx, query, args...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf("DELETE FROM %s", adapters.PhysicalTable(ms.names(), m))
	_, err := ms.q().ExecContext(ctx, query)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		adapters.PhysicalTable(ms.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := ms.q().QueryContext(ctx, query, args...)
	if err != nil {
		return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	defer row.Close()

	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
		}
	}

	return count, nil
}

// Transaction runs fn with an adapter bound to one database transaction. fn's
// error rolls the transaction back and is returned as-is.
//
// Called on an adapter that is already bound to a transaction (the one
// Transaction hands to fn), it runs fn in that same transaction: nothing is
// begun, committed or rolled back here, and fn's error is returned for the
// outer call to roll back on. Code that is handed an adapter, such as a hook
// handler, can therefore call Transaction without knowing whether one is open.
func (ms *SQLServerAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	var db *sql.DB
	switch q := ms.DB.(type) {
	case *sql.DB:
		db = q
	case *sql.Tx:
		_, err := fn(ctx, ms)
		return err
	default:
		return behemotherr.NewTransactionError("Transaction",
			fmt.Errorf("cannot begin a transaction on a %T; the adapter needs a *sql.DB", ms.DB))
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	txAdapter := NewSQLServerAdapter(tx, ms.Resolver).WithLogger(ms.Logger)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()
}

// Pagination helper
//
// SQL Server pagination rules:
//   - Use ORDER BY ... OFFSET ... ROWS FETCH NEXT ... ROWS ONLY.
//   - OFFSET / FETCH always require an ORDER BY clause.
//   - When the caller supplies Limit or Offset but no OrderBy field we
//     inject ORDER BY (SELECT NULL) which is the idiomatic SQL Server
//     no-op sort that satisfies the syntax requirement.
//   - When only Limit is given (no Offset) we still emit OFFSET 0 ROWS
//     because FETCH NEXT requires a preceding OFFSET clause.
//
// orderBy is the physical column to sort on ("" for none); the caller
// resolves options.OrderBy.Field.
func appendMSSQLPagination(query, orderBy string, options *behemoth.QueryOptions) string {
	needsPagination := options.Limit != 0 || options.Offset != 0

	if orderBy != "" {
		query += fmt.Sprintf(" ORDER BY %s %s", orderBy, options.OrderBy.Direction)
	} else if needsPagination {
		// OFFSET ... FETCH is syntactically invalid without ORDER BY.
		query += " ORDER BY (SELECT NULL)"
	}

	if needsPagination {
		offset := options.Offset
		query += fmt.Sprintf(" OFFSET %d ROWS", offset)

		if options.Limit != 0 {
			query += fmt.Sprintf(" FETCH NEXT %d ROWS ONLY", options.Limit)
		}
	}

	return query
}

// Error mapping
//
// go-mssqldb surfaces constraint and server errors as *mssql.Error.
// The Number field carries the SQL Server error number:
//
//	2627 / 2601 — unique constraint / unique index violation
//	547         — foreign key, check constraint, or column default violation
//	515 / 245   — cannot insert NULL / conversion failed (validation)
//	208         — invalid object name (table not found — undefined_table)
//
// sql.ErrNoRows is returned by QueryRowContext when no row is found,
// and sql.ErrTxDone signals a completed or rolled-back transaction.
func mapMSSQLError(op, entity string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return behemotherr.NewNotFound(op, entity, err)
	}

	if errors.Is(err, sql.ErrTxDone) {
		return behemotherr.NewTransactionError(op, err)
	}

	if mssqlErr, ok := errors.AsType[mssql.Error](err); ok {
		switch mssqlErr.Number {
		case 208:
			return adapters.Classify(op, entity, adapters.SentinelUndefinedTable, err)
		case 2627, 2601:
			return behemotherr.NewDuplicateKey(op, entity, err)
		case 547:
			return behemotherr.NewForeignKeyViolation(op, entity, err)
		case 515, 245:
			return behemotherr.NewValidationError(op, entity, err)
		}
	}

	return behemotherr.NewDatabaseError(op, err)

}

// mssqlPlaceholders returns a slice of n @pN-style placeholder strings
// starting from startN, e.g. mssqlPlaceholders(3, 2) -> ["@p3", "@p4"].
func mssqlPlaceholders(startN, count int) []string {
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("@p%d", startN+i)
	}
	return placeholders
}

// mssqlSETClause builds a SET fragment with @pN placeholders beginning
// at startN, e.g. mssqlSETClause(["name","age"], 1) -> "name = @p1, age = @p2".
func mssqlSETClause(columns []string, startN int) string {
	parts := make([]string, len(columns))
	for i, col := range columns {
		parts[i] = fmt.Sprintf("%s = @p%d", col, startN+i)
	}
	return strings.Join(parts, ", ")
}
