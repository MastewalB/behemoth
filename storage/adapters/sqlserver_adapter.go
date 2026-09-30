package adapters

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
	DB       Querier
	Resolver behemoth.SchemaResolver
}

func NewSQLServerAdapter(db Querier, resolver behemoth.SchemaResolver) *SQLServerAdapter {
	return &SQLServerAdapter{DB: db, Resolver: resolver}
}

func (ms *SQLServerAdapter) names() behemoth.SchemaResolver {
	return resolverOrIdentity(ms.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (ms *SQLServerAdapter) where(m behemoth.Model, expr *clause.Expression, options *ClauseOptions) (string, []any) {
	return BuildSQLWhereClause(physicalExpression(ms.names(), m, expr), options)
}

// SQL Server uses @p1, @p2, … positional named parameters. The counter N
// is threaded through recursive calls so nested expressions and multi-step
// operations (UpdateOne SET args + WHERE args) share a single sequence.
var defaultMSSQLClauseOptions = &ClauseOptions{
	Placeholder:            "@p",
	UseNumberedPlaceholder: true,
	Number:                 1,
}

func NewMSSQLClauseOptions(N int) *ClauseOptions {
	return &ClauseOptions{
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
		physicalTable(ms.names(), m),
		strings.Join(physicalColumns(ms.names(), m, columns), ", "),
		strings.Join(placeholders, ", "),
	)

	fmt.Println(query, values)
	_, err := ms.DB.ExecContext(ctx, query, values...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)

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
	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	// SQL Server uses SELECT TOP 1 instead of appending LIMIT 1.
	query := fmt.Sprintf(
		"SELECT TOP 1 %s FROM %s",
		strings.Join(physicalColumns(ms.names(), m, columns), ", "),
		physicalTable(ms.names(), m),
	)
	whereClause, args := ms.where(m, &whereExpression, defaultMSSQLClauseOptions)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	fmt.Println(query, args)
	row := ms.DB.QueryRowContext(ctx, query, args...)
	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
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
	if options != nil && len(options.Select) > 0 {
		columns, values, valuePtrs = models.GenerateColumnValuePairsWithSelectFilter(m, options.Select)
	} else {
		columns, values, valuePtrs = models.GenerateColumnValuePairs(m)
	}

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := ms.where(m, &whereExpression, defaultMSSQLClauseOptions)

	query := fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(physicalColumns(ms.names(), m, columns), ", "),
		physicalTable(ms.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		orderBy := ""
		if options.OrderBy.Field != "" {
			orderBy = physicalColumn(ms.names(), m, options.OrderBy.Field)
		}
		query = appendMSSQLPagination(query, orderBy, options)
	}

	rows, err := ms.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
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
	setClause := mssqlSETClause(physicalColumns(ms.names(), m, columns), 1)
	pkPlaceholder := fmt.Sprintf("@p%d", len(columns)+1)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = %s",
		physicalTable(ms.names(), m),
		setClause,
		physicalColumn(ms.names(), m, m.PrimaryKeyName()),
		pkPlaceholder,
	)

	_, err := ms.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
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
	setClause := mssqlSETClause(physicalColumns(ms.names(), m, columns), 1)
	whereClause, whereArgs := ms.where(m, &expr, NewMSSQLClauseOptions(len(values)+1))
	table := physicalTable(ms.names(), m)
	pk := physicalColumn(ms.names(), m, m.PrimaryKeyName())

	// SQL Server allows a plain subquery on the same table in an UPDATE.
	subQuery := fmt.Sprintf(
		"SELECT TOP 1 %s FROM %s WHERE %s",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		table,
		setClause,
		pk,
		subQuery,
	)

	_, err := ms.DB.ExecContext(ctx, query, append(values, whereArgs...)...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
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
	setClause := mssqlSETClause(physicalColumns(ms.names(), m, columns), 1)
	whereClause, whereArgs := ms.where(m, &expr, NewMSSQLClauseOptions(len(values)+1))

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		physicalTable(ms.names(), m),
		setClause,
		whereClause,
	)

	_, err := ms.DB.ExecContext(ctx, query, append(values, whereArgs...)...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

// Delete  (by primary key field on the model)
func (ms *SQLServerAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = @p1",
		physicalTable(ms.names(), m),
		physicalColumn(ms.names(), m, m.PrimaryKeyName()),
	)
	_, err := ms.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) DeleteOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteOne, "clause", nil)
	}

	table := physicalTable(ms.names(), m)
	pk := physicalColumn(ms.names(), m, m.PrimaryKeyName())

	subQuery := fmt.Sprintf(
		"SELECT TOP 1 %s FROM %s WHERE %s",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = (%s)",
		table,
		pk,
		subQuery,
	)

	_, err := ms.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) DeleteMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		physicalTable(ms.names(), m),
		whereClause,
	)

	_, err := ms.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf("DELETE FROM %s", physicalTable(ms.names(), m))
	_, err := ms.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
}

func (ms *SQLServerAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	whereClause, args := ms.where(m, &expr, defaultMSSQLClauseOptions)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		physicalTable(ms.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := ms.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
	}
	defer row.Close()

	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, WrapWithCaller(err, m.SchemaName(), mapMSSQLError)
		}
	}

	return count, nil
}

func (ms *SQLServerAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	tx, err := ms.DB.(*sql.DB).BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	txAdapter := NewSQLServerAdapter(tx, ms.Resolver)
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
			return classify(op, entity, sentinelUndefinedTable, err)
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
