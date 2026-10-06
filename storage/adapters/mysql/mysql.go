// Package mysql is behemoth's MySQL integration, in its own module so the core
// module does not depend on the MySQL driver:
//
//   - MySQLAdapter implements behemoth.Database (application reads/writes).
//   - MySQLDriver implements the migration interfaces: core.SchemaDriver,
//     core.MigrationRenderer, core.SchemaIntrospector and core.ColumnNormalizer.
//
// Both take the same behemoth.SchemaResolver, so application queries and
// migrations agree on physical table and column names.
//
// The migration driver works with any database/sql MySQL driver. The adapter
// classifies errors using github.com/go-sql-driver/mysql's error type, which
// is what makes this module depend on it.
package mysql

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
	"github.com/go-sql-driver/mysql"
)

// MySQLAdapter implements the behemoth.Database interface for MySQL.
//
// Models are addressed by canonical names; every table and column name in the
// generated SQL goes through Resolver first. A nil Resolver maps every name to
// itself.
type MySQLAdapter struct {
	DB       adapters.Querier
	Resolver behemoth.SchemaResolver

	// Logger receives the text of every statement at Debug. nil = none.
	// Set it with WithLogger.
	Logger telemetry.Logger
}

// NewMySQLAdapter wraps db (a *sql.DB, or a *sql.Tx). resolver maps canonical
// names to physical ones; nil uses them as-is.
func NewMySQLAdapter(db adapters.Querier, resolver behemoth.SchemaResolver) *MySQLAdapter {
	return &MySQLAdapter{DB: db, Resolver: resolver}
}

// WithLogger makes the adapter write the text of every statement it runs to
// logger at Debug, and returns the adapter. Argument values are never
// logged: they hold password hashes and token hashes. Adapters bound to a
// transaction (see Transaction) log to the same logger.
func (my *MySQLAdapter) WithLogger(logger telemetry.Logger) *MySQLAdapter {
	my.Logger = logger
	return my
}

// q is the connection statements run on: DB, logging each statement when a
// Logger is set.
func (my *MySQLAdapter) q() adapters.Querier {
	return adapters.LogQueries(my.DB, my.Logger, "storage.mysql")
}

func (my *MySQLAdapter) names() behemoth.SchemaResolver {
	return adapters.ResolverOrIdentity(my.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (my *MySQLAdapter) where(m behemoth.Model, expr *clause.Expression) (string, []any) {
	return adapters.BuildSQLWhereClause(adapters.PhysicalExpression(my.names(), m, expr), adapters.DefaultClauseOption)
}

// mapMySQLErrors classifies MySQL server errors by error number
// (https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html).
func mapMySQLErrors(op, entity string, err error) error {
	if classified, ok := adapters.MapStdSQLErrors(op, entity, err); ok {
		return classified
	}

	myErr, ok := errors.AsType[*mysql.MySQLError](err)
	if !ok {
		return adapters.Classify(op, entity, adapters.SentinelUnknown, err)
	}
	switch myErr.Number {
	case 1062: // ER_DUP_ENTRY
		return adapters.Classify(op, entity, adapters.SentinelDuplicateKey, err)
	case 1451, 1452, 1216, 1217: // ER_ROW_IS_REFERENCED_2, ER_NO_REFERENCED_ROW_2, and their pre-5.1 forms
		return adapters.Classify(op, entity, adapters.SentinelForeignKey, err)
	case 1146: // ER_NO_SUCH_TABLE
		return adapters.Classify(op, entity, adapters.SentinelUndefinedTable, err)
	case 1048, 3819: // ER_BAD_NULL_ERROR, ER_CHECK_CONSTRAINT_VIOLATED
		return adapters.Classify(op, entity, adapters.SentinelConstraintViolation, err)
	default:
		return adapters.Classify(op, entity, adapters.SentinelUnknown, err)
	}
}

// generateMySQLPlaceholders returns a VALUES clause with n '?' placeholders: (?, ?, ?)
func generateMySQLPlaceholders(n int) string {
	placeholders := make([]string, n)
	for i := range placeholders {
		placeholders[i] = "?"
	}
	return "(" + strings.Join(placeholders, ", ") + ")"
}

// generateMySQLSETClause returns "col1 = ?, col2 = ?, ..." for an UPDATE SET clause.
func generateMySQLSETClause(columns []string) string {
	parts := make([]string, len(columns))
	for i, col := range columns {
		parts[i] = fmt.Sprintf("%s = ?", col)
	}
	return strings.Join(parts, ", ")
}

func (my *MySQLAdapter) Create(ctx context.Context, m behemoth.Model) error {
	if _, ok := m.(behemoth.Serializable); !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	placeholders := generateMySQLPlaceholders(len(columns))

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		adapters.PhysicalTable(my.names(), m),
		strings.Join(adapters.PhysicalColumns(my.names(), m, columns), ", "),
		placeholders,
	)

	_, err := my.q().ExecContext(ctx, query, values...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
}

func (my *MySQLAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}

	// columns stay canonical: they key the map handed to FromMap.
	columns := adapters.ReadColumns(my.names(), m, nil)
	values, valuePtrs := adapters.ScanTargets(len(columns))

	query := fmt.Sprintf(
		"SELECT %s FROM %s",
		strings.Join(adapters.PhysicalColumns(my.names(), m, columns), ", "),
		adapters.PhysicalTable(my.names(), m),
	)
	whereClause, args := my.where(m, &whereExpression)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " LIMIT 1"

	row := my.q().QueryRowContext(ctx, query, args...)
	if err := row.Scan(valuePtrs...); err != nil {
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}

	return models.GenerateModelFromRows(m, columns, values)

}

func (my *MySQLAdapter) FindMany(
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
		query          string
	)

	// columns stay canonical: they key the map handed to FromMap.
	var selected []string
	if options != nil {
		selected = options.Select
	}
	columns = adapters.ReadColumns(my.names(), m, selected)
	values, valuePtrs = adapters.ScanTargets(len(columns))

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := my.where(m, &whereExpression)

	query = fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(adapters.PhysicalColumns(my.names(), m, columns), ", "),
		adapters.PhysicalTable(my.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		if options.OrderBy.Field != "" {
			query += fmt.Sprintf(" ORDER BY %s %s", adapters.PhysicalColumn(my.names(), m, options.OrderBy.Field), options.OrderBy.Direction)
		}
		// MySQL supports LIMIT / OFFSET in the same way as SQLite.
		if options.Limit != 0 {
			query += fmt.Sprintf(" LIMIT %d", options.Limit)
		}
		if options.Offset != 0 {
			query += fmt.Sprintf(" OFFSET %d", options.Offset)
		}
	}

	rows, err := my.q().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
		}
		result, err := models.GenerateModelFromRows(m, columns, values)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil

}

func (my *MySQLAdapter) Update(ctx context.Context, m behemoth.Model) error {
	if _, ok := m.(behemoth.Serializable); !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = ?",
		adapters.PhysicalTable(my.names(), m),
		generateMySQLSETClause(adapters.PhysicalColumns(my.names(), m, columns)),
		adapters.PhysicalColumn(my.names(), m, m.PrimaryKeyName()),
	)

	// MySQL reports changed rows unless the connection sets clientFoundRows.
	res, err := my.q().ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	return adapters.ExpectOneRow("Update", m, n, func() (int64, error) { return my.Count(ctx, m, adapters.ByPrimaryKey(m)) })
}

func (my *MySQLAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereClause, whereArgs := my.where(m, &expr)
	table := adapters.PhysicalTable(my.names(), m)
	pk := adapters.PhysicalColumn(my.names(), m, m.PrimaryKeyName())

	// MySQL forbids "UPDATE t SET ... WHERE pk = (SELECT pk FROM t WHERE ...)"
	// when the subquery references the same table. We work around this by
	// wrapping the subquery in a derived table aliased as `_sub`.
	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (SELECT %s FROM (%s) AS _sub)",
		table,
		generateMySQLSETClause(adapters.PhysicalColumns(my.names(), m, columns)),
		pk,
		pk,
		selectQuery,
	)
	// expr is repeated in the outer WHERE so it holds for the row as written
	// (the UpdateOne convention).
	query += " AND (" + whereClause + ")"
	args := append(append(values, whereArgs...), whereArgs...)

	res, err := my.q().ExecContext(ctx, query, args...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	// MySQL reports changed rows unless the connection sets clientFoundRows.
	return adapters.ExpectOneRow("UpdateOne", m, n, func() (int64, error) { return my.Count(ctx, m, expr) })
}

func (my *MySQLAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereClause, whereArgs := my.where(m, &expr)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		adapters.PhysicalTable(my.names(), m),
		generateMySQLSETClause(adapters.PhysicalColumns(my.names(), m, columns)),
		whereClause,
	)

	_, err := my.q().ExecContext(ctx, query, append(values, whereArgs...)...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)

}

func (my *MySQLAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ?",
		adapters.PhysicalTable(my.names(), m),
		adapters.PhysicalColumn(my.names(), m, m.PrimaryKeyName()),
	)
	res, err := my.q().ExecContext(ctx, query, m.PrimaryKeyField())
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	return adapters.ExpectOneRow("Delete", m, n, nil)
}

func (my *MySQLAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := my.where(m, &expr)
	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteOne, "clause", nil)
	}

	table := adapters.PhysicalTable(my.names(), m)
	pk := adapters.PhysicalColumn(my.names(), m, m.PrimaryKeyName())

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = (SELECT %s FROM (%s) AS _sub)",
		table,
		pk,
		pk,
		selectQuery,
	)

	// expr is repeated in the outer WHERE so it holds for the row as deleted.
	query += " AND (" + whereClause + ")"
	res, err := my.q().ExecContext(ctx, query, append(args, args...)...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	return adapters.ExpectOneRow("DeleteOne", m, n, nil)
}

func (my *MySQLAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := my.where(m, &expr)
	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		adapters.PhysicalTable(my.names(), m),
		whereClause,
	)

	_, err := my.q().ExecContext(ctx, query, args...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
}

func (my *MySQLAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf("DELETE FROM %s", adapters.PhysicalTable(my.names(), m))
	_, err := my.q().ExecContext(ctx, query)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
}

func (my *MySQLAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	whereClause, args := my.where(m, &expr)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		adapters.PhysicalTable(my.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := my.q().QueryContext(ctx, query, args...)
	if err != nil {
		return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
	}
	defer row.Close()

	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapMySQLErrors)
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
func (my *MySQLAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	var db *sql.DB
	switch q := my.DB.(type) {
	case *sql.DB:
		db = q
	case *sql.Tx:
		_, err := fn(ctx, my)
		return err
	default:
		return behemotherr.NewTransactionError("Transaction",
			fmt.Errorf("cannot begin a transaction on a %T; the adapter needs a *sql.DB", my.DB))
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

	txAdapter := NewMySQLAdapter(tx, my.Resolver).WithLogger(my.Logger)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()

}
