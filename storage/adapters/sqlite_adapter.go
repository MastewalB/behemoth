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
	"github.com/mattn/go-sqlite3"
)

// SQLiteAdapter implements behemoth.Database for SQLite.
//
// Models are addressed by canonical names; every table and column name in the
// generated SQL goes through Resolver first. A nil Resolver maps every name to
// itself.
type SQLiteAdapter struct {
	DB       Querier
	Resolver behemoth.SchemaResolver
}

func NewSQLiteAdapter(db Querier, resolver behemoth.SchemaResolver) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db, Resolver: resolver}
}

func (sqlt *SQLiteAdapter) names() behemoth.SchemaResolver {
	return resolverOrIdentity(sqlt.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (sqlt *SQLiteAdapter) where(m behemoth.Model, expr *clause.Expression) (string, []any) {
	return BuildSQLWhereClause(physicalExpression(sqlt.names(), m, expr), DefaultClauseOption)
}

func (sqlt *SQLiteAdapter) Create(ctx context.Context, m behemoth.Model) error {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	placeholders := GeneratePlaceholdersSlice(
		DefaultClauseOption.Number,
		len(columns),
		DefaultClauseOption.Placeholder,
		DefaultClauseOption.UseNumberedPlaceholder,
	)

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		physicalTable(sqlt.names(), m),
		strings.Join(physicalColumns(sqlt.names(), m, columns), ", "),
		placeholders,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, values...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}

	// columns stay canonical: they key the map handed to FromMap.
	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	query := fmt.Sprintf(
		"SELECT %s FROM %s",
		strings.Join(physicalColumns(sqlt.names(), m, columns), ", "),
		physicalTable(sqlt.names(), m),
	)
	whereClause, args := sqlt.where(m, &whereExpression)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " LIMIT 1"

	fmt.Println("Executing query:", query, "with args:", args)
	row := sqlt.DB.QueryRowContext(ctx, query, args...)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
	}

	return models.GenerateModelFromRows(m, columns, values)
}

func (sqlt *SQLiteAdapter) FindMany(
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
	if options != nil && len(options.Select) > 0 {
		columns, values, valuePtrs = models.GenerateColumnValuePairsWithSelectFilter(m, options.Select)
	} else {
		columns, values, valuePtrs = models.GenerateColumnValuePairs(m)
	}

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := sqlt.where(m, &whereExpression)

	query = fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(physicalColumns(sqlt.names(), m, columns), ", "),
		physicalTable(sqlt.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		if options.OrderBy.Field != "" {
			query += fmt.Sprintf(" ORDER BY %s %s", physicalColumn(sqlt.names(), m, options.OrderBy.Field), options.OrderBy.Direction)
		}
		if options.Limit != 0 {
			query += fmt.Sprintf(" LIMIT %d", options.Limit)
		}
		if options.Offset != 0 {
			query += fmt.Sprintf(" OFFSET %d", options.Offset)
		}

	}

	fmt.Println("Executing query:", query, "with args:", args)
	rows, err := sqlt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
	}

	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		err := rows.Scan(valuePtrs...)
		if err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
		}
		result, err := models.GenerateModelFromRows(m, columns, values)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

func (sqlt *SQLiteAdapter) Update(ctx context.Context, m behemoth.Model) error {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = ?",
		physicalTable(sqlt.names(), m),
		GenerateSQLSETClause(
			physicalColumns(sqlt.names(), m, columns),
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		physicalColumn(sqlt.names(), m, m.PrimaryKeyName()),
	)

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereClause, args := sqlt.where(m, &expr)
	table := physicalTable(sqlt.names(), m)
	pk := physicalColumn(sqlt.names(), m, m.PrimaryKeyName())

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		table,
		GenerateSQLSETClause(
			physicalColumns(sqlt.names(), m, columns),
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		pk,
		selectQuery,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, args...)...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {

	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereExpression, args := sqlt.where(m, &expr)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		physicalTable(sqlt.names(), m),
		GenerateSQLSETClause(
			physicalColumns(sqlt.names(), m, columns),
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		whereExpression,
	)

	fmt.Println("Executing query ", query)
	_, err := sqlt.DB.ExecContext(ctx, query, append(values, args...)...)

	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ?",
		physicalTable(sqlt.names(), m),
		physicalColumn(sqlt.names(), m, m.PrimaryKeyName()),
	)
	_, err := sqlt.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	whereClause, args := sqlt.where(m, &expr)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteOne, "clause", nil)
	}

	table := physicalTable(sqlt.names(), m)
	pk := physicalColumn(sqlt.names(), m, m.PrimaryKeyName())

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = (%s)",
		table,
		pk,
		selectQuery,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := sqlt.where(m, &expr)

	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		physicalTable(sqlt.names(), m),
		whereClause,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s",
		physicalTable(sqlt.names(), m),
	)

	_, err := sqlt.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
}

func (sqlt *SQLiteAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	whereClause, args := sqlt.where(m, &expr)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		physicalTable(sqlt.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := sqlt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
	}

	defer row.Close()
	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, WrapWithCaller(err, m.SchemaName(), mapSQLiteErrors)
		}
	}

	return count, nil
}

func (sqlt *SQLiteAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	tx, err := sqlt.DB.(*sql.DB).BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	txAdapter := NewSQLiteAdapter(tx, sqlt.Resolver)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()
}

// mapSQLiteErrors classifies mattn/go-sqlite3 errors by result code.
func mapSQLiteErrors(op, entity string, err error) error {
	if classified, ok := mapStdSQLErrors(op, entity, err); ok {
		return classified
	}

	switch {
	case isSQLiteMissingTable(err):
		return classify(op, entity, sentinelUndefinedTable, err)
	case isSQLiteConstraintViolation(err):
		if isUniqueConstraint(err) {
			return classify(op, entity, sentinelDuplicateKey, err)
		}
		if isForeignKeyConstraint(err) {
			return classify(op, entity, sentinelForeignKey, err)
		}
		return classify(op, entity, sentinelConstraintViolation, err)
	default:
		return classify(op, entity, sentinelUnknown, err)
	}

}

// isSQLiteMissingTable matches "no such table: x". SQLite reports it with the
// generic SQLITE_ERROR code, so the message is the only distinguishing signal.
func isSQLiteMissingTable(err error) bool {
	if sqliteErr, ok := errors.AsType[sqlite3.Error](err); ok {
		return sqliteErr.Code == sqlite3.ErrError && strings.HasPrefix(sqliteErr.Error(), "no such table")
	}
	return false
}

func isSQLiteConstraintViolation(err error) bool {
	if sqliteErr, ok := errors.AsType[sqlite3.Error](err); ok { // mattn returns sqlite3.Error by value
		return sqliteErr.Code == sqlite3.ErrConstraint
	}
	return false
}

func isUniqueConstraint(err error) bool {
	if sqliteErr, ok := errors.AsType[sqlite3.Error](err); ok { // mattn returns sqlite3.Error by value
		return sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique ||
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey
	}
	return false
}

func isForeignKeyConstraint(err error) bool {
	if sqliteErr, ok := errors.AsType[sqlite3.Error](err); ok {
		return sqliteErr.ExtendedCode == sqlite3.ErrConstraintForeignKey
	}
	return false
}
