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

type SQLiteAdapter struct {
	DB Querier
}

func NewSQLiteAdapter(db Querier) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db}
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
		m.SchemaName(),
		strings.Join(columns, ", "),
		placeholders,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, values...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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

	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	whereClause, args := BuildSQLWhereClause(&whereExpression, DefaultClauseOption)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		strings.Join(columns, ", "),
		m.SchemaName(),
		whereClause,
	)

	fmt.Println("Executing query:", query, "with args:", args)
	row := sqlt.DB.QueryRowContext(ctx, query, args...)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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

	if options != nil && len(options.Select) > 0 {
		columns, values, valuePtrs = models.GenerateColumnValuePairsWithSelectFilter(m, options.Select)
	} else {
		columns, values, valuePtrs = models.GenerateColumnValuePairs(m)
	}

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := BuildSQLWhereClause(&whereExpression, DefaultClauseOption)

	if whereClause != "" {
		query = fmt.Sprintf(
			"SELECT %s%s FROM %s WHERE %s",
			distinctClause,
			strings.Join(columns, ", "),
			m.SchemaName(),
			whereClause,
		)
	} else {
		query = fmt.Sprintf(
			"SELECT %s%s FROM %s",
			distinctClause,
			strings.Join(columns, ", "),
			m.SchemaName(),
		)
	}

	if options != nil {
		if options.OrderBy.Field != "" {
			query += fmt.Sprintf(" ORDER BY %s %s", options.OrderBy.Field, options.OrderBy.Direction)
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
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
	}

	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		err := rows.Scan(valuePtrs...)
		if err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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
		m.SchemaName(),
		GenerateSQLSETClause(
			columns,
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		m.PrimaryKeyName(),
	)

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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
	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		m.PrimaryKeyName(),
		m.SchemaName(),
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		m.SchemaName(),
		GenerateSQLSETClause(
			columns,
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, args...)...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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
	whereExpression, args := BuildSQLWhereClause(&expr, DefaultClauseOption)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		m.SchemaName(),
		GenerateSQLSETClause(
			columns,
			DefaultClauseOption.Number,
			DefaultClauseOption.Placeholder,
			DefaultClauseOption.UseNumberedPlaceholder,
		),
		whereExpression,
	)

	fmt.Println("Executing query ", query)
	_, err := sqlt.DB.ExecContext(ctx, query, append(values, args...)...)

	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ?",
		m.SchemaName(),
		m.PrimaryKeyName(),
	)
	_, err := sqlt.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteOne, "clause", nil)
	}

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		m.PrimaryKeyName(),
		m.SchemaName(),
		whereClause,
	)

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = (%s)",
		m.SchemaName(),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)

	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		m.SchemaName(),
		whereClause,
	)

	_, err := sqlt.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s",
		m.SchemaName(),
	)

	_, err := sqlt.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	var query string
	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)

	if whereClause != "" {

		query = fmt.Sprintf(
			"SELECT COUNT(*) FROM %s WHERE %s",
			m.SchemaName(),
			whereClause,
		)
	} else {
		query = fmt.Sprintf(
			"SELECT COUNT(*) FROM %s",
			m.SchemaName(),
		)
	}

	row, err := sqlt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
	}

	defer row.Close()
	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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

	txAdapter := NewSQLiteAdapter(tx)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()
}

func mapSQLErrors(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return classify(op, entity, sentinelNotFound, err)
	case errors.Is(err, sql.ErrTxDone):
		return classify(op, entity, sentinelTxDone, err)
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

func isSQLiteConstraintViolation(err error) bool {
	var sqliteErr *sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrConstraint
	}
	return false
}

func isUniqueConstraint(err error) bool {
	var sqliteErr *sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique ||
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey
	}
	return false
}

func isForeignKeyConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.ExtendedCode == sqlite3.ErrConstraintForeignKey
	}
	return false
}
