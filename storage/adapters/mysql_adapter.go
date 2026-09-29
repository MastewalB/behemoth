package adapters

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
)

// MySQLAdapter implements the behemoth.Database interface for MySQL.
type MySQLAdapter struct {
	DB Querier
}

func NewMySQLAdapter(db Querier) *MySQLAdapter {
	return &MySQLAdapter{DB: db}
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
		m.SchemaName(),
		strings.Join(columns, ", "),
		placeholders,
	)

	_, err := my.DB.ExecContext(ctx, query, values...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (my *MySQLAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
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

	row := my.DB.QueryRowContext(ctx, query, args...)
	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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
		// MySQL supports LIMIT / OFFSET in the same way as SQLite.
		if options.Limit != 0 {
			query += fmt.Sprintf(" LIMIT %d", options.Limit)
		}
		if options.Offset != 0 {
			query += fmt.Sprintf(" OFFSET %d", options.Offset)
		}
	}

	fmt.Println(query, args)
	rows, err := my.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
	}
	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
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

func (my *MySQLAdapter) Update(ctx context.Context, m behemoth.Model) error {
	if _, ok := m.(behemoth.Serializable); !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = ?",
		m.SchemaName(),
		generateMySQLSETClause(columns),
		m.PrimaryKeyName(),
	)

	_, err := my.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
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
	whereClause, whereArgs := BuildSQLWhereClause(&expr, DefaultClauseOption)

	// MySQL forbids "UPDATE t SET ... WHERE pk = (SELECT pk FROM t WHERE ...)"
	// when the subquery references the same table. We work around this by
	// wrapping the subquery in a derived table aliased as `_sub`.
	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		m.PrimaryKeyName(),
		m.SchemaName(),
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (SELECT %s FROM (%s) AS _sub)",
		m.SchemaName(),
		generateMySQLSETClause(columns),
		m.PrimaryKeyName(),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := my.DB.ExecContext(ctx, query, append(values, whereArgs...)...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)

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
	whereClause, whereArgs := BuildSQLWhereClause(&expr, DefaultClauseOption)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		m.SchemaName(),
		generateMySQLSETClause(columns),
		whereClause,
	)

	_, err := my.DB.ExecContext(ctx, query, append(values, whereArgs...)...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)

}

func (my *MySQLAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ?",
		m.SchemaName(),
		m.PrimaryKeyName(),
	)
	_, err := my.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (my *MySQLAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
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
		"DELETE FROM %s WHERE %s = (SELECT %s FROM (%s) AS _sub)",
		m.SchemaName(),
		m.PrimaryKeyName(),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := my.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (my *MySQLAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		m.SchemaName(),
		whereClause,
	)

	_, err := my.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (my *MySQLAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf("DELETE FROM %s", m.SchemaName())
	_, err := my.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (my *MySQLAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	whereClause, args := BuildSQLWhereClause(&expr, DefaultClauseOption)

	var query string
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

	row, err := my.DB.QueryContext(ctx, query, args...)
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

func (my *MySQLAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	tx, err := my.DB.(*sql.DB).BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	txAdapter := NewMySQLAdapter(tx)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()

}
