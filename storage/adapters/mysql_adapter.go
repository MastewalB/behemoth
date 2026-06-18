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
	whereClause, args := BuildMySQLWhereClause(&whereExpression)

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

	whereClause, args := BuildMySQLWhereClause(&whereExpression)

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
	whereClause, whereArgs := buildMySQLWhereClause(&expr)

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
	whereClause, whereArgs := buildMySQLWhereClause(&expr)

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
	whereClause, args := BuildMySQLWhereClause(&expr)
	if whereClause == "" {
		return &behemotherr.DomainError{
			Type:    behemotherr.Database,
			Op:      "DeleteOne",
			Entity:  m.SchemaName(),
			Message: "DeleteOne requires a where clause.",
		}
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
	whereClause, args := BuildMySQLWhereClause(&expr)
	if whereClause == "" {
		return &behemotherr.DomainError{
			Type:    behemotherr.Database,
			Op:      "DeleteMany",
			Entity:  m.SchemaName(),
			Message: "DeleteMany requires a where clause.",
		}
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
	whereClause, args := BuildMySQLWhereClause(&expr)

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

// BuildMySQLWhereClause is the exported entry point used by FindOne / FindMany / Count.
func BuildMySQLWhereClause(expr *clause.Expression) (string, []any) {
	return buildMySQLWhereClause(expr)
}

func buildMySQLWhereClause(expr *clause.Expression) (string, []any) {
	if expr == nil {
		return "", nil
	}

	var queryParts []string
	var args []any
	var formatString string
	var logicalOp clause.Logic = clause.OpAnd

	totalConditions := len(expr.Conditions) + len(expr.Children)
	if totalConditions > 1 {
		formatString = "(%s)"
	} else {
		formatString = "%s"
	}

	if expr.Logic != "" {
		logicalOp = expr.Logic
	}

	for _, child := range expr.Children {
		subQuery, subArgs := buildMySQLWhereClause(child)
		queryParts = append(queryParts, subQuery)
		args = append(args, subArgs...)
	}

	for _, cond := range expr.Conditions {
		subQuery, subArgs := buildMySQLConditionSQL(cond)
		queryParts = append(queryParts, subQuery)
		args = append(args, subArgs...)
	}

	joined := strings.Join(queryParts, fmt.Sprintf(" %s ", logicalOp))
	return fmt.Sprintf(formatString, joined), args
}

// buildMySQLConditionSQL emits '?' placeholders instead of '$N'.
func buildMySQLConditionSQL(cond clause.Condition) (string, []any) {
	switch cond.Operator {
	case clause.OpEqual:
		return fmt.Sprintf("(%s = ?)", cond.Field), []any{cond.Value}

	case clause.OpNotEqual:
		return fmt.Sprintf("(%s != ?)", cond.Field), []any{cond.Value}

	case clause.OpGreaterThan:
		return fmt.Sprintf("(%s > ?)", cond.Field), []any{cond.Value}

	case clause.OpGreaterEq:
		return fmt.Sprintf("(%s >= ?)", cond.Field), []any{cond.Value}

	case clause.OpLessThan:
		return fmt.Sprintf("(%s < ?)", cond.Field), []any{cond.Value}

	case clause.OpLessEq:
		return fmt.Sprintf("(%s <= ?)", cond.Field), []any{cond.Value}

	case clause.OpIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := "(" + strings.Repeat("?, ", len(valueSlice)-1) + "?)"
		return fmt.Sprintf("(%s IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpNotIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := "(" + strings.Repeat("?, ", len(valueSlice)-1) + "?)"
		return fmt.Sprintf("(%s NOT IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpStartsWith:
		return fmt.Sprintf("(%s LIKE ?)", cond.Field), []any{fmt.Sprintf("%s%%", cond.Value)}

	case clause.OpEndsWith:
		return fmt.Sprintf("(%s LIKE ?)", cond.Field), []any{fmt.Sprintf("%%%s", cond.Value)}

	case clause.OpContains:
		return fmt.Sprintf("(%s LIKE ?)", cond.Field), []any{fmt.Sprintf("%%%s%%", cond.Value)}

	case clause.OpIsNull:
		return fmt.Sprintf("(%s IS NULL)", cond.Field), nil

	case clause.OpNotNull:
		return fmt.Sprintf("(%s IS NOT NULL)", cond.Field), nil

	default:
		return "", []any{cond.Value}
	}
}
