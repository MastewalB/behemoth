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

type SQLiteAdapter struct {
	DB Querier
}

func NewSQLiteAdapter(db Querier) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db}
}

func (sqlt *SQLiteAdapter) Create(ctx context.Context, m behemoth.Model) error {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return fmt.Errorf("model does not implement Serializable interface")
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	placeholders := utils.GenerateSQLPlaceholders(1, len(columns))

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
		return nil, fmt.Errorf("model does not implement Serializable interface")
	}

	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	whereClause, args := BuildSQLWhereClause(&whereExpression)
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
) ([]behemoth.Model, error) {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, fmt.Errorf("model does not implement Serializable interface")
	}

	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	whereClause, args := BuildSQLWhereClause(&whereExpression)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s",
		strings.Join(columns, ", "),
		m.SchemaName(),
		whereClause,
	)

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
		utils.GenerateSQLSETClause(columns),
		m.PrimaryKeyName(),
	)

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (sqlt *SQLiteAdapter) UpdateField(ctx context.Context, m behemoth.Model, fieldName string, value any) error {
	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = ?",
		m.SchemaName(),
		utils.GenerateSQLSETClause([]string{fieldName}),
		m.PrimaryKeyName(),
	)

	_, err := sqlt.DB.ExecContext(ctx, query, []any{value, m.PrimaryKeyField()}...)
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

func BuildSQLWhereClause(expr *clause.Expression) (string, []any) {
	return buildSQLiteWhereClause(expr, 1)
}

func buildSQLiteWhereClause(expr *clause.Expression, N int) (string, []any) {
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

	if len(expr.Children) > 0 {
		for _, child := range expr.Children {
			subQuery, subArgs := buildSQLiteWhereClause(child, N)
			queryParts = append(queryParts, subQuery)
			args = append(args, subArgs...)
			N += len(subArgs)
		}
	}
	for _, cond := range expr.Conditions {
		subQuery, subArgs := buildConditionSQL(cond, N)
		queryParts = append(queryParts, subQuery)
		args = append(args, subArgs...)
		N += len(subArgs)
	}

	joinedQuery := strings.Join(queryParts, fmt.Sprintf(" %s ", logicalOp))

	return fmt.Sprintf(formatString, joinedQuery), args
}

func buildConditionSQL(cond clause.Condition, N int) (string, []any) {
	switch cond.Operator {
	case clause.OpEqual:
		return fmt.Sprintf("(%s = $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpNotEqual:
		return fmt.Sprintf("(%s != $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpGreaterThan:
		return fmt.Sprintf("(%s > $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpGreaterEq:
		return fmt.Sprintf("(%s >= $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpLessThan:
		return fmt.Sprintf("(%s < $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpLessEq:
		return fmt.Sprintf("(%s <= $%d)", cond.Field, N), []any{cond.Value}

	case clause.OpIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := utils.GenerateSQLPlaceholders(N, N+len(valueSlice)-1)
		return fmt.Sprintf("(%s IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpNotIn:
		valueSlice := ToSlice(cond.Value)
		placeholders := utils.GenerateSQLPlaceholders(N, N+len(valueSlice)-1)
		return fmt.Sprintf("(%s NOT IN %s)", cond.Field, placeholders), valueSlice

	case clause.OpStartsWith:
		return fmt.Sprintf("(%s LIKE $%d)", cond.Field, N), []any{fmt.Sprintf("%s%%", cond.Value)}

	case clause.OpEndsWith:
		return fmt.Sprintf("(%s LIKE $%d)", cond.Field, N), []any{fmt.Sprintf("%%%s", cond.Value)}

	case clause.OpContains:
		return fmt.Sprintf("(%s LIKE $%d)", cond.Field, N), []any{fmt.Sprintf("%%%s%%", cond.Value)}

	case clause.OpIsNull:
		return fmt.Sprintf("(%s IS NULL)", cond.Field), nil

	case clause.OpNotNull:
		return fmt.Sprintf("(%s IS NOT NULL)", cond.Field), nil

	default:
		return "", []any{cond.Value}
	}
}

func mapSQLErrors(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch err {
	case sql.ErrNoRows:
		return behemotherr.NewNotFound(op, entity, err)
	case sql.ErrTxDone:
		return behemotherr.NewTransactionError(op, err)

	default:
		return behemotherr.NewDatabaseError(op, err)
	}

}
