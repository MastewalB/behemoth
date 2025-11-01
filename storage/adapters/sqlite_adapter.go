package adapters

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/utils"
)

type SQLiteAdapter struct {
	DB *sql.DB
}

func NewSQLiteAdapter(db *sql.DB) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db}
}

func (sqlt *SQLiteAdapter) Create(ctx context.Context, m behemoth.Model) error {
	query := `INSERT INTO ` + m.TableName() + ` (` +
		strings.Join(m.Fields(), ", ") + `) VALUES ` +
		utils.GenerateSQLPlaceholders(len(m.Fields()))

	fmt.Println("Executing query:", query, "with values:", m.ScanDestinations())
	_, err := sqlt.DB.ExecContext(ctx, query, m.ScanDestinations()...)
	return err
}

func (sqlt *SQLiteAdapter) Find(ctx context.Context, m behemoth.Model, whereExpression clause.Expression) (behemoth.Model, error) {
	whereClause, args := BuildSQLiteWhereClause(&whereExpression, 1)
	query := `SELECT * FROM ` + m.TableName() + ` WHERE ` + whereClause + ` LIMIT 1`
	fmt.Println("Executing query:", query, "with args:", args)
	row := sqlt.DB.QueryRowContext(ctx, query, args...)

	err := row.Scan(m.ScanDestinations()...)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (sqlt *SQLiteAdapter) Update(ctx context.Context, m behemoth.Model) error {
	query := `UPDATE ` + m.TableName() +
		` SET ` + utils.GenerateSQLSETClause(m.Fields()) +
		` WHERE ` + m.PrimaryKey() + ` = ?`

	_, err := sqlt.DB.ExecContext(ctx, query, append(m.ScanDestinations(), m.PrimaryValue())...)
	return err
}

func (sqlt *SQLiteAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := `DELETE FROM ` + m.TableName() + ` WHERE ` + m.PrimaryKey() + ` = ?`
	_, err := sqlt.DB.ExecContext(ctx, query, m.PrimaryValue())
	return err
}

func BuildSQLiteWhereClause(expr *clause.Expression, N int) (string, []any) {
	if expr == nil {
		return "", nil
	}

	var queryParts []string
	var args []any

	if len(expr.Children) > 0 {
		for _, child := range expr.Children {
			subQuery, subArgs := BuildSQLiteWhereClause(child, N)
			queryParts = append(queryParts, fmt.Sprintf("(%s)", subQuery))
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

	return strings.Join(queryParts, fmt.Sprintf(" %s ", expr.Logic)), args
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
		placeholders := utils.GenerateSQLPlaceholders(len(cond.Value.([]any)))
		return fmt.Sprintf("(%s IN %s)", cond.Field, placeholders), cond.Value.([]any)

	case clause.OpNotIn:
		placeholders := utils.GenerateSQLPlaceholders(len(cond.Value.([]any)))
		return fmt.Sprintf("(%s NOT IN %s)", cond.Field, placeholders), cond.Value.([]any)

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
