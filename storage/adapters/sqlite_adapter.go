package adapters

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
)

type SQLiteAdapter struct {
	DB *sql.DB
}

func NewSQLiteAdapter(db *sql.DB) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db}
}

func (sqlt *SQLiteAdapter) CreateTable(ctx context.Context, schema string) error {
	_, err := sqlt.DB.ExecContext(ctx, schema)
	return err
}

func (sqlt *SQLiteAdapter) Create(ctx context.Context, m behemoth.Model) error {
	// query := `INSERT INTO ` + m.TableName() + ` (` +
	// 	strings.Join(m.Fields(), ", ") + `) VALUES ` +
	// 	utils.GenerateSQLPlaceholders(len(m.Fields()))

	// fmt.Println("Executing query:", query, "with values:", m.ScanDestinations())
	// _, err := sqlt.DB.ExecContext(ctx, query, m.ScanDestinations()...)

	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return fmt.Errorf("model does not implement Serializable interface")
	}
	data, err := ser.ToMap()
	if err != nil {
		return err
	}

	columns := []string{}
	values := []any{}
	placeholders := utils.GenerateSQLPlaceholders(len(data))

	i := 1
	for k, v := range data {
		columns = append(columns, k)
		values = append(values, v)
		// placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		i++
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		m.SchemaName(),
		strings.Join(columns, ", "),
		placeholders,
	)

	_, err = sqlt.DB.ExecContext(ctx, query, values...)
	return err
}

func (sqlt *SQLiteAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {

	whereClause, args := BuildSQLiteWhereClause(&whereExpression, 1)
	query := `SELECT * FROM ` + m.SchemaName() + ` WHERE ` + whereClause + ` LIMIT 1`
	fmt.Println("Executing query:", query, "with args:", args)
	row := sqlt.DB.QueryRowContext(ctx, query, args...)

	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, err
	}

	resultMap := map[string]any{}
	for i, col := range columns {
		resultMap[col] = values[i]
	}

	newModel := m.New()
	if serializable, ok := newModel.(behemoth.Serializable); ok {
		if err := serializable.FromMap(resultMap); err != nil {
			return nil, err
		}

		return newModel, nil
	}
	return nil, fmt.Errorf("model does not implement Serializable interface")
}

func (sqlt *SQLiteAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) ([]behemoth.Model, error) {

	whereClause, args := BuildSQLiteWhereClause(&whereExpression, 1)
	query := `SELECT * FROM ` + m.SchemaName() + ` WHERE ` + whereClause
	fmt.Println("Executing query:", query, "with args:", args)
	rows, err := sqlt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	_, values, _ := models.GenerateColumnValuePairs(m)

	var results []behemoth.Model
	for rows.Next() {
		err := rows.Scan(values...)
		if err != nil {
			return nil, err
		}
		results = append(results, m)
	}

	return results, nil
}

func (sqlt *SQLiteAdapter) Update(ctx context.Context, m behemoth.Model) error {
	columns, values, _ := models.GenerateColumnValuePairs(m)

	query := `UPDATE ` + m.SchemaName() +
		` SET ` + utils.GenerateSQLSETClause(columns) +
		` WHERE ` + m.PrimaryKeyName() + ` = ?`

	_, err := sqlt.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return err
}

func (sqlt *SQLiteAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := `DELETE FROM ` + m.SchemaName() + ` WHERE ` + m.PrimaryKeyName() + ` = ?`
	_, err := sqlt.DB.ExecContext(ctx, query, m.PrimaryKeyField())
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
