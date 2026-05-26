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

type PostgresAdapter struct {
	DB *sql.DB
}

func NewPostgresAdapter(db *sql.DB) *PostgresAdapter {
	return &PostgresAdapter{DB: db}
}

func (pg *PostgresAdapter) Create(ctx context.Context, m behemoth.Model) error {
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
	_, err := pg.DB.ExecContext(ctx, query, values...)

	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {

	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	whereClause, args := BuildSQLWhereClause(&whereExpression)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		strings.Join(columns, ", "),
		m.SchemaName(),
		whereClause,
	)

	fmt.Println("Executing query:", query, "with args:", args)
	row := pg.DB.QueryRowContext(ctx, query, args...)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
	}

	return models.GenerateModelFromRows(m, columns, values)
}

func (pg *PostgresAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) ([]behemoth.Model, error) {
	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	whereClause, args := BuildSQLWhereClause(&whereExpression)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s",
		strings.Join(columns, ", "),
		m.SchemaName(),
		whereClause,
	)

	fmt.Println("Executing query:", query, "with args:", args)

	rows, err := pg.DB.QueryContext(ctx, query, args...)
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

func (pg *PostgresAdapter) Update(ctx context.Context, m behemoth.Model) error {
	columns, values, _ := models.GenerateColumnValuePairs(m)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = $%d",
		m.SchemaName(),
		utils.GenerateSQLSETClause(columns),
		m.PrimaryKeyName(),
		len(values)+1,
	)
	fmt.Println(query, values)

	_, err := pg.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = $1",
		m.SchemaName(),
		m.PrimaryKeyName(),
	)

	_, err := pg.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}
