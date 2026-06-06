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

// Querier is implemented by both *sql.DB and *sql.Tx
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type PostgresAdapter struct {
	DB Querier
}

func NewPostgresAdapter(db Querier) *PostgresAdapter {
	return &PostgresAdapter{DB: db}
}

func (pg *PostgresAdapter) Create(ctx context.Context, m behemoth.Model) error {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
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

	whereClause, args := BuildSQLWhereClause(&whereExpression)

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
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}

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

func (pg *PostgresAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {

	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereClause, args := buildSQLiteWhereClause(&expr, len(values)+1)

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		m.PrimaryKeyName(),
		m.SchemaName(),
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		m.SchemaName(),
		utils.GenerateSQLSETClause(columns),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := pg.DB.ExecContext(ctx, query, append(values, args...)...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {

	if len(updates) == 0 {
		return nil
	}

	columns, values := utils.MapToSlice(updates)
	whereExpression, args := buildSQLiteWhereClause(&expr, len(values)+1)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		m.SchemaName(),
		utils.GenerateSQLSETClause(columns),
		whereExpression,
	)

	fmt.Println("Executing query ", query)
	_, err := pg.DB.ExecContext(ctx, query, append(values, args...)...)

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

func (pg *PostgresAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	whereClause, args := BuildSQLWhereClause(&expr)
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
		"DELETE FROM %s WHERE %s = (%s)",
		m.SchemaName(),
		m.PrimaryKeyName(),
		selectQuery,
	)

	_, err := pg.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := BuildSQLWhereClause(&expr)

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

	_, err := pg.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s",
		m.SchemaName(),
	)

	_, err := pg.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapSQLErrors)
}

func (pg *PostgresAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	var query string
	whereClause, args := BuildSQLWhereClause(&expr)

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

	// fmt.Println("Count Query: ", query, args)

	row, err := pg.DB.QueryContext(ctx, query, args...)
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

func (pg *PostgresAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	tx, err := pg.DB.(*sql.DB).BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	txAdapter := NewPostgresAdapter(tx)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()
}
