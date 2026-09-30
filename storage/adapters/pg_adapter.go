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
)

// PostgresAdapter implements behemoth.Database for PostgreSQL.
//
// Models are addressed by canonical names; every table and column name in the
// generated SQL goes through Resolver first. A nil Resolver maps every name to
// itself.
type PostgresAdapter struct {
	DB       Querier
	Resolver behemoth.SchemaResolver
}

func NewPostgresAdapter(db Querier, resolver behemoth.SchemaResolver) *PostgresAdapter {
	return &PostgresAdapter{DB: db, Resolver: resolver}
}

func (pg *PostgresAdapter) names() behemoth.SchemaResolver {
	return resolverOrIdentity(pg.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (pg *PostgresAdapter) where(m behemoth.Model, expr *clause.Expression, options *ClauseOptions) (string, []any) {
	return BuildSQLWhereClause(physicalExpression(pg.names(), m, expr), options)
}

// sqlStater is implemented by both lib/pq's *pq.Error and pgx's
// *pgconn.PgError, so the adapter works with either driver.
type sqlStater interface {
	error
	SQLState() string
}

// mapPostgresErrors classifies Postgres errors by SQLSTATE
// (https://www.postgresql.org/docs/current/errcodes-appendix.html).
func mapPostgresErrors(op, entity string, err error) error {
	if classified, ok := mapStdSQLErrors(op, entity, err); ok {
		return classified
	}

	pgErr, ok := errors.AsType[sqlStater](err)
	if !ok {
		return classify(op, entity, sentinelUnknown, err)
	}
	switch code := pgErr.SQLState(); code {
	case "23505": // unique_violation
		return classify(op, entity, sentinelDuplicateKey, err)
	case "23503": // foreign_key_violation
		return classify(op, entity, sentinelForeignKey, err)
	case "42P01": // undefined_table
		return classify(op, entity, sentinelUndefinedTable, err)
	default:
		if len(code) == 5 && code[:2] == "23" { // class 23: any other integrity constraint (not_null, check, exclusion)
			return classify(op, entity, sentinelConstraintViolation, err)
		}
		return classify(op, entity, sentinelUnknown, err)
	}
}

var defaultPostgresClauseOptions = &ClauseOptions{
	Placeholder:            "$",
	UseNumberedPlaceholder: true,
	Number:                 1,
}

// Create a Postgres ClauseOptions with a specified starting number for numbered placeholderes.
func NewPostgresClauseOptions(N int) *ClauseOptions {
	return &ClauseOptions{
		Placeholder:            "$",
		UseNumberedPlaceholder: true,
		Number:                 N,
	}
}

func (pg *PostgresAdapter) Create(ctx context.Context, m behemoth.Model) error {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}

	columns, values, _ := models.GenerateColumnValuePairs(m)
	placeholders := GeneratePlaceholdersSlice(
		defaultPostgresClauseOptions.Number,
		len(columns),
		defaultPostgresClauseOptions.Placeholder,
		defaultPostgresClauseOptions.UseNumberedPlaceholder,
	)

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		physicalTable(pg.names(), m),
		strings.Join(physicalColumns(pg.names(), m, columns), ", "),
		placeholders,
	)
	_, err := pg.DB.ExecContext(ctx, query, values...)

	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	whereExpression clause.Expression,
) (behemoth.Model, error) {

	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}

	// columns stay canonical: they key the map handed to FromMap.
	columns, values, valuePtrs := models.GenerateColumnValuePairs(m)

	query := fmt.Sprintf(
		"SELECT %s FROM %s",
		strings.Join(physicalColumns(pg.names(), m, columns), ", "),
		physicalTable(pg.names(), m),
	)
	whereClause, args := pg.where(m, &whereExpression, defaultPostgresClauseOptions)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " LIMIT 1"

	fmt.Println("Executing query:", query, "with args:", args)
	row := pg.DB.QueryRowContext(ctx, query, args...)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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

	// columns stay canonical: they key the map handed to FromMap.
	if options != nil && len(options.Select) > 0 {
		columns, values, valuePtrs = models.GenerateColumnValuePairsWithSelectFilter(m, options.Select)
	} else {
		columns, values, valuePtrs = models.GenerateColumnValuePairs(m)
	}

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := pg.where(m, &whereExpression, defaultPostgresClauseOptions)

	query = fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(physicalColumns(pg.names(), m, columns), ", "),
		physicalTable(pg.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		if options.OrderBy.Field != "" {
			query += fmt.Sprintf(" ORDER BY %s %s", physicalColumn(pg.names(), m, options.OrderBy.Field), options.OrderBy.Direction)
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
		return nil, WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}

	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
		physicalTable(pg.names(), m),
		GenerateSQLSETClause(physicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),
		physicalColumn(pg.names(), m, m.PrimaryKeyName()),
		len(values)+1,
	)
	fmt.Println(query, values)

	_, err := pg.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
	whereClause, args := pg.where(m, &expr, NewPostgresClauseOptions(len(values)+1))
	table := physicalTable(pg.names(), m)
	pk := physicalColumn(pg.names(), m, m.PrimaryKeyName())

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		table,
		GenerateSQLSETClause(physicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),

		pk,
		selectQuery,
	)

	_, err := pg.DB.ExecContext(ctx, query, append(values, args...)...)
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
	whereExpression, args := pg.where(m, &expr, NewPostgresClauseOptions(len(values)+1))

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s",
		physicalTable(pg.names(), m),
		GenerateSQLSETClause(physicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),

		whereExpression,
	)

	fmt.Println("Executing query ", query)
	_, err := pg.DB.ExecContext(ctx, query, append(values, args...)...)

	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = $1",
		physicalTable(pg.names(), m),
		physicalColumn(pg.names(), m, m.PrimaryKeyName()),
	)

	_, err := pg.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteOne, "clause", nil)
	}

	table := physicalTable(pg.names(), m)
	pk := physicalColumn(pg.names(), m, m.PrimaryKeyName())

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

	_, err := pg.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)

	if whereClause == "" {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		physicalTable(pg.names(), m),
		whereClause,
	)

	_, err := pg.DB.ExecContext(ctx, query, args...)
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s",
		physicalTable(pg.names(), m),
	)

	_, err := pg.DB.ExecContext(ctx, query)
	return WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		physicalTable(pg.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := pg.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}

	defer row.Close()
	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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

	txAdapter := NewPostgresAdapter(tx, pg.Resolver)
	_, err = fn(ctx, txAdapter)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return behemotherr.NewTransactionError("Transaction", rollbackErr)
		}
		return err
	}

	return tx.Commit()
}
