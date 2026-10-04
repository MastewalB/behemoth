package postgres

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
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/utils"
)

// PostgresAdapter implements behemoth.Database for PostgreSQL.
//
// Models are addressed by canonical names; every table and column name in the
// generated SQL goes through Resolver first. A nil Resolver maps every name to
// itself.
type PostgresAdapter struct {
	DB       adapters.Querier
	Resolver behemoth.SchemaResolver
}

func NewPostgresAdapter(db adapters.Querier, resolver behemoth.SchemaResolver) *PostgresAdapter {
	return &PostgresAdapter{DB: db, Resolver: resolver}
}

func (pg *PostgresAdapter) names() behemoth.SchemaResolver {
	return adapters.ResolverOrIdentity(pg.Resolver)
}

// where renders expr with its fields resolved to physical columns.
func (pg *PostgresAdapter) where(m behemoth.Model, expr *clause.Expression, options *adapters.ClauseOptions) (string, []any) {
	return adapters.BuildSQLWhereClause(adapters.PhysicalExpression(pg.names(), m, expr), options)
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
	if classified, ok := adapters.MapStdSQLErrors(op, entity, err); ok {
		return classified
	}

	pgErr, ok := errors.AsType[sqlStater](err)
	if !ok {
		return adapters.Classify(op, entity, adapters.SentinelUnknown, err)
	}
	switch code := pgErr.SQLState(); code {
	case "23505": // unique_violation
		return adapters.Classify(op, entity, adapters.SentinelDuplicateKey, err)
	case "23503": // foreign_key_violation
		return adapters.Classify(op, entity, adapters.SentinelForeignKey, err)
	case "42P01": // undefined_table
		return adapters.Classify(op, entity, adapters.SentinelUndefinedTable, err)
	default:
		if len(code) == 5 && code[:2] == "23" { // class 23: any other integrity constraint (not_null, check, exclusion)
			return adapters.Classify(op, entity, adapters.SentinelConstraintViolation, err)
		}
		return adapters.Classify(op, entity, adapters.SentinelUnknown, err)
	}
}

var defaultPostgresClauseOptions = &adapters.ClauseOptions{
	Placeholder:            "$",
	UseNumberedPlaceholder: true,
	Number:                 1,
}

// Create a Postgres adapters.ClauseOptions with a specified starting number for numbered placeholderes.
func NewPostgresClauseOptions(N int) *adapters.ClauseOptions {
	return &adapters.ClauseOptions{
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
	placeholders := adapters.GeneratePlaceholdersSlice(
		defaultPostgresClauseOptions.Number,
		len(columns),
		defaultPostgresClauseOptions.Placeholder,
		defaultPostgresClauseOptions.UseNumberedPlaceholder,
	)

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES %s",
		adapters.PhysicalTable(pg.names(), m),
		strings.Join(adapters.PhysicalColumns(pg.names(), m, columns), ", "),
		placeholders,
	)
	_, err := pg.DB.ExecContext(ctx, query, values...)

	return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
	columns := adapters.ReadColumns(pg.names(), m, nil)
	values, valuePtrs := adapters.ScanTargets(len(columns))

	query := fmt.Sprintf(
		"SELECT %s FROM %s",
		strings.Join(adapters.PhysicalColumns(pg.names(), m, columns), ", "),
		adapters.PhysicalTable(pg.names(), m),
	)
	whereClause, args := pg.where(m, &whereExpression, defaultPostgresClauseOptions)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " LIMIT 1"

	fmt.Println("Executing query:", query, "with args:", args)
	row := pg.DB.QueryRowContext(ctx, query, args...)

	if err := row.Scan(valuePtrs...); err != nil {
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
	var selected []string
	if options != nil {
		selected = options.Select
	}
	columns = adapters.ReadColumns(pg.names(), m, selected)
	values, valuePtrs = adapters.ScanTargets(len(columns))

	if options != nil && options.Distinct {
		distinctClause = "DISTINCT "
	}

	whereClause, args := pg.where(m, &whereExpression, defaultPostgresClauseOptions)

	query = fmt.Sprintf(
		"SELECT %s%s FROM %s",
		distinctClause,
		strings.Join(adapters.PhysicalColumns(pg.names(), m, columns), ", "),
		adapters.PhysicalTable(pg.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if options != nil {
		if options.OrderBy.Field != "" {
			query += fmt.Sprintf(" ORDER BY %s %s", adapters.PhysicalColumn(pg.names(), m, options.OrderBy.Field), options.OrderBy.Direction)
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
		return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}

	defer rows.Close()

	var results []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
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
		adapters.PhysicalTable(pg.names(), m),
		adapters.GenerateSQLSETClause(adapters.PhysicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),
		adapters.PhysicalColumn(pg.names(), m, m.PrimaryKeyName()),
		len(values)+1,
	)
	fmt.Println(query, values)

	res, err := pg.DB.ExecContext(ctx, query, append(values, m.PrimaryKeyField())...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	return adapters.ExpectOneRow("Update", m, n, nil)
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
	table := adapters.PhysicalTable(pg.names(), m)
	pk := adapters.PhysicalColumn(pg.names(), m, m.PrimaryKeyName())

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT 1",
		pk,
		table,
		whereClause,
	)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s)",
		table,
		adapters.GenerateSQLSETClause(adapters.PhysicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),

		pk,
		selectQuery,
	)
	// expr is repeated in the outer WHERE (the UpdateOne convention):
	// Postgres evaluates the selecting subquery once, before waiting on a
	// concurrent writer's lock, and afterwards re-checks only the outer
	// WHERE — without the repetition the update would still apply to a row
	// the other writer just changed. Numbered placeholders continue after
	// the subquery's. Postgres reports matched rows.
	queryArgs := append(values, args...)
	guard, guardArgs := pg.where(m, &expr, NewPostgresClauseOptions(len(queryArgs)+1))
	query += " AND (" + guard + ")"
	queryArgs = append(queryArgs, guardArgs...)

	res, err := pg.DB.ExecContext(ctx, query, queryArgs...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	return adapters.ExpectOneRow("UpdateOne", m, n, nil)
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
		adapters.PhysicalTable(pg.names(), m),
		adapters.GenerateSQLSETClause(adapters.PhysicalColumns(pg.names(), m, columns),
			defaultPostgresClauseOptions.Number,
			defaultPostgresClauseOptions.Placeholder,
			defaultPostgresClauseOptions.UseNumberedPlaceholder,
		),

		whereExpression,
	)

	fmt.Println("Executing query ", query)
	_, err := pg.DB.ExecContext(ctx, query, append(values, args...)...)

	return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = $1",
		adapters.PhysicalTable(pg.names(), m),
		adapters.PhysicalColumn(pg.names(), m, m.PrimaryKeyName()),
	)

	res, err := pg.DB.ExecContext(ctx, query, m.PrimaryKeyField())
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	return adapters.ExpectOneRow("Delete", m, n, nil)
}

func (pg *PostgresAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)
	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteOne, "clause", nil)
	}

	table := adapters.PhysicalTable(pg.names(), m)
	pk := adapters.PhysicalColumn(pg.names(), m, m.PrimaryKeyName())

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

	// expr is repeated in the outer WHERE so it holds for the row as deleted
	// (see UpdateOne); numbered placeholders continue after the subquery's.
	guard, guardArgs := pg.where(m, &expr, NewPostgresClauseOptions(len(args)+1))
	query += " AND (" + guard + ")"
	res, err := pg.DB.ExecContext(ctx, query, append(args, guardArgs...)...)
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}
	return adapters.ExpectOneRow("DeleteOne", m, n, nil)
}

func (pg *PostgresAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)

	if whereClause == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteMany, "clause", nil)
	}

	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s",
		adapters.PhysicalTable(pg.names(), m),
		whereClause,
	)

	_, err := pg.DB.ExecContext(ctx, query, args...)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	query := fmt.Sprintf(
		"DELETE FROM %s",
		adapters.PhysicalTable(pg.names(), m),
	)

	_, err := pg.DB.ExecContext(ctx, query)
	return adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
}

func (pg *PostgresAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	whereClause, args := pg.where(m, &expr, defaultPostgresClauseOptions)

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s",
		adapters.PhysicalTable(pg.names(), m),
	)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	row, err := pg.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
	}

	defer row.Close()
	var count int64
	if row.Next() {
		if err := row.Scan(&count); err != nil {
			return 0, adapters.WrapWithCaller(err, m.SchemaName(), mapPostgresErrors)
		}
	}

	return count, nil
}

// Transaction runs fn with an adapter bound to one database transaction. fn's
// error rolls the transaction back and is returned as-is.
//
// Called on an adapter that is already bound to a transaction (the one
// Transaction hands to fn), it runs fn in that same transaction: nothing is
// begun, committed or rolled back here, and fn's error is returned for the
// outer call to roll back on. Code that is handed an adapter, such as a hook
// handler, can therefore call Transaction without knowing whether one is open.
func (pg *PostgresAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	var db *sql.DB
	switch q := pg.DB.(type) {
	case *sql.DB:
		db = q
	case *sql.Tx:
		_, err := fn(ctx, pg)
		return err
	default:
		return behemotherr.NewTransactionError("Transaction",
			fmt.Errorf("cannot begin a transaction on a %T; the adapter needs a *sql.DB", pg.DB))
	}

	tx, err := db.BeginTx(ctx, nil)
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
