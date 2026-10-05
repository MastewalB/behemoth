package bun

import (
	"context"
	"database/sql"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/uptrace/bun"
)

// BunAdapter runs behemoth's operations through an application's bun.IDB —
// its connection, dialect, query hooks and transactions.
//
// Rows travel as maps, never as structs: what's written is the model's ToMap
// keyed by physical column, and what's read is scanned by column and handed
// to FromMap — the same path every SQL adapter takes. Behemoth's models need
// no bun tags, contributed columns (Extensible) round-trip, and the
// SchemaResolver's physical names apply. Since bun never sees a struct, bun
// model hooks (BeforeAppendModel, ...) don't run on behemoth's models;
// behemoth's data hooks are the extension point for these writes.
type BunAdapter struct {
	db       bun.IDB
	resolver behemoth.SchemaResolver
}

// NewBunAdapter wraps db (a *bun.DB, or a bun.Tx). resolver maps canonical
// names to physical ones; nil uses them as-is.
func NewBunAdapter(db bun.IDB, resolver behemoth.SchemaResolver) *BunAdapter {
	return &BunAdapter{db: db, resolver: adapters.ResolverOrIdentity(resolver)}
}

func (ba *BunAdapter) table(m behemoth.Model) bun.Ident {
	return bun.Ident(adapters.PhysicalTable(ba.resolver, m))
}

func (ba *BunAdapter) column(m behemoth.Model, canonical string) bun.Ident {
	return bun.Ident(adapters.PhysicalColumn(ba.resolver, m, canonical))
}

// whereClause renders expr with physical columns; "" for an empty expression.
func (ba *BunAdapter) whereClause(m behemoth.Model, expr *clause.Expression) (string, []any) {
	return adapters.BuildSQLWhereClause(adapters.PhysicalExpression(ba.resolver, m, expr), adapters.DefaultClauseOption)
}

// where is implemented by every bun query taking a WHERE.
type where[Q any] interface {
	Where(query string, args ...any) Q
}

// applyWhere adds expr to q; an empty expression adds no condition.
func applyWhere[Q where[Q]](ba *BunAdapter, q Q, m behemoth.Model, expr *clause.Expression) Q {
	query, args := ba.whereClause(m, expr)
	if query == "" {
		return q
	}
	return q.Where(query, args...)
}

// oneRow restricts q to a single row matching expr. expr is applied both in
// the subquery picking the row and to the row itself, so it holds for the row
// as written (the UpdateOne / DeleteOne convention). The pick is wrapped in a
// derived table because MySQL rejects a subquery on the table being updated.
func oneRow[Q where[Q]](ba *BunAdapter, q Q, m behemoth.Model, expr *clause.Expression) Q {
	pk := ba.column(m, m.PrimaryKeyName())
	pick := applyWhere(ba, ba.db.NewSelect().TableExpr("?", ba.table(m)).ColumnExpr("?", pk), m, expr).Limit(1)
	sub := ba.db.NewSelect().TableExpr("(?) AS _sub", pick).ColumnExpr("?", pk)
	return applyWhere(ba, q.Where("? IN (?)", pk, sub), m, expr)
}

// row returns m's ToMap keyed by physical column.
func (ba *BunAdapter) row(m behemoth.Model) (map[string]any, error) {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}
	data, err := ser.ToMap()
	if err != nil {
		return nil, err
	}
	return adapters.PhysicalDocument(ba.resolver, m, data), nil
}

// set adds a SET for each update, keyed by physical column.
func (ba *BunAdapter) set(q *bun.UpdateQuery, m behemoth.Model, updates map[string]any) *bun.UpdateQuery {
	for col, val := range updates {
		q = q.Set("? = ?", ba.column(m, col), val)
	}
	return q
}

// selectColumns selects the physical names of canonical columns.
func (ba *BunAdapter) selectColumns(q *bun.SelectQuery, m behemoth.Model, columns []string) *bun.SelectQuery {
	for _, c := range columns {
		q = q.ColumnExpr("?", ba.column(m, c))
	}
	return q
}

// scan reads rows of the canonical columns into new models.
func (ba *BunAdapter) scan(m behemoth.Model, rows *sql.Rows, columns []string) ([]behemoth.Model, error) {
	defer rows.Close()
	values, ptrs := adapters.ScanTargets(len(columns))
	var out []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, ba.err(m, err)
		}
		model, err := models.GenerateModelFromRows(m, columns, values)
		if err != nil {
			return nil, err
		}
		out = append(out, model)
	}
	return out, ba.err(m, rows.Err())
}

func (ba *BunAdapter) err(m behemoth.Model, err error) error {
	return adapters.WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) Create(ctx context.Context, m behemoth.Model) error {
	row, err := ba.row(m)
	if err != nil {
		return err
	}
	_, err = ba.db.NewInsert().Model(&row).TableExpr("?", ba.table(m)).Exec(ctx)
	return ba.err(m, err)
}

func (ba *BunAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}
	// columns stay canonical: they key the map handed to FromMap.
	columns := adapters.ReadColumns(ba.resolver, m, nil)
	q := ba.selectColumns(ba.db.NewSelect().TableExpr("?", ba.table(m)), m, columns)
	rows, err := applyWhere(ba, q, m, &expr).Limit(1).Rows(ctx)
	if err != nil {
		return nil, ba.err(m, err)
	}
	found, err := ba.scan(m, rows, columns)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ba.err(m, sql.ErrNoRows)
	}
	return found[0], nil
}

func (ba *BunAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	options *behemoth.QueryOptions,
) ([]behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}
	var selected []string
	if options != nil {
		selected = options.Select
	}
	// columns stay canonical: they key the map handed to FromMap.
	columns := adapters.ReadColumns(ba.resolver, m, selected)

	q := ba.selectColumns(ba.db.NewSelect().TableExpr("?", ba.table(m)), m, columns)
	q = applyWhere(ba, q, m, &expr)
	if options != nil {
		if options.Distinct {
			q = q.Distinct()
		}
		if options.OrderBy.Field != "" {
			q = q.OrderExpr("? ?", ba.column(m, options.OrderBy.Field), bun.Safe(string(options.OrderBy.Direction)))
		}
		if options.Limit != 0 {
			q = q.Limit(options.Limit)
		}
		if options.Offset != 0 {
			q = q.Offset(options.Offset)
		}
	}

	rows, err := q.Rows(ctx)
	if err != nil {
		return nil, ba.err(m, err)
	}
	return ba.scan(m, rows, columns)
}

func (ba *BunAdapter) Update(ctx context.Context, m behemoth.Model) error {
	row, err := ba.row(m)
	if err != nil {
		return err
	}
	res, err := ba.set(ba.db.NewUpdate().TableExpr("?", ba.table(m)), m, row).
		Where("? = ?", ba.column(m, m.PrimaryKeyName()), m.PrimaryKeyField()).
		Exec(ctx)
	if err != nil {
		return ba.err(m, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ba.err(m, err)
	}
	// bun reports what its dialect reports: changed rows on MySQL.
	return adapters.ExpectOneRow("Update", m, n, func() (int64, error) { return ba.Count(ctx, m, adapters.ByPrimaryKey(m)) })
}

func (ba *BunAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}
	q := ba.set(ba.db.NewUpdate().TableExpr("?", ba.table(m)), m, updates)
	res, err := oneRow(ba, q, m, &expr).Exec(ctx)
	if err != nil {
		return ba.err(m, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ba.err(m, err)
	}
	// bun reports what its dialect reports: changed rows on MySQL.
	return adapters.ExpectOneRow("UpdateOne", m, n, func() (int64, error) { return ba.Count(ctx, m, expr) })
}

func (ba *BunAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}
	// bun refuses an UPDATE without a WHERE; an empty expression means
	// every row.
	q := ba.set(ba.db.NewUpdate().TableExpr("?", ba.table(m)), m, updates).Where("1 = 1")
	_, err := applyWhere(ba, q, m, &expr).Exec(ctx)
	return ba.err(m, err)
}

func (ba *BunAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	res, err := ba.db.NewDelete().
		TableExpr("?", ba.table(m)).
		Where("? = ?", ba.column(m, m.PrimaryKeyName()), m.PrimaryKeyField()).
		Exec(ctx)
	if err != nil {
		return ba.err(m, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ba.err(m, err)
	}
	return adapters.ExpectOneRow("Delete", m, n, nil)
}

func (ba *BunAdapter) DeleteOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	if query, _ := ba.whereClause(m, &expr); query == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteOne, "clause", nil)
	}
	res, err := oneRow(ba, ba.db.NewDelete().TableExpr("?", ba.table(m)), m, &expr).Exec(ctx)
	if err != nil {
		return ba.err(m, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ba.err(m, err)
	}
	return adapters.ExpectOneRow("DeleteOne", m, n, nil)
}

func (ba *BunAdapter) DeleteMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	if query, _ := ba.whereClause(m, &expr); query == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteMany, "clause", nil)
	}
	_, err := applyWhere(ba, ba.db.NewDelete().TableExpr("?", ba.table(m)), m, &expr).Exec(ctx)
	return ba.err(m, err)
}

// DeleteAll deletes every row. bun refuses a DELETE without a WHERE, hence
// the explicit, dialect-agnostic "1 = 1".
func (ba *BunAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	_, err := ba.db.NewDelete().
		TableExpr("?", ba.table(m)).
		Where("1 = 1").
		Exec(ctx)
	return ba.err(m, err)
}

func (ba *BunAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	count, err := applyWhere(ba, ba.db.NewSelect().TableExpr("?", ba.table(m)), m, &expr).Count(ctx)
	return int64(count), ba.err(m, err)
}

// Transaction runs fn in a transaction: a new one on a *bun.DB, a savepoint
// when the adapter already holds a bun.Tx.
//
// The savepoint is bun's behaviour and differs from the plain SQL and MongoDB
// adapters, which join the open transaction. The results match as long as
// the caller passes fn's error on. Making this adapter join too is deferred;
// see "Nested transactions keep each library's behaviour" in
// docs/internal/database/adapters/transactions.md.
func (ba *BunAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	return ba.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := fn(ctx, NewBunAdapter(tx, ba.resolver))
		return err
	})
}

func mapBunError(op, entity string, err error) error {
	if classified, ok := adapters.MapStdSQLErrors(op, entity, err); ok {
		return classified
	}
	// bun hands back the application's driver errors untranslated.
	if kind := adapters.ConstraintKind(err); kind != adapters.SentinelUnknown {
		return adapters.Classify(op, entity, kind, err)
	}
	return behemotherr.NewDatabaseError(op, err)
}
