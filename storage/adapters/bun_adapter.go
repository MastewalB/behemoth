package adapters

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/uptrace/bun"
)

// BunAdapter implements behemoth.Database using the Bun ORM.
type BunAdapter struct {
	db bun.IDB
}

func NewBunAdapter(db bun.IDB) *BunAdapter {
	return &BunAdapter{db: db}
}

func (ba *BunAdapter) Create(ctx context.Context, m behemoth.Model) error {
	_, err := ba.db.NewInsert().
		// TableExpr(m.SchemaName()).
		Model(m).
		Exec(ctx)
	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) FindOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (behemoth.Model, error) {
	whereClause, args := BuildMySQLWhereClause(&expr)
	dest := m.New()
 
	err := ba.db.NewSelect().
		// TableExpr(m.SchemaName()).
		Model(dest).
		Where(whereClause, args...).
		Limit(1).
		Scan(ctx)

	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapBunError)
	}

	return dest, nil
}

func (ba *BunAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	options *behemoth.QueryOptions,
) ([]behemoth.Model, error) {
	whereClause, args := BuildMySQLWhereClause(&expr)

	// Build *[]ConcreteType via reflection so Bun can scan into it.
	modelType := reflect.TypeOf(m)
	sliceType := reflect.SliceOf(modelType)
	slicePtr := reflect.New(sliceType)

	q := ba.db.NewSelect().
		Model(slicePtr.Interface())

	if whereClause != "" {
		q = q.Where(whereClause, args...)
	}

	if options != nil {
		if len(options.Select) > 0 {
			q = q.ColumnExpr(columnsToExpr(options.Select))
		}
		if options.Distinct {
			q = q.Distinct()
		}
		if options.OrderBy.Field != "" {
			q = q.OrderExpr("? ?",
				bun.Ident(options.OrderBy.Field),
				bun.Safe(string(options.OrderBy.Direction)),
			)
		}
		if options.Limit != 0 {
			q = q.Limit(options.Limit)
		}
		if options.Offset != 0 {
			q = q.Offset(options.Offset)
		}
	}

	if err := q.Scan(ctx); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapBunError)
	}

	sliceValue := slicePtr.Elem()
	entities := make([]behemoth.Model, sliceValue.Len())
	for i := 0; i < sliceValue.Len(); i++ {
		entities[i] = sliceValue.Index(i).Interface().(behemoth.Model)
	}

	return entities, nil
}

func (ba *BunAdapter) Update(ctx context.Context, m behemoth.Model) error {
	_, err := ba.db.NewUpdate().
		TableExpr(m.SchemaName()).
		Model(m).
		WherePK().
		Exec(ctx)
	return WrapWithCaller(err, m.SchemaName(), mapBunError)
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

	whereClause, args := BuildMySQLWhereClause(&expr)

	subQuery := ba.db.NewSelect().
		TableExpr(m.SchemaName()).
		ColumnExpr(m.PrimaryKeyName()).
		Where(whereClause, args...).
		Limit(1)

	q := ApplyMapUpdates(
		ba.db.NewUpdate().
			TableExpr(m.SchemaName()).
			Where("? = (?)", bun.Ident(m.PrimaryKeyName()), subQuery),
		updates,
	)
	_, err := q.Exec(ctx)

	return WrapWithCaller(err, m.SchemaName(), mapBunError)
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

	whereClause, args := BuildMySQLWhereClause(&expr)

	q := ApplyMapUpdates(
		ba.db.NewUpdate().
			TableExpr(m.SchemaName()).
			Where(whereClause, args...),
		updates,
	)
	_, err := q.Exec(ctx)

	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	_, err := ba.db.NewDelete().
		TableExpr(m.SchemaName()).
		Where("? = ?", bun.Ident(m.PrimaryKeyName()), m.PrimaryKeyField()).
		Exec(ctx)
	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) DeleteOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := BuildMySQLWhereClause(&expr)
	if whereClause == "" {
		return &behemotherr.DomainError{
			Type:    behemotherr.Database,
			Op:      "DeleteOne",
			Entity:  m.SchemaName(),
			Message: "DeleteOne requires a where clause.",
		}
	}

	subQuery := ba.db.NewSelect().
		TableExpr(m.SchemaName()).
		ColumnExpr(m.PrimaryKeyName()).
		Where(whereClause, args...).
		Limit(1)

	_, err := ba.db.NewDelete().
		TableExpr(m.SchemaName()).
		Where("? = (?)", bun.Ident(m.PrimaryKeyName()), subQuery).
		Exec(ctx)

	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) DeleteMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) error {
	whereClause, args := BuildMySQLWhereClause(&expr)
	if whereClause == "" {
		return &behemotherr.DomainError{
			Type:    behemotherr.Database,
			Op:      "DeleteMany",
			Entity:  m.SchemaName(),
			Message: "DeleteMany requires a where clause.",
		}
	}

	_, err := ba.db.NewDelete().
		TableExpr(m.SchemaName()).
		Where(whereClause, args...).
		Exec(ctx)

	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

// DeleteAll
//
// Bun doesn't issue a DELETE without a WHERE clause unless you
// explicitly opt in with WhereAllWithDeletes() / Where("1=1").
// We use Where("1=1") to be explicit and dialect-agnostic.
func (ba *BunAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	_, err := ba.db.NewDelete().
		TableExpr(m.SchemaName()).
		Where("1 = 1").
		Exec(ctx)
	return WrapWithCaller(err, m.SchemaName(), mapBunError)
}

func (ba *BunAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	whereClause, args := BuildMySQLWhereClause(&expr)

	q := ba.db.NewSelect().
		TableExpr(m.SchemaName())

	if whereClause != "" {
		q = q.Where(whereClause, args...)
	}

	count, err := q.Count(ctx)
	return int64(count), WrapWithCaller(err, m.SchemaName(), mapBunError)
}

// Transaction
//
// bun.IDB is implemented by both *bun.DB and bun.Tx, so we can construct
// a new BunAdapter from the bun.Tx and pass it into the TransactionFunc,
// matching the pattern used by GormAdapter.
func (ba *BunAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	// db.RunInTx is only available on *bun.DB, not the bun.IDB interface.
	// We perform a type assertion here; callers should not call Transaction
	// on an adapter that is already inside a transaction (i.e. holds a bun.Tx).
	rootDB, ok := ba.db.(*bun.DB)
	if !ok {
		return behemotherr.NewTransactionError(
			"Transaction",
			errors.New("Transaction cannot be called on an adapter that is already inside a transaction"),
		)
	}

	return rootDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		txAdapter := NewBunAdapter(tx)
		_, err := fn(ctx, txAdapter)
		return err
	})
}

func mapBunError(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return behemotherr.NewNotFound(op, entity, err)
	}

	return behemotherr.NewDatabaseError(op, err)

}

func ApplyMapUpdates(q *bun.UpdateQuery, updates map[string]any) *bun.UpdateQuery {
	for col, val := range updates {
		q = q.Set("? = ?", bun.Ident(col), val)
	}
	return q
}

// columnsToExpr joins a slice of column names into a comma-separated
// string for Bun's ColumnExpr, e.g. ["id", "name"] → "id, name".
func columnsToExpr(cols []string) string {
	return strings.Join(cols, ", ")
}
