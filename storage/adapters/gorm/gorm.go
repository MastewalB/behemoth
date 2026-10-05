// Package gorm provides GormAdapter, a behemoth.Database backed by GORM. It
// lives in its own module, like the other database adapters, so the core module does not
// depend on gorm.io/gorm.
package gorm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage/adapters"
	"gorm.io/gorm"
)

// GormAdapter runs behemoth's operations through an application's *gorm.DB —
// its connection pool, dialect, logger, callbacks and plugins.
//
// Rows travel as maps, never as structs: what's written is the model's ToMap
// keyed by physical column, and what's read is scanned by column and handed
// to FromMap — the same path every SQL adapter takes. Behemoth's models need
// no gorm tags, contributed columns (Extensible) round-trip, and the
// SchemaResolver's physical names apply. Since GORM never sees a struct, GORM
// model hooks (BeforeCreate, ...) don't run on behemoth's models; behemoth's
// data hooks are the extension point for these writes.
type GormAdapter struct {
	db       *gorm.DB
	resolver behemoth.SchemaResolver
}

// NewGormAdapter wraps db. resolver maps canonical names to physical ones; nil
// uses them as-is.
func NewGormAdapter(db *gorm.DB, resolver behemoth.SchemaResolver) *GormAdapter {
	return &GormAdapter{db: db, resolver: adapters.ResolverOrIdentity(resolver)}
}

func (ga *GormAdapter) table(ctx context.Context, m behemoth.Model) *gorm.DB {
	return ga.db.WithContext(ctx).Table(adapters.PhysicalTable(ga.resolver, m))
}

// where applies expr, resolved to physical columns, to tx; an empty
// expression adds no condition.
func (ga *GormAdapter) where(tx *gorm.DB, m behemoth.Model, expr *clause.Expression) *gorm.DB {
	query, args := adapters.BuildSQLWhereClause(adapters.PhysicalExpression(ga.resolver, m, expr), adapters.DefaultClauseOption)
	if query == "" {
		return tx
	}
	return tx.Where(query, args...)
}

// oneRow restricts tx to a single row matching expr. expr is applied both in
// the subquery picking the row and to the row itself, so it holds for the row
// as written (the UpdateOne / DeleteOne convention). The pick is wrapped in a
// derived table because MySQL rejects a subquery on the table being updated.
func (ga *GormAdapter) oneRow(ctx context.Context, tx *gorm.DB, m behemoth.Model, expr *clause.Expression) *gorm.DB {
	pk := adapters.PhysicalColumn(ga.resolver, m, m.PrimaryKeyName())
	pick := ga.where(ga.table(ctx, m).Select(pk), m, expr).Limit(1)
	sub := ga.db.WithContext(ctx).Table("(?) AS _sub", pick).Select(pk)
	return ga.where(tx.Where(fmt.Sprintf("%s IN (?)", pk), sub), m, expr)
}

func (ga *GormAdapter) err(m behemoth.Model, err error) error {
	if err == nil {
		return nil
	}
	// The dialect's translation, which GORM applies only with
	// Config.TranslateError: constraint violations become ErrDuplicatedKey /
	// ErrForeignKeyViolated whatever the application configured.
	if t, ok := ga.db.Dialector.(gorm.ErrorTranslator); ok {
		err = t.Translate(err)
	}
	return adapters.WrapWithCaller(err, m.SchemaName(), mapGormError)
}

// row returns m's ToMap keyed by physical column.
func (ga *GormAdapter) row(m behemoth.Model) (map[string]any, error) {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}
	data, err := ser.ToMap()
	if err != nil {
		return nil, err
	}
	return adapters.PhysicalDocument(ga.resolver, m, data), nil
}

// scan reads rows of the canonical columns into new models.
func (ga *GormAdapter) scan(m behemoth.Model, rows *sql.Rows, columns []string) ([]behemoth.Model, error) {
	defer rows.Close()
	values, ptrs := adapters.ScanTargets(len(columns))
	var out []behemoth.Model
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, ga.err(m, err)
		}
		model, err := models.GenerateModelFromRows(m, columns, values)
		if err != nil {
			return nil, err
		}
		out = append(out, model)
	}
	return out, ga.err(m, rows.Err())
}

func (ga *GormAdapter) Create(ctx context.Context, m behemoth.Model) error {
	row, err := ga.row(m)
	if err != nil {
		return err
	}
	return ga.err(m, ga.table(ctx, m).Create(row).Error)
}

func (ga *GormAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {
	if _, ok := m.(behemoth.Serializable); !ok {
		return nil, behemotherr.SerializableNotImplemented()
	}
	// columns stay canonical: they key the map handed to FromMap.
	columns := adapters.ReadColumns(ga.resolver, m, nil)
	rows, err := ga.where(ga.table(ctx, m).Select(adapters.PhysicalColumns(ga.resolver, m, columns)), m, &expr).Limit(1).Rows()
	if err != nil {
		return nil, ga.err(m, err)
	}
	found, err := ga.scan(m, rows, columns)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ga.err(m, gorm.ErrRecordNotFound)
	}
	return found[0], nil
}

func (ga *GormAdapter) FindMany(
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
	columns := adapters.ReadColumns(ga.resolver, m, selected)
	physical := adapters.PhysicalColumns(ga.resolver, m, columns)

	tx := ga.table(ctx, m)
	if options != nil && options.Distinct {
		tx = tx.Distinct(physical)
	} else {
		tx = tx.Select(physical)
	}
	tx = ga.where(tx, m, &expr)
	if options != nil {
		if options.OrderBy.Field != "" {
			tx = tx.Order(fmt.Sprintf("%s %s", adapters.PhysicalColumn(ga.resolver, m, options.OrderBy.Field), options.OrderBy.Direction))
		}
		if options.Limit != 0 {
			tx = tx.Limit(options.Limit)
		}
		if options.Offset != 0 {
			tx = tx.Offset(options.Offset)
		}
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, ga.err(m, err)
	}
	return ga.scan(m, rows, columns)
}

func (ga *GormAdapter) Update(ctx context.Context, m behemoth.Model) error {
	// Not Save: in GORM v2, Save inserts the row when the update matches
	// nothing, which would silently create a missing row instead of
	// reporting it (the behemoth.Database convention).
	row, err := ga.row(m)
	if err != nil {
		return err
	}
	pk := adapters.PhysicalColumn(ga.resolver, m, m.PrimaryKeyName())
	res := ga.table(ctx, m).Where(fmt.Sprintf("%s = ?", pk), m.PrimaryKeyField()).Updates(row)
	if res.Error != nil {
		return ga.err(m, res.Error)
	}
	// GORM reports what its dialect reports: changed rows on MySQL.
	return adapters.ExpectOneRow("Update", m, res.RowsAffected, func() (int64, error) { return ga.Count(ctx, m, adapters.ByPrimaryKey(m)) })
}

func (ga *GormAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}
	res := ga.oneRow(ctx, ga.table(ctx, m), m, &expr).Updates(adapters.PhysicalDocument(ga.resolver, m, updates))
	if res.Error != nil {
		return ga.err(m, res.Error)
	}
	// GORM reports what its dialect reports: changed rows on MySQL.
	return adapters.ExpectOneRow("UpdateOne", m, res.RowsAffected, func() (int64, error) { return ga.Count(ctx, m, expr) })
}

func (ga *GormAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}
	tx := ga.table(ctx, m).Session(&gorm.Session{AllowGlobalUpdate: true})
	err := ga.where(tx, m, &expr).Updates(adapters.PhysicalDocument(ga.resolver, m, updates)).Error
	return ga.err(m, err)
}

// deleted is the value handed to Delete: GORM needs one, and a map keeps it
// from parsing a model schema — the table comes from Table.
func deleted() map[string]any { return map[string]any{} }

func (ga *GormAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	pk := adapters.PhysicalColumn(ga.resolver, m, m.PrimaryKeyName())
	res := ga.table(ctx, m).Where(fmt.Sprintf("%s = ?", pk), m.PrimaryKeyField()).Delete(deleted())
	if res.Error != nil {
		return ga.err(m, res.Error)
	}
	return adapters.ExpectOneRow("Delete", m, res.RowsAffected, nil)
}

func (ga *GormAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	if query, _ := adapters.BuildSQLWhereClause(&expr, adapters.DefaultClauseOption); query == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteOne, "clause", nil)
	}
	res := ga.oneRow(ctx, ga.table(ctx, m), m, &expr).Delete(deleted())
	if res.Error != nil {
		return ga.err(m, res.Error)
	}
	return adapters.ExpectOneRow("DeleteOne", m, res.RowsAffected, nil)
}

func (ga *GormAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	if query, _ := adapters.BuildSQLWhereClause(&expr, adapters.DefaultClauseOption); query == "" {
		return behemotherr.NewValidationError(adapters.OpDeleteMany, "clause", nil)
	}
	return ga.err(m, ga.where(ga.table(ctx, m), m, &expr).Delete(deleted()).Error)
}

func (ga *GormAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	err := ga.table(ctx, m).
		Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(deleted()).
		Error
	return ga.err(m, err)
}

func (ga *GormAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	var count int64
	err := ga.where(ga.table(ctx, m), m, &expr).Count(&count).Error
	return count, ga.err(m, err)
}

// Transaction runs fn in a transaction: a new one on a plain *gorm.DB, a
// savepoint when the adapter is already bound to one.
//
// The savepoint is GORM's behaviour and differs from the plain SQL and
// MongoDB adapters, which join the open transaction. The results match as
// long as the caller passes fn's error on. Making this adapter join too is
// deferred; see "Nested transactions keep each library's behaviour" in
// docs/internal/database/adapters/transactions.md.
func (ga *GormAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	return ga.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := fn(ctx, NewGormAdapter(tx, ga.resolver))
		return err
	})
}

func mapGormError(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return behemotherr.NewNotFound(op, entity, err)

	case errors.Is(err, gorm.ErrDuplicatedKey):
		return behemotherr.NewDuplicateKey(op, entity, err)

	case errors.Is(err, gorm.ErrForeignKeyViolated):
		return behemotherr.NewForeignKeyViolation(op, entity, err)

	case errors.Is(err, gorm.ErrInvalidTransaction):
		return behemotherr.NewTransactionError(op, err)

	case errors.Is(err, gorm.ErrInvalidData) ||
		errors.Is(err, gorm.ErrInvalidDB) ||
		errors.Is(err, gorm.ErrInvalidField) ||
		errors.Is(err, gorm.ErrInvalidValue):
		return behemotherr.NewValidationError(op, entity, err)
	}

	return behemotherr.NewDatabaseError(op, err)
}
