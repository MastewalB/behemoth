package adapters

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"gorm.io/gorm"
)

type GormAdapter struct {
	db *gorm.DB
}

func NewGormAdapter(db *gorm.DB) *GormAdapter {
	return &GormAdapter{db: db}
}

func (ga *GormAdapter) Create(ctx context.Context, m behemoth.Model) error {
	err := ga.db.WithContext(ctx).Table(m.SchemaName()).Create(m).Error
	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {
	query, args := BuildSQLWhereClause(&expr)
	newModel := m.New()
	err := ga.db.
		WithContext(ctx).
		Table(m.SchemaName()).
		Where(query, args...).
		First(newModel).
		Error
	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapGormError)
	}
	return newModel, nil
}

func (ga *GormAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	options *behemoth.QueryOptions,
) ([]behemoth.Model, error) {
	query, args := BuildSQLWhereClause(&expr)

	modelType := reflect.TypeOf(m)
	sliceType := reflect.SliceOf(modelType)
	slicePtr := reflect.New(sliceType)

	db := ga.db.
		WithContext(ctx).
		Table(m.SchemaName()).
		Where(query, args...)

	if options != nil {
		if len(options.Select) > 0 {
			db = db.Select(options.Select)
		}
		if options.Distinct {
			db = db.Distinct()
		}
		if options.OrderBy.Field != "" {
			db = db.Order(fmt.Sprintf("%s %s", options.OrderBy.Field, options.OrderBy.Direction))
		}
		if options.Limit != 0 {
			db = db.Limit(options.Limit)
		}
		if options.Offset != 0 {
			db = db.Offset(options.Offset)
		}
	}

	err := db.Find(slicePtr.Interface()).Error

	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapGormError)
	}

	sliceValue := slicePtr.Elem()
	entities := make([]behemoth.Model, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		entities[i] = sliceValue.Index(i).Interface().(behemoth.Model)
	}

	return entities, nil
}

func (ga *GormAdapter) Update(ctx context.Context, m behemoth.Model) error {
	err := ga.db.WithContext(ctx).Save(m).Error
	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func replaceParams(s string) string {
	return regexp.MustCompile(`\$\d+`).ReplaceAllString(s, "?")
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

	query, args := BuildSQLWhereClause(&expr)
	query = replaceParams(query)

	fmt.Println(query, args, updates)
	op := ga.db.Debug().
		WithContext(ctx).
		Table(m.SchemaName()).
		Where(
			fmt.Sprintf("%s = (?)", m.PrimaryKeyName()),
			ga.db.
				Table(m.SchemaName()).
				Select(m.PrimaryKeyName()).
				Where(query, args...).
				Find(m.New()).
				Limit(1),
		).
		Updates(map[string]any(updates))

	err := op.Error

	fmt.Println(op.RowsAffected)
	return WrapWithCaller(err, m.SchemaName(), mapGormError)
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

	query, args := BuildSQLWhereClause(&expr)
	err := ga.db.
		WithContext(ctx).
		Model(m.New()).
		Where(query, args...).
		Updates(map[string]any(updates)).
		Error
	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	err := ga.db.WithContext(ctx).Delete(m).Error
	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	whereClause, args := BuildSQLWhereClause(&expr)

	if whereClause == "" {
		return &behemotherr.DomainError{
			Type:    behemotherr.Database,
			Op:      "DeleteMany",
			Entity:  m.SchemaName(),
			Message: "DeleteMany requires a where clause.",
		}
	}
	err := ga.db.
		WithContext(ctx).
		Where(whereClause, args...).
		Delete(m.New()).
		Error

	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	err := ga.db.
		WithContext(ctx).
		Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(m.New()).
		Error

	return WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) Count(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
) (int64, error) {
	query, args := BuildSQLWhereClause(&expr)
	var count int64

	err := ga.db.
		WithContext(ctx).
		Table(m.SchemaName()).
		Where(query, args...).
		Count(&count).
		Error

	return count, WrapWithCaller(err, m.SchemaName(), mapGormError)
}

func (ga *GormAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {

	return ga.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txAdapter := NewGormAdapter(tx)
		_, err := fn(ctx, txAdapter)
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
