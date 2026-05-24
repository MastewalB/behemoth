package adapters

import (
	"context"
	"errors"
	"reflect"

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
	return withErrorHandling(func() error {
		return ga.db.
			WithContext(ctx).
			Table(m.SchemaName()).
			Create(m).
			Error
	},
		"Create",
		m.SchemaName())
}

func (ga *GormAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {
	query, args := BuildSQLWhereClause(&expr)
	err := ga.db.WithContext(ctx).Where(query, args...).First(m).Error
	if err != nil {
		return nil, mapGormError("FindOne", m.SchemaName(), err)
	}
	return m, nil
}

func (ga *GormAdapter) FindMany(ctx context.Context, m behemoth.Model, expr clause.Expression) ([]behemoth.Model, error) {
	query, args := BuildSQLWhereClause(&expr)

	modelType := reflect.TypeOf(m)
	sliceType := reflect.SliceOf(modelType)
	slicePtr := reflect.New(sliceType)

	err := ga.db.
		WithContext(ctx).
		Table(m.SchemaName()).
		Where(query, args...).
		Find(slicePtr.Interface()).Error

	if err != nil {
		return nil, mapGormError("FindMany", m.SchemaName(), err)
	}

	sliceValue := slicePtr.Elem()
	entities := make([]behemoth.Model, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		entities[i] = sliceValue.Index(i).Interface().(behemoth.Model)
	}

	return entities, nil
}

func (ga *GormAdapter) Update(ctx context.Context, m behemoth.Model) error {
	return withErrorHandling(func() error { return ga.db.WithContext(ctx).Save(m).Error }, "Update", m.SchemaName())
}

func (ga *GormAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	// return ga.db.WithContext(ctx).Delete(m).Error
	return withErrorHandling(func() error { return ga.db.WithContext(ctx).Delete(m).Error }, "Delete", m.SchemaName())
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

	return behemotherr.NewInternal(op, err)
}

func withErrorHandling(fn func() error, op, entity string) error {
	if err := fn(); err != nil {
		return mapGormError(op, entity, err)
	}
	return nil
}
