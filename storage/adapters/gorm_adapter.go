package adapters

import (
	"context"
	"reflect"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"gorm.io/gorm"
)

type GormAdapter struct {
	db *gorm.DB
}

func NewGormAdapter(db *gorm.DB) *GormAdapter {
	return &GormAdapter{db: db}
}

func (ga *GormAdapter) Create(ctx context.Context, m behemoth.Model) error {
	return ga.db.
		WithContext(ctx).
		Table(m.SchemaName()).
		Create(m).
		Error
}

func (ga *GormAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {
	query, args := BuildSQLWhereClause(&expr)
	err := ga.db.WithContext(ctx).Where(query, args...).First(m).Error
	return m, err
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
		return nil, err
	}

	sliceValue := slicePtr.Elem()
	entities := make([]behemoth.Model, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		entities[i] = sliceValue.Index(i).Interface().(behemoth.Model)
	}

	return entities, nil
}

func (ga *GormAdapter) Update(ctx context.Context, m behemoth.Model) error {
	return ga.db.WithContext(ctx).Save(m).Error
}

func (ga *GormAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	return ga.db.WithContext(ctx).Delete(m).Error
}
