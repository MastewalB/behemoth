package behemoth

import (
	"context"

	"github.com/MastewalB/behemoth/clause"
)

// DatabaseName is a string type that represents the name of the database.
type DatabaseName string

const (
	SQLite   DatabaseName = "sqlite"
	Postgres DatabaseName = "postgres"
)

type M map[string]any

type Model interface {
	SchemaName() string
	PrimaryKeyName() string
	PrimaryKeyField() any

	New() Model
}

type Database interface {
	Create(ctx context.Context, m Model) error

	FindOne(ctx context.Context, model Model, expr clause.Expression) (Model, error)
	FindMany(ctx context.Context, model Model, expr clause.Expression, options *QueryOptions) ([]Model, error)

	Update(ctx context.Context, m Model) error
	UpdateOne(ctx context.Context, m Model, expr clause.Expression, updates M) error
	UpdateMany(ctx context.Context, m Model, expr clause.Expression, updates M) error

	Delete(ctx context.Context, m Model) error
	DeleteOne(ctx context.Context, m Model, expr clause.Expression) error
	DeleteMany(ctx context.Context, m Model, expr clause.Expression) error
	DeleteAll(ctx context.Context, m Model) error

	Count(ctx context.Context, m Model, expr clause.Expression) (int64, error)

	Transaction(ctx context.Context, fn TransactionFunc) error
}

type TransactionFunc func(ctx context.Context, tx Database) (any, error)

type QueryOptions struct {
	Limit    int
	Offset   int
	OrderBy  Order
	Select   []string
	Distinct bool
}

type Order struct {
	Field     string
	Direction OrderDirection
}

type OrderDirection string

const (
	Asc  OrderDirection = "ASC"
	Desc OrderDirection = "DESC"
)

type KeyValueStorage interface {
	Get(ctx context.Context, key string) (string, error)

	Set(
		ctx context.Context,
		key string,
		value string,
		ttl int,
	) error

	Delete(ctx context.Context, key string) error
}

type Serializable interface {
	ToMap() (map[string]any, error)
	FromMap(map[string]any) error
}
