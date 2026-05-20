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
	FindMany(ctx context.Context, model Model, expr clause.Expression) ([]Model, error)

	Update(ctx context.Context, m Model) error
	Delete(ctx context.Context, m Model) error

	// DeleteMany(ctx context.Context, model Model, expr clause.Expression) error
}

type Serializable interface {
	ToMap() (map[string]any, error)
	FromMap(map[string]any) error
}
