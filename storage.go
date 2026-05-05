package behemoth

import (
	"context"

	"github.com/MastewalB/behemoth/clause"
)

type Model interface {
	TableName() string
	PrimaryKey() string
	Fields() []string
	PrimaryValue() any
	ScanDestinations() []any
}

type Database interface {
	Create(ctx context.Context, m Model) error
	Find(ctx context.Context, m Model, whereExpression clause.Expression) (Model, error)
	FindMany(ctx context.Context, m Model, whereExpression clause.Expression) ([]Model, error)
	Update(ctx context.Context, m Model) error
	Delete(ctx context.Context, m Model) error

	CreateTable(ctx context.Context, schema string) error
}

// DatabaseName is a string type that represents the name of the database.
type DatabaseName string

const (
	SQLite   DatabaseName = "sqlite"
	Postgres DatabaseName = "postgres"
)
