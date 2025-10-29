package behemoth

import (
	"context"
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
	Find(ctx context.Context, m Model, where string, args ...any) (Model, error)
	Update(ctx context.Context, m Model) error
	Delete(ctx context.Context, m Model) error
}

// DatabaseName is a string type that represents the name of the database.
type DatabaseName string

const (
	SQLite   DatabaseName = "sqlite"
	Postgres DatabaseName = "postgres"
)
