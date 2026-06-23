package types

import (
	"context"

	"github.com/MastewalB/behemoth/clause"
)

// DatabaseName is a string type that represents the name of the database/ORM.
type DatabaseName string

const (
	SQLite   DatabaseName = "sqlite"
	Postgres DatabaseName = "postgres"
	MongoDB  DatabaseName = "mongodb"
	Gorm     DatabaseName = "gorm"
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
	UpdateField(ctx context.Context, m Model, fieldName string, value any) error
	UpdateMany(ctx context.Context, m Model, expr clause.Expression, updates map[string]any) error

	Delete(ctx context.Context, m Model) error
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

	// Delete removes a key-value pair from storage.
	//
	// Deleting a non-existent key is not considered an error.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - key: The key to delete. Must not be empty.
	//
	// Returns:
	//   - error:
	//     - ErrEmptyKey: if key is empty string
	//     - Context errors: if ctx is cancelled or times out
	//     - DatabaseError: for underlying storage errors
	//     - nil: on success OR if key doesn't exist
	//
	// Behavior guarantees:
	//   - Empty key: MUST return ErrEmptyKey immediately
	//   - Non-existent key: Returns nil (idempotent operation)
	//   - Context cancellation: SHOULD abort the operation and return ctx.Err()
	//
	// Example:
	//   // Delete a key (safe even if key doesn't exist)
	//   err := storage.Delete(ctx, "user:123")
	//   if err != nil {
	//       // Handle error (excluding ErrKeyNotFound which isn't returned)
	//   }
	Delete(ctx context.Context, key string) error
}

type Serializable interface {
	ToMap() (map[string]any, error)
	FromMap(map[string]any) error
}
