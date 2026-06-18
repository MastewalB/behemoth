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

// KeyValueStorage defines the interface for key-value storage operations.
//
// Implementations must handle the following common scenarios:
//   - Empty keys: MUST return ErrEmptyKey for all operations
//   - Non-existent keys: Get operation SHOULD return ErrKeyNotFound or empty string
//   - TTL values: Negative TTLs SHOULD be treated as non-expiring (equivalent to 0 or no expiration)
//   - Zero TTL: Implementation dependent (may mean no expiration or immediate expiration)
type KeyValueStorage interface {

	// Get retrieves the value associated with the given key.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - key: The key to retrieve. Must not be empty.
	//
	// Returns:
	//   - string: The value associated with the key. Empty string if key doesn't exist
	//             and an error is returned.
	//   - error:
	//     - ErrEmptyKey: if key is empty string
	//     - ErrKeyNotFound: if the key does not exist in storage
	//     - Context errors: if ctx is cancelled or times out
	//     - DatabaseError: for underlying storage errors
	//
	// Behavior guarantees:
	//   - Empty key: MUST return ErrEmptyKey immediately
	//   - Non-existent key: SHOULD return ErrKeyNotFound or empty string with nil error
	//   - Context cancellation: SHOULD abort the operation and return ctx.Err()
	//
	// Example:
	//   value, err := storage.Get(ctx, "user:123")
	//   if errors.Is(err, ErrKeyNotFound) {
	//       // Handle missing key
	//   }
	Get(ctx context.Context, key string) (string, error)

	// Set stores a key-value pair with an optional time-to-live (TTL) expiration.
	//
	// If the key already exists, its value and TTL are overwritten.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - key: The key to store. Must not be empty.
	//   - value: The value to store. Can be empty string.
	//   - ttl: Time-to-live in seconds. Behavior by value:
	//       - ttl > 0: Key expires after ttl seconds
	//       - ttl == 0: Implementation dependent. SHOULD store without expiration
	//       - ttl < 0: SHOULD treat as non-expiring (equivalent to 0)
	//
	// Returns:
	//   - error:
	//     - ErrEmptyKey: if key is empty string
	//     - ErrInvalidTTL: if TTL value is invalid for the implementation
	//     - Context errors: if ctx is cancelled or times out
	//     - DatabaseError: for underlying storage errors
	//
	// Behavior guarantees:
	//   - Empty key: MUST return ErrEmptyKey immediately
	//   - Negative TTL: SHOULD be treated as non-expiring (no expiration)
	//   - Existing key: Overwrites both value and TTL
	//   - Context cancellation: SHOULD abort the operation and return ctx.Err()
	//
	// Example:
	//   // Store a value that expires in 1 hour
	//   err := storage.Set(ctx, "session:abc", "user-data", 3600)
	//
	//   // Store a permanent value
	//   err := storage.Set(ctx, "config:theme", "dark", 0)
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
