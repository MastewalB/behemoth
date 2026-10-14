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

	// Update writes every field of m to the row with m's primary key.
	// [Convention] NotFound when there is no such row — it never inserts.
	Update(ctx context.Context, m Model) error

	// UpdateOne applies updates to one row matching expr — the first, if
	// several match.
	//
	// [Convention] It returns a NotFound error (behemotherr.IsNotFound) when
	// no row matches, and expr is checked against the row as it is when
	// written, not only when it was selected: an implementation re-checks
	// expr in the write itself, so after waiting on a concurrent writer the
	// update applies only if expr still holds. A guarded write ("set
	// consumed_at where it is still NULL") is therefore atomic: of several
	// concurrent calls, one succeeds and the others get NotFound. A row that
	// matches but already holds the new values counts as matched. An empty
	// updates map is a no-op and returns nil.
	UpdateOne(ctx context.Context, m Model, expr clause.Expression, updates M) error
	// UpdateMany applies updates to every row matching expr. Matching no
	// row is not an error: the *Many and *All operations act on a set, and
	// an empty set is a valid one.
	UpdateMany(ctx context.Context, m Model, expr clause.Expression, updates M) error

	// Delete removes the row with m's primary key.
	// [Convention] NotFound when there is no such row.
	Delete(ctx context.Context, m Model) error
	// DeleteOne removes one row matching expr — the first, if several match.
	// [Convention] NotFound when no row matches, with expr checked against
	// the row as it is deleted, exactly like UpdateOne.
	DeleteOne(ctx context.Context, m Model, expr clause.Expression) error
	// DeleteMany and DeleteAll remove every matching row; matching none is
	// not an error.
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

// TransactionChecker is an optional interface of a Database whose
// transactions depend on how the database is deployed. Boot calls
// CheckTransactions once, before anything is written, and fails when it
// returns an error. The store runs every write to a table that fires data
// hooks in a transaction, so a deployment without them can't run those
// writes at all.
//
// The MongoDB adapter implements it: MongoDB has transactions only on a
// replica set or a sharded cluster. The SQL adapters don't need to; their
// databases always have transactions.
type TransactionChecker interface {
	// CheckTransactions returns nil when Transaction can be used on this
	// deployment, and an error that says what is missing otherwise.
	CheckTransactions(ctx context.Context) error
}

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

// SchemaResolver maps canonical names — a Model's SchemaName() and the keys
// of its ToMap() — to the physical names used in the database. Every storage
// adapter and migration driver resolves names through it, so a table or
// column can be renamed physically without touching model code.
type SchemaResolver interface {
	Resolve(canonicalName string) string // returns the physical name; canonicalName itself if nothing overrides it
	ResolveColumn(canonicalTable, canonicalColumn string) string

	// Columns lists canonicalTable's declared columns — canonical names, in
	// declaration order, columns other declarers contributed (ExtendColumn)
	// included — or nil when the table isn't declared. Adapters read
	// these columns, so a contributed column reaches the model; for a table
	// it doesn't know, they fall back to the model's own ToMap keys.
	Columns(canonicalTable string) []string
}

// Extensible is a model that carries columns beyond its own fields: values
// of columns contributed to its table by another declarer (a plugin's
// ExtendColumn on users, say). Its ToMap includes them and its FromMap
// keeps every column it doesn't know as one. schema.Field gives typed
// access to a single extra column.
type Extensible interface {
	Model
	// Extras returns the contributed columns' values, keyed by canonical
	// column name. It may be nil.
	Extras() M
	// SetExtra sets one contributed column's value.
	SetExtra(column string, value any)
}

// IdentityResolver maps every name to itself: the resolver to use when no
// physical names are configured.
type IdentityResolver struct{}

func (IdentityResolver) Resolve(canonical string) string                 { return canonical }
func (IdentityResolver) ResolveColumn(_ string, canonical string) string { return canonical }
func (IdentityResolver) Columns(string) []string                         { return nil }

type Serializable interface {
	ToMap() (map[string]any, error)
	FromMap(map[string]any) error
}
