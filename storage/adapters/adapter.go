package adapters

import (
	"context"
	"database/sql"
)

// Querier is implemented by both *sql.DB and *sql.Tx
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const (
	OpCreate     = "Create"
	OpFindOne    = "FindOne"
	OpFindMany   = "FindMany"
	OpUpdate     = "Update"
	OpUpdateOne  = "UpdateOne"
	OpUpdateMany = "UpdateMany"
	OpDelete     = "Delete"
	OpDeleteOne  = "DeleteOne"
	OpDeleteMany = "DeleteMany"
	OpDeleteAll  = "DeleteAll"

	OpCount       = "Count"
	OpTransaction = "Transaction"

	OpGet = "Get"
	OpSet = "Set"
)
