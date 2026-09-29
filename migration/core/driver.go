package core

import "context"

type SchemaDriver interface {
	CreateTable(ctx context.Context, t TableSchema) error
	DropTable(ctx context.Context, name string) error
	AddColumn(ctx context.Context, table string, col Column) error
	DropColumn(ctx context.Context, table, column string) error
	RenameColumn(ctx context.Context, table, oldName, newName string) error
	AlterColumn(ctx context.Context, table string, col Column) error
	AddIndex(ctx context.Context, table string, idx Index) error
	DropIndex(ctx context.Context, table, indexName string) error
	AddForeignKey(ctx context.Context, table string, fk ForeignKey) error
	DropForeignKey(ctx context.Context, table, fkName string) error

	// ApplyOperation is the one method MigrationRunner calls:
	// dispatches to the right method above by op.Kind, so the big switch
	// exists exactly once, not duplicated at every call site.
	ApplyMigration(ctx context.Context, op MigrationRequest) error

	// RecordBaseline persists LedgerEntry and SnapshotUpdate atomically —
	// exactly the same atomicity contract as ApplyMigration's ledger/snapshot
	// half — but executes NO schema-modifying statements at all. This is
	// the driver-owned-atomicity principle from last round, applied to a
	// narrower operation: a driver author implements this by literally
	// reusing ApplyMigration's own ledger+snapshot transaction code, minus
	// the DDL loop.
	RecordBaseline(ctx context.Context, req MigrationRequest) error

	// AtomicityLevel replaces the binary SupportsTransactionalDDL — a real
	// spectrum, not a yes/no, since "MySQL commits DDL implicitly" and
	// "MongoDB without a replica set has no multi-document transactions" are
	// different failure shapes a Runner/operator needs to distinguish.
	AtomicityLevel() AtomicityLevel
}

type MigrationRequest struct {
	Migration      Migration
	LedgerEntry    MigrationLedgerEntry
	SnapshotUpdate SchemaSnapshot // the FULL next snapshot state — driver persists this as part of its own atomic unit, however it stores that internally
	LedgerTable    string
	SnapshotTable  string
}

type AtomicityLevel string

const (
	// e.g. Postgres, SQLite — DDL + ledger + snapshot with all-or-nothing transaction capability
	AtomicityFull AtomicityLevel = "full"

	// e.g. MySQL — driver does its best (ledger/snapshot in a tx, DDL statements outside it) but a mid-DDL failure can leave partial schema changes
	AtomicityBestEffort AtomicityLevel = "best_effort"

	// e.g. a hypothetical KV-only backend with no cross-write guarantee at all
	AtomicityNone AtomicityLevel = "none"
)
