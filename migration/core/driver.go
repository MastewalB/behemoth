package core

import (
	"context"

	"github.com/MastewalB/behemoth/types/schema"
)

type SchemaDriver interface {

	// ApplyOperation is the one method MigrationRunner calls
	// The driver implementation will map the each SchemaOperation in the Migration
	// to their respective op in the target database.
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

// MigrationRenderer is an optional driver capability: rendering a Migration
// as a script in the target database's native language, written next to the
// migration's .json file. Drivers that can't express migrations as a script
// simply don't implement it; callers discover it via type assertion, e.g.
//
//	renderer, _ := driver.(core.MigrationRenderer)
type MigrationRenderer interface {
	// RenderMigration returns the statements that applying m's Up would
	// execute. It must be called against the database state m will be applied
	// to (i.e. before Apply): some drivers — SQLite's table rebuilds — derive
	// the statements from the live schema. A baseline migration renders the
	// existing schema it records, since its Up is never executed.
	RenderMigration(ctx context.Context, m Migration) (string, error)

	// FileExtension is the rendered script's extension, including the dot:
	// ".sql" for SQL databases, ".js" for a MongoDB shell script, ...
	FileExtension() string
}

// ColumnNormalizer is an optional SchemaIntrospector capability: describing
// how the driver's DDL changes a declared column. Some canonical distinctions
// have no counterpart in the database — Postgres stores blob and bytes both as
// BYTEA, a string without a length is created as VARCHAR(255) — so a column
// read back from the database can't equal its declaration. Comparing the
// normalized declaration instead lets an unchanged column match. Callers
// discover it via type assertion, e.g.
//
//	normalizer, _ := introspector.(core.ColumnNormalizer)
type ColumnNormalizer interface {
	// NormalizeColumn returns col as Introspect would report it after the
	// driver created it in table (canonical name): the same lossy mapping the
	// DDL performs, applied in advance. It only affects whether a column
	// counts as changed; operations are always built from the declaration.
	NormalizeColumn(table string, col schema.Column) schema.Column
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
