package core

import (
	"sync"
	"time"

	"github.com/MastewalB/behemoth/types/schema"
)

type Config struct {
	DB                    any
	Conn                  any
	MigrationDatabaseName string
	DatabaseName          string
	SchemaName            string
	StatementDuration     time.Duration
}

// NewMigrationConfig fills defaults for any zero-valued field — this is the
// "populated at init" step. FolderPath defaults to the current working
// directory rather than a nested subfolder, since a fresh project shouldn't
// need to create structure just to run its first generate.
func NewMigrationConfig(cfg MigrationConfig) MigrationConfig {
	if cfg.FolderPath == "" {
		cfg.FolderPath = "."
	}
	if cfg.TableName == "" {
		cfg.TableName = "behemoth_auth_schema"
	}
	if cfg.Path == "" {
		// PathGenerateOnly is the default option
		// behemoth won't touch a developer's database unless PathManaged is explicitly chosen.
		cfg.Path = PathGenerateOnly
	}
	return cfg
}

// SchemaResolverTable is the canonical -> physical name mapping a
// DefaultSchemaResolver serves after Freeze.
type SchemaResolverTable struct {
	Tables  map[string]string            // canonical table -> physical table
	Columns map[string]map[string]string // canonical table -> canonical column -> physical column
	// ColumnOrder lists each table's canonical columns in declaration order
	// (contributions after the base columns, as schema.Registry merges them).
	ColumnOrder map[string][]string
}

type DefaultSchemaResolver struct {
	mu     sync.RWMutex
	table  SchemaResolverTable
	frozen bool
}

func NewSchemaResolver() *DefaultSchemaResolver {
	return &DefaultSchemaResolver{} // empty — Resolve/ResolveColumn degrade to identity until Freeze runs
}

func (r *DefaultSchemaResolver) Resolve(canonical string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if phys, ok := r.table.Tables[canonical]; ok {
		return phys
	}
	return canonical // exactly today's behavior — a developer who never configures anything sees zero change
}

// ResolveColumn implements [SchemaResolver]. Columns are keyed by their
// CANONICAL table name, so renaming a table's physical name never changes
// how its columns resolve. Unknown tables/columns resolve to themselves.
func (r *DefaultSchemaResolver) ResolveColumn(canonicalTable string, canonicalColumn string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if phys, ok := r.table.Columns[canonicalTable][canonicalColumn]; ok {
		return phys
	}
	return canonicalColumn
}

// Columns implements [SchemaResolver]: the table's declared columns,
// contributions included, or nil for a table that isn't declared.
func (r *DefaultSchemaResolver) Columns(canonicalTable string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cols := r.table.ColumnOrder[canonicalTable]
	if cols == nil {
		return nil
	}
	return append([]string(nil), cols...)
}

// Freeze is called exactly once, by Boot, after schema.Registry.Freeze()
// has run — same "construct empty, populate in place, every early holder
// of the reference sees the populated state automatically" pattern as
// Dispatcher.Freeze.
func (r *DefaultSchemaResolver) Freeze(table SchemaResolverTable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.table, r.frozen = table, true
}

// BuildSchemaResolverTable runs INSIDE Boot, after schema.Registry.Freeze() —
// derived from already-declared tables, never independently authored. This
// is what makes "default to SchemaName() if unset" automatic: a schema.Table
// with no PhysicalName override simply maps to itself; the same holds for
// every Column, including ones contributed via ExtendColumn.
func BuildSchemaResolverTable(registry schema.Registry, cfg MigrationConfig) SchemaResolverTable {
	table := SchemaResolverTable{
		Tables:      map[string]string{},
		Columns:     map[string]map[string]string{},
		ColumnOrder: map[string][]string{},
	}
	for _, t := range registry.All() {
		table.Tables[t.Name] = orDefault(t.PhysicalName, t.Name)

		cols := make(map[string]string, len(t.Columns))
		order := make([]string, 0, len(t.Columns))
		for _, c := range t.Columns {
			cols[c.Name] = orDefault(c.PhysicalName, c.Name)
			order = append(order, c.Name)
		}
		table.Columns[t.Name] = cols
		table.ColumnOrder[t.Name] = order
	}
	// Ledger/snapshot aren't plugin-declared tables at all — they're
	// framework-internal bookkeeping, sourced from MigrationConfig instead.
	table.Tables[LedgerCanonicalName] = cfg.TableName
	table.Tables[SnapshotCanonicalName] = cfg.snapshotTableName()
	return table
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

var _ SchemaResolver = (*DefaultSchemaResolver)(nil)
