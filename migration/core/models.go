package core

import (
	"time"

	"github.com/MastewalB/behemoth"
)

const (
	LedgerCanonicalName   = "behemoth_migration_ledger"
	SnapshotCanonicalName = "behemoth_schema_snapshot"
)

type MigrationLedgerEntry struct {
	ID        string    `db:"id"`
	AppliedAt time.Time `db:"applied_at"`
}

// New implements [behemoth.Model].
func (m *MigrationLedgerEntry) New() behemoth.Model {
	panic("unimplemented")
}

// PrimaryKeyField implements [behemoth.Model].
func (m *MigrationLedgerEntry) PrimaryKeyField() any {
	panic("unimplemented")
}

// PrimaryKeyName implements [behemoth.Model].
func (m *MigrationLedgerEntry) PrimaryKeyName() string {
	panic("unimplemented")
}

// SchemaName implements [behemoth.Model].
func (m *MigrationLedgerEntry) SchemaName() string {
	return LedgerCanonicalName
}

type SchemaSnapshot struct {
	Version string                 `db:"version"` // last applied Migration ID
	Tables  map[string]TableSchema `db:"tables"`  // marshaled JSON, same idiom as Token.MetadataJSON
}

// New implements [behemoth.Model].
func (s *SchemaSnapshot) New() behemoth.Model {
	panic("unimplemented")
}

// PrimaryKeyField implements [behemoth.Model].
func (s *SchemaSnapshot) PrimaryKeyField() any {
	panic("unimplemented")
}

// PrimaryKeyName implements [behemoth.Model].
func (s *SchemaSnapshot) PrimaryKeyName() string {
	panic("unimplemented")
}

// SchemaName implements [behemoth.Model].
func (s *SchemaSnapshot) SchemaName() string {
	return SnapshotCanonicalName
}

var _ behemoth.Model = (*MigrationLedgerEntry)(nil)
var _ behemoth.Model = (*SchemaSnapshot)(nil)
