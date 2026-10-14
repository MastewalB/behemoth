package core

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

const (
	LedgerCanonicalName   = "behemoth_migration_ledger"
	SnapshotCanonicalName = "behemoth_schema_snapshot"

	// snapshotRowID is the primary key of the snapshot table's only row:
	// drivers upsert the full next snapshot into it on every migration.
	snapshotRowID = 1
)

// MigrationLedgerEntry is one applied migration. Rows are written by
// SchemaDriver.ApplyMigration / RecordBaseline and read back through
// behemoth.Database by MigrationRunner.
type MigrationLedgerEntry struct {
	ID        string    `db:"id"`
	AppliedAt time.Time `db:"applied_at"`
}

func (m *MigrationLedgerEntry) SchemaName() string     { return LedgerCanonicalName }
func (m *MigrationLedgerEntry) PrimaryKeyName() string { return "id" }
func (m *MigrationLedgerEntry) PrimaryKeyField() any   { return m.ID }
func (m *MigrationLedgerEntry) New() behemoth.Model    { return &MigrationLedgerEntry{} }

// ToMap implements [behemoth.Serializable]. Every column is present even on a
// zero value: adapters derive their column list from an empty model's keys.
func (m *MigrationLedgerEntry) ToMap() (map[string]any, error) {
	return map[string]any{
		"id":         m.ID,
		"applied_at": m.AppliedAt,
	}, nil
}

// FromMap implements [behemoth.Serializable]. A ledger entry without an ID,
// or with an unreadable timestamp, is an error rather than a zero value: the
// ledger is what decides which migrations run.
func (m *MigrationLedgerEntry) FromMap(data map[string]any) error {
	id, err := stringValue(data["id"])
	if err != nil || id == "" {
		return behemotherr.NewMigrationError("MigrationLedgerEntry.FromMap", behemotherr.ErrorCodeMigrationInvalidLedgerEntry, fmt.Errorf("id: %v (got %T)", err, data["id"]))
	}
	appliedAt, err := timeValue(data["applied_at"])
	if err != nil {
		return behemotherr.NewMigrationError("MigrationLedgerEntry.FromMap", behemotherr.ErrorCodeMigrationInvalidLedgerEntry, fmt.Errorf("migration %q applied_at: %w", id, err))
	}
	m.ID, m.AppliedAt = id, appliedAt
	return nil
}

// SchemaSnapshot is the canonical schema as of the last applied migration.
// The snapshot table holds exactly one row (id = snapshotRowID); Tables is
// stored as JSON (a JSON/JSONB column where the database has one).
type SchemaSnapshot struct {
	Version string                  `db:"version"` // last applied Migration ID
	Tables  map[string]schema.Table `db:"tables"`  // marshaled JSON, same idiom as Token.MetadataJSON
}

func (s *SchemaSnapshot) SchemaName() string     { return SnapshotCanonicalName }
func (s *SchemaSnapshot) PrimaryKeyName() string { return "id" }
func (s *SchemaSnapshot) PrimaryKeyField() any   { return snapshotRowID }
func (s *SchemaSnapshot) New() behemoth.Model    { return &SchemaSnapshot{} }

// ToMap implements [behemoth.Serializable]. Tables is encoded as a JSON
// string; a nil map encodes as "{}" rather than "null".
func (s *SchemaSnapshot) ToMap() (map[string]any, error) {
	tables := s.Tables
	if tables == nil {
		tables = map[string]schema.Table{}
	}
	data, err := json.Marshal(tables)
	if err != nil {
		return nil, behemotherr.NewMigrationError("SchemaSnapshot.ToMap", behemotherr.ErrorCodeMigrationMarshalFailed, err)
	}
	return map[string]any{
		"id":      snapshotRowID,
		"version": s.Version,
		"tables":  string(data),
	}, nil
}

// FromMap implements [behemoth.Serializable]. "tables" is accepted as JSON
// text (string or []byte, depending on the driver and column type) or as an
// already-decoded document (e.g. from a document store).
//
// Unreadable tables are an error, never an empty map: an empty snapshot
// means "greenfield", and the next diff would re-create every table.
func (s *SchemaSnapshot) FromMap(data map[string]any) error {
	version, err := stringValue(data["version"])
	if err != nil {
		return behemotherr.NewMigrationError("SchemaSnapshot.FromMap", behemotherr.ErrorCodeMigrationInvalidSnapshot, fmt.Errorf("version: %w", err))
	}

	var raw []byte
	switch v := data["tables"].(type) {
	case nil:
		return behemotherr.NewMigrationError("SchemaSnapshot.FromMap", behemotherr.ErrorCodeMigrationInvalidSnapshot, fmt.Errorf("tables is missing"))
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		// Already decoded (map[string]any, bson.M, ...): re-encode so the
		// schema.Table field mapping stays json's, in one place.
		if raw, err = json.Marshal(v); err != nil {
			return behemotherr.NewMigrationError("SchemaSnapshot.FromMap", behemotherr.ErrorCodeMigrationInvalidSnapshot, fmt.Errorf("tables (%T): %w", v, err))
		}
	}

	var tables map[string]schema.Table
	if err := json.Unmarshal(raw, &tables); err != nil {
		return behemotherr.NewMigrationError("SchemaSnapshot.FromMap", behemotherr.ErrorCodeMigrationInvalidSnapshot, fmt.Errorf("tables: %w", err))
	}
	if tables == nil {
		tables = map[string]schema.Table{} // stored "null"
	}
	s.Version, s.Tables = version, tables
	return nil
}

var (
	_ behemoth.Model        = (*MigrationLedgerEntry)(nil)
	_ behemoth.Serializable = (*MigrationLedgerEntry)(nil)
	_ behemoth.Model        = (*SchemaSnapshot)(nil)
	_ behemoth.Serializable = (*SchemaSnapshot)(nil)
)

// stringValue accepts the forms database/sql drivers scan text into.
func stringValue(v any) (string, error) {
	switch s := v.(type) {
	case string:
		return s, nil
	case []byte:
		return string(s), nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("expected text, got %T", v)
	}
}

// timeLayouts are the text encodings a timestamp may come back in when the
// driver doesn't decode it itself: RFC 3339, and the layouts SQLite drivers
// write (mattn/go-sqlite3 and modernc.org/sqlite).
var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
}

func timeValue(v any) (time.Time, error) {
	switch t := v.(type) {
	case time.Time:
		return t, nil
	case string, []byte:
		s, _ := stringValue(t)
		for _, layout := range timeLayouts {
			if parsed, err := time.Parse(layout, s); err == nil {
				return parsed, nil
			}
		}
		return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
	default:
		return time.Time{}, fmt.Errorf("expected a timestamp, got %T", v)
	}
}
