package models

import (
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/schema"
)

// Canonical names of the reserved_values table and its columns.
const (
	ReservedValueTable = "reserved_values"

	ReservedValueID        = "id"
	ReservedValueColumn    = "column_name"
	ReservedValueValue     = "column_value"
	ReservedValueUserID    = "user_id"
	ReservedValueExpiresAt = "expires_at"
	ReservedValueCreatedAt = "created_at"
)

var reservedValueColumns = columnSet(ReservedValueID, ReservedValueColumn, ReservedValueValue,
	ReservedValueUserID, ReservedValueExpiresAt, ReservedValueCreatedAt)

// ReservedValue keeps a value of a unique column of users for the user who
// gave it up, until ExpiresAt: an email address a user changed away from and
// can still take back, for example. Until then no other user is given the
// value. There is at most one row per Column and Value.
type ReservedValue struct {
	ID string
	// Column is the canonical name of the users column, such as "email".
	Column string
	// Value is the value in the form the column stores it.
	Value     string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (r *ReservedValue) SchemaName() string     { return ReservedValueTable }
func (r *ReservedValue) PrimaryKeyName() string { return ReservedValueID }
func (r *ReservedValue) PrimaryKeyField() any   { return r.ID }
func (r *ReservedValue) New() behemoth.Model    { return &ReservedValue{} }

func (r *ReservedValue) ToMap() (map[string]any, error) {
	return map[string]any{
		ReservedValueID:        r.ID,
		ReservedValueColumn:    r.Column,
		ReservedValueValue:     r.Value,
		ReservedValueUserID:    r.UserID,
		ReservedValueExpiresAt: r.ExpiresAt,
		ReservedValueCreatedAt: r.CreatedAt,
	}, nil
}

func (r *ReservedValue) FromMap(m map[string]any) error {
	r.ID, _ = m[ReservedValueID].(string)
	r.Column, _ = m[ReservedValueColumn].(string)
	r.Value = text(m[ReservedValueValue])
	r.UserID, _ = m[ReservedValueUserID].(string)
	r.ExpiresAt, _ = m[ReservedValueExpiresAt].(time.Time)
	r.CreatedAt, _ = m[ReservedValueCreatedAt].(time.Time)
	return nil
}

// ReservedValueTableSchema declares reserved_values. The unique index keeps
// one reservation per column and value, and is what a reservation is found
// by. Like sessions and accounts, a reservation goes with its user.
func ReservedValueTableSchema() schema.Table {
	return schema.Table{
		Name: ReservedValueTable,
		Columns: []schema.Column{
			{Name: ReservedValueID, Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: ReservedValueColumn, Type: schema.ColTypeString, Length: 64},
			{Name: ReservedValueValue, Type: schema.ColTypeString, Length: 255},
			{Name: ReservedValueUserID, Type: schema.ColTypeString, Length: 36},
			{Name: ReservedValueExpiresAt, Type: schema.ColTypeTimestamp},
			{Name: ReservedValueCreatedAt, Type: schema.ColTypeTimestamp},
		},
		Indexes: []schema.Index{
			{Name: "uq_reserved_values_column_value", Columns: []string{ReservedValueColumn, ReservedValueValue}, Unique: true},
			{Name: "idx_reserved_values_user_id", Columns: []string{ReservedValueUserID}},
			{Name: "idx_reserved_values_expires_at", Columns: []string{ReservedValueExpiresAt}},
		},
		ForeignKeys: []schema.ForeignKey{{
			Name: "fk_reserved_values_user", Columns: []string{ReservedValueUserID},
			RefTable: UserTable, RefColumns: []string{UserID}, OnDelete: schema.FKCascade,
		}},
	}
}
