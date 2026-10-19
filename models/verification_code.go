package models

import (
	"encoding/json"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/schema"
)

// Canonical names of the verification_codes table and its columns.
const (
	VerificationCodeTable = "verification_codes"

	VerificationCodeID           = "id"
	VerificationCodeKindColumn   = "kind"
	VerificationCodeSubject      = "subject"
	VerificationCodeHash         = "code_hash"
	VerificationCodeKeyVersion   = "key_version"
	VerificationCodeAttemptsLeft = "attempts_left"
	VerificationCodeMetadata     = "metadata"
	VerificationCodeExpiresAt    = "expires_at"
	VerificationCodeCreatedAt    = "created_at"
)

// CodeKind says what a one-time code is for, such as "phonenumber.sign_in".
type CodeKind string

// VerificationCode is one live one-time code: a short numeric secret sent to
// a person, of which only a keyed hash is stored. Unlike a Token it is found
// by Kind and Subject, not by its own hash, and it carries the number of
// attempts it still allows. There is at most one row per Kind and Subject.
type VerificationCode struct {
	ID   string
	Kind CodeKind
	// Subject is who the code is for: a user id for the codes plugins issue
	// today, which is what lets Store.DeleteUser remove a user's codes.
	Subject      string
	CodeHash     string
	KeyVersion   int
	AttemptsLeft int
	Metadata     behemoth.M
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

func (c *VerificationCode) SchemaName() string     { return VerificationCodeTable }
func (c *VerificationCode) PrimaryKeyName() string { return VerificationCodeID }
func (c *VerificationCode) PrimaryKeyField() any   { return c.ID }
func (c *VerificationCode) New() behemoth.Model    { return &VerificationCode{} }

// ToMap writes the metadata as a JSON string, the form every adapter stores
// a json column from, and NULL when there is none.
func (c *VerificationCode) ToMap() (map[string]any, error) {
	var metadata any
	if len(c.Metadata) > 0 {
		encoded, err := json.Marshal(c.Metadata)
		if err != nil {
			return nil, err
		}
		metadata = string(encoded)
	}
	return map[string]any{
		VerificationCodeID:           c.ID,
		VerificationCodeKindColumn:   string(c.Kind),
		VerificationCodeSubject:      c.Subject,
		VerificationCodeHash:         c.CodeHash,
		VerificationCodeKeyVersion:   c.KeyVersion,
		VerificationCodeAttemptsLeft: c.AttemptsLeft,
		VerificationCodeMetadata:     metadata,
		VerificationCodeExpiresAt:    c.ExpiresAt,
		VerificationCodeCreatedAt:    c.CreatedAt,
	}, nil
}

func (c *VerificationCode) FromMap(m map[string]any) error {
	c.ID, _ = m[VerificationCodeID].(string)
	kind, _ := m[VerificationCodeKindColumn].(string)
	c.Kind = CodeKind(kind)
	c.Subject, _ = m[VerificationCodeSubject].(string)
	c.CodeHash = text(m[VerificationCodeHash])
	c.KeyVersion = intOf(m[VerificationCodeKeyVersion])
	c.AttemptsLeft = intOf(m[VerificationCodeAttemptsLeft])
	c.ExpiresAt, _ = m[VerificationCodeExpiresAt].(time.Time)
	c.CreatedAt, _ = m[VerificationCodeCreatedAt].(time.Time)

	c.Metadata = nil
	switch raw := m[VerificationCodeMetadata].(type) {
	case behemoth.M: // an in-memory row
		c.Metadata = raw
	case map[string]any: // a driver that decodes json columns
		c.Metadata = raw
	case string:
		if raw != "" {
			return json.Unmarshal([]byte(raw), &c.Metadata)
		}
	case []byte:
		if len(raw) > 0 {
			return json.Unmarshal(raw, &c.Metadata)
		}
	}
	return nil
}

// intOf reads an integer column in whichever width the driver returned.
func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64: // after a JSON round trip
		return int(n)
	}
	return 0
}

// VerificationCodeTableSchema declares verification_codes. The unique index
// is what keeps one live code per kind and subject, and what a code is found
// by.
func VerificationCodeTableSchema() schema.Table {
	return schema.Table{
		Name: VerificationCodeTable,
		Columns: []schema.Column{
			{Name: VerificationCodeID, Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
			{Name: VerificationCodeKindColumn, Type: schema.ColTypeString, Length: 64},
			{Name: VerificationCodeSubject, Type: schema.ColTypeString, Length: 255},
			{Name: VerificationCodeHash, Type: schema.ColTypeText},
			{Name: VerificationCodeKeyVersion, Type: schema.ColTypeInteger},
			{Name: VerificationCodeAttemptsLeft, Type: schema.ColTypeInteger},
			{Name: VerificationCodeMetadata, Type: schema.ColTypeJson, Nullable: true},
			{Name: VerificationCodeExpiresAt, Type: schema.ColTypeTimestamp},
			{Name: VerificationCodeCreatedAt, Type: schema.ColTypeTimestamp},
		},
		Indexes: []schema.Index{
			{Name: "uq_verification_codes_kind_subject", Columns: []string{VerificationCodeKindColumn, VerificationCodeSubject}, Unique: true},
			{Name: "idx_verification_codes_expires_at", Columns: []string{VerificationCodeExpiresAt}},
		},
	}
}
