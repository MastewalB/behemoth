package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
)

// Canonical names of the audit_log table and its columns. The event's type
// is stored as event_type: adapters emit column names unquoted, and TYPE is
// a keyword in several databases.
const (
	AuditLogTable = "audit_log"

	AuditLogID          = "id"
	AuditLogEventType   = "event_type"
	AuditLogOutcome     = "outcome"
	AuditLogActorType   = "actor_type"
	AuditLogActorID     = "actor_id"
	AuditLogSubjectType = "subject_type"
	AuditLogSubjectID   = "subject_id"
	AuditLogSessionID   = "session_id"
	AuditLogRequestID   = "request_id"
	AuditLogIPAddress   = "ip_address"
	AuditLogUserAgent   = "user_agent"
	AuditLogMetadata    = "metadata"
	AuditLogCreatedAt   = "created_at"
)

var auditLogColumns = columnSet(AuditLogID, AuditLogEventType, AuditLogOutcome, AuditLogActorType, AuditLogActorID,
	AuditLogSubjectType, AuditLogSubjectID, AuditLogSessionID, AuditLogRequestID, AuditLogIPAddress,
	AuditLogUserAgent, AuditLogMetadata, AuditLogCreatedAt)

// AuditLog is one row of the audit log: a telemetry.AuditEvent as stored.
// The store converts between the two (Store.RecordAuditEvent,
// Store.QueryAuditEvents); nothing else writes the table. Rows are inserted
// and never updated.
//
// ID is a UUIDv7, so ids sort in the order events were recorded. The store
// pages through the table on that order.
//
// The table has no foreign key to users: an event outlives the user it is
// about.
type AuditLog struct {
	ID          string
	EventType   string
	Outcome     string
	ActorType   string
	ActorID     string // "" is stored as NULL, like every optional column below
	SubjectType string
	SubjectID   string
	SessionID   string
	RequestID   string
	IPAddress   string
	UserAgent   string
	Metadata    behemoth.M
	CreatedAt   time.Time
}

func (a *AuditLog) SchemaName() string     { return AuditLogTable }
func (a *AuditLog) PrimaryKeyName() string { return AuditLogID }
func (a *AuditLog) PrimaryKeyField() any   { return a.ID }
func (a *AuditLog) New() behemoth.Model    { return &AuditLog{} }

// ToMap stores metadata as JSON text, like Token, and empty optional values
// as NULL so that "no actor" is one value in the column.
func (a *AuditLog) ToMap() (map[string]any, error) {
	var metadata any
	if len(a.Metadata) > 0 {
		b, err := json.Marshal(a.Metadata)
		if err != nil {
			return nil, fmt.Errorf("audit metadata: %w", err)
		}
		metadata = string(b)
	}
	return map[string]any{
		AuditLogID:          a.ID,
		AuditLogEventType:   a.EventType,
		AuditLogOutcome:     a.Outcome,
		AuditLogActorType:   a.ActorType,
		AuditLogActorID:     nullable(a.ActorID),
		AuditLogSubjectType: nullable(a.SubjectType),
		AuditLogSubjectID:   nullable(a.SubjectID),
		AuditLogSessionID:   nullable(a.SessionID),
		AuditLogRequestID:   nullable(a.RequestID),
		AuditLogIPAddress:   nullable(a.IPAddress),
		AuditLogUserAgent:   nullable(a.UserAgent),
		AuditLogMetadata:    metadata,
		AuditLogCreatedAt:   a.CreatedAt,
	}, nil
}

func (a *AuditLog) FromMap(m map[string]any) error {
	a.ID = text(m[AuditLogID])
	a.EventType = text(m[AuditLogEventType])
	a.Outcome = text(m[AuditLogOutcome])
	a.ActorType = text(m[AuditLogActorType])
	a.ActorID = text(m[AuditLogActorID])
	a.SubjectType = text(m[AuditLogSubjectType])
	a.SubjectID = text(m[AuditLogSubjectID])
	a.SessionID = text(m[AuditLogSessionID])
	a.RequestID = text(m[AuditLogRequestID])
	a.IPAddress = text(m[AuditLogIPAddress])
	a.UserAgent = text(m[AuditLogUserAgent])

	a.Metadata = nil
	switch v := m[AuditLogMetadata].(type) {
	case behemoth.M:
		a.Metadata = v
	case map[string]any:
		a.Metadata = v
	case string:
		if v != "" {
			if err := json.Unmarshal([]byte(v), &a.Metadata); err != nil {
				return fmt.Errorf("audit metadata: %w", err)
			}
		}
	case []byte:
		if len(v) > 0 {
			if err := json.Unmarshal(v, &a.Metadata); err != nil {
				return fmt.Errorf("audit metadata: %w", err)
			}
		}
	}
	a.CreatedAt, _ = m[AuditLogCreatedAt].(time.Time)
	return nil
}

// nullable maps "" to nil, which adapters write as NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// text reads a string column that drivers return as string or []byte.
func text(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	}
	return ""
}
