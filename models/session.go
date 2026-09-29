package models

import (
	"time"

	"github.com/MastewalB/behemoth"
)

type SessionState string

const (
	SessionPending SessionState = "pending" // credentials verified, awaiting a secondary factor
	SessionActive  SessionState = "active"
	SessionRevoked SessionState = "revoked"
)

type Session struct {
	ID             string       `db:"id"`
	UserID         string       `db:"user_id"`     // stored as string regardless of behemoth.Session.UserID's `any
	LookupHash     string       `db:"lookup_hash"` // unkeyed sha256(rawToken), indexed, unique, lookup key
	TokenHash      string       `db:"token_hash"`  // keyed HMAC(rawToken)
	KeyVersion     int          `db:"key_version"` // which KeyManager version produced TokenHash; required for ByVersion after rotation
	State          SessionState `db:"state"`       // "pending" | "active" | "revoked"
	ExpiresAt      time.Time    `db:"expires_at"`
	LastActiveAt   time.Time    `db:"last_active_at"` // drives the updateAge throttle; deliberately separated from UpdatedAt
	FreshAt        time.Time    `db:"fresh_at"`       // last full credential re-check; step-up auth compares against this
	IPAddress      string       `db:"ip_address"`
	UserAgent      string       `db:"user_agent"`
	ImpersonatorID any          `db:"impersonator_id"` // nullable; set when an admin is impersonating this session's user
	RevokedAt      *time.Time   `db:"revoked_at"`      // nullable; session soft-revoked, row kept for audit
	RevokedReason  string       `db:"revoked_reason"`  // "user_logout" | "admin_revoked" | "password_changed" | etc...

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (s *Session) GetID() string {
	return s.ID
}

func (s *Session) SetExpiresAt(expiry time.Time) {
	s.ExpiresAt = expiry
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Implementations of the Model interface.
func (s *Session) SchemaName() string     { return "sessions" }
func (s *Session) PrimaryKeyName() string { return "id" }
func (s *Session) PrimaryKeyField() any   { return s.ID }
func (s *Session) New() behemoth.Model    { return &Session{} }

func (s *Session) FromMap(m map[string]any) error {
	s.ID, _ = m["id"].(string)
	s.UserID, _ = m["user_id"].(string)
	s.LookupHash, _ = m["lookup_hash"].(string)
	s.TokenHash, _ = m["token_hash"].(string)
	if kv, ok := m["key_version"].(int64); ok {
		s.KeyVersion = int(kv)
	}
	if state, ok := m["state"].(string); ok {
		s.State = SessionState(state)
	}
	s.ExpiresAt, _ = m["expires_at"].(time.Time)
	s.LastActiveAt, _ = m["last_active_at"].(time.Time)
	s.FreshAt, _ = m["fresh_at"].(time.Time)
	s.IPAddress, _ = m["ip_address"].(string)
	s.UserAgent, _ = m["user_agent"].(string)
	s.ImpersonatorID, _ = m["impersonator_id"].(string)
	if t, ok := m["revoked_at"].(time.Time); ok {
		s.RevokedAt = &t
	}
	s.RevokedReason, _ = m["revoked_reason"].(string)
	s.CreatedAt, _ = m["created_at"].(time.Time)
	s.UpdatedAt, _ = m["updated_at"].(time.Time)
	return nil
}

func (s *Session) ToMap() (map[string]any, error) {
	var revokedAt any
	if s.RevokedAt != nil {
		revokedAt = *s.RevokedAt
	}

	return map[string]any{
		"id":              s.ID,
		"user_id":         s.UserID,
		"lookup_hash":     s.LookupHash,
		"token_hash":      s.TokenHash,
		"key_version":     s.KeyVersion,
		"state":           s.State,
		"expires_at":      s.ExpiresAt,
		"last_active_at":  s.LastActiveAt,
		"fresh_at":        s.FreshAt,
		"ip_address":      s.IPAddress,
		"user_agent":      s.UserAgent,
		"impersonator_id": s.ImpersonatorID,
		"revoked_at":      revokedAt,
		"revoked_reason":  s.RevokedReason,
		"created_at":      s.CreatedAt,
		"updated_at":      s.UpdatedAt,
	}, nil
}

// type SessionStore struct {
// 	DB behemoth.Database
// }

// func (s *SessionStore) SaveSession(ctx context.Context, session behemoth.Session) error {
// 	return s.DB.Create(ctx, session)
// }

// func (s *SessionStore) GetSession(ctx context.Context, sessionModel behemoth.Session, id any) (behemoth.Session, error) {
// 	whereClause := clause.Expression{
// 		Logic: clause.OpAnd,
// 		Conditions: []clause.Condition{
// 			{Field: sessionModel.PrimaryKeyName(), Operator: clause.OpEqual, Value: id},
// 		},
// 	}
// 	found, err := s.DB.FindOne(ctx, sessionModel, whereClause)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return found.(behemoth.Session), nil
// }

// func (s *SessionStore) UpdateSession(ctx context.Context, sessionModel behemoth.Session) error {
// 	return s.DB.Update(ctx, sessionModel)
// }

// func (s *SessionStore) DeleteSession(ctx context.Context, sessionModel behemoth.Session) error {
// 	return s.DB.Delete(ctx, sessionModel)
// }

// NewDefaultSession creates a new DefaultSession.
// func NewDefaultSession(sessionContext behemoth.SessionContext) *Session {
// 	return &Session{
// 		ID:        utils.GenerateUUID(),
// 		UserID:    sessionContext.UserID.(string),
// 		IPAddress: sessionContext.IpAddress,
// 		UserAgent: sessionContext.UserAgent,
// 		CreatedAt: time.Now(),
// 	}
// }

const SessionTableSchema = `
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	ip_address TEXT,
	user_agent TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);
`
