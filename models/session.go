package models

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/utils"
)

type Session struct {
	ID        string
	UserID    any
	ExpiresAt time.Time
	IpAddress string
	UserAgent string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Session) TableName() string {
	return "sessions"
}

func (s *Session) PrimaryKey() string {
	return "id"
}

func (s *Session) Fields() []string {
	return []string{"id", "user_id", "expires_at", "ip_address", "user_agent", "created_at", "updated_at"}
}

func (s *Session) PrimaryValue() any {
	return s.ID
}

func (s *Session) ScanDestinations() []any {
	return []any{&s.ID, &s.UserID, &s.ExpiresAt, &s.IpAddress, &s.UserAgent, &s.CreatedAt, &s.UpdatedAt}
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

func (s *Session) New() behemoth.Model {
	return &Session{}
}

func (s *Session) PrimaryKeyName() string {
	return "id"
}

func (s *Session) PrimaryKeyField() any {
	return s.ID
}

func (s *Session) SchemaName() string {
	return "sessions"
}

func (s *Session) FromMap(data map[string]any) error {
	var err error
	if id, ok := data["id"].(string); ok {
		s.ID = id
	} else {
		return utils.NewTypeAssertionError("id", "string")
	}

	if userID, ok := data["user_id"]; ok {
		s.UserID = userID
	} else {
		return utils.NewTypeAssertionError("user_id", "any")
	}
	
	if expiresAtStr, ok := data["expires_at"].(string); ok {
		s.ExpiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return utils.NewTypeAssertionError("expires_at", "time.Time")
		}
	} else {
		return utils.NewTypeAssertionError("expires_at", "string")
	}

	if ipAddress, ok := data["ip_address"].(string); ok {
		s.IpAddress = ipAddress
	} else {
		return utils.NewTypeAssertionError("ip_address", "string")
	}

	if userAgent, ok := data["user_agent"].(string); ok {
		s.UserAgent = userAgent
	} else {
		return utils.NewTypeAssertionError("user_agent", "string")
	}

	if createdAtStr, ok := data["created_at"].(string); ok {
		s.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return utils.NewTypeAssertionError("created_at", "time.Time")
		}
	} else {
		return utils.NewTypeAssertionError("created_at", "string")
	}

	if updatedAtStr, ok := data["updated_at"].(string); ok {
		s.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
		if err != nil {
			return utils.NewTypeAssertionError("updated_at", "time.Time")
		}
	} else {
		return utils.NewTypeAssertionError("updated_at", "string")
	}

	return nil
}

func (s *Session) ToMap() (map[string]any, error) {
	return map[string]any{
		"id":         s.ID,
		"user_id":    s.UserID,
		"expires_at": s.ExpiresAt,
		"ip_address": s.IpAddress,
		"user_agent": s.UserAgent,
		"created_at": s.CreatedAt,
		"updated_at": s.UpdatedAt,
	}, nil
}

type SessionStore struct {
	DB behemoth.Database
}

// func (s *SessionStore) CreateSessionTable(ctx context.Context) error {
// 	return s.DB.CreateTable(ctx, SessionTableSchema)
// }

func (s *SessionStore) SaveSession(ctx context.Context, session behemoth.Session) error {
	return s.DB.Create(ctx, session)
}

func (s *SessionStore) GetSession(ctx context.Context, sessionModel behemoth.Session, id any) (behemoth.Session, error) {
	whereClause := clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: sessionModel.PrimaryKeyName(), Operator: clause.OpEqual, Value: id},
		},
	}
	found, err := s.DB.FindOne(ctx, sessionModel, whereClause)
	if err != nil {
		return nil, err
	}

	return found.(behemoth.Session), nil
}

func (s *SessionStore) UpdateSession(ctx context.Context, sessionModel behemoth.Session) error {
	return s.DB.Update(ctx, sessionModel)
}

func (s *SessionStore) DeleteSession(ctx context.Context, sessionModel behemoth.Session) error {
	return s.DB.Delete(ctx, sessionModel)
}

// NewDefaultSession creates a new DefaultSession.
func NewDefaultSession(sessionContext behemoth.SessionContext) *Session {
	return &Session{
		ID:        utils.GenerateUUID(),
		UserID:    sessionContext.UserID,
		IpAddress: sessionContext.IpAddress,
		UserAgent: sessionContext.UserAgent,
		CreatedAt: time.Now(),
	}
}

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
