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
	Token     string
	ExpiresAt time.Time
	IpAddress string
	UserAgent string
	CreatedAt time.Time
	UpdatedAt time.Time
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

	id, ok := data["id"].(string)
	if !ok {
		id = ""
	}

	userID, ok := data["user_id"].(string)
	if !ok {
		userID = ""
	}

	expiresAt, ok := data["expires_at"].(time.Time)
	if !ok {
		expiresAt = time.Time{}
	}

	ipAddress, ok := data["ip_address"].(string)
	if !ok {
		ipAddress = ""
	}

	userAgent, ok := data["user_agent"].(string)
	if !ok {
		userAgent = ""
	}

	createdAt, ok := data["created_at"].(time.Time)
	if !ok {
		createdAt = time.Time{}
	}

	updatedAt, ok := data["updated_at"].(time.Time)
	if !ok {
		updatedAt = time.Time{}
	}

	s.ID = id
	s.UserID = userID
	s.ExpiresAt = expiresAt
	s.IpAddress = ipAddress
	s.UserAgent = userAgent
	s.CreatedAt = createdAt
	s.UpdatedAt = updatedAt
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
