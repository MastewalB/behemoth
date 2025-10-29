package models

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
)

type Session struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Session) TableName() string {
	return "sessions"
}

func (s *Session) PrimaryKey() string {
	return "id"
}

func (s *Session) Fields() []string {
	return []string{"id", "created_at", "expires_at"}
}

func (s *Session) PrimaryValue() any {
	return s.ID
}

func (s *Session) ScanDestinations() []any {
	return []any{&s.ID, &s.CreatedAt, &s.ExpiresAt}
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

type SessionStore struct {
	DB behemoth.Database
}

func (s *SessionStore) SaveSession(ctx context.Context, session behemoth.Model) error {
	return s.DB.Create(ctx, session)
}

func (s *SessionStore) GetSession(ctx context.Context, sessionModel behemoth.Session) (behemoth.Session, error) {
	found, err := s.DB.Find(ctx, sessionModel, sessionModel.PrimaryKey()+" = ?", sessionModel.PrimaryValue())
	if err != nil {
		return nil, err
	}

	return found.(behemoth.Session), nil
}

func (s *SessionStore) DeleteSession(ctx context.Context, sessionModel behemoth.Session) error {
	return s.DB.Delete(ctx, sessionModel)
}

// NewDefaultSession creates a new DefaultSession with the given ID.
func NewDefaultSession(ctx behemoth.SessionContext) *Session {
	return &Session{
		ID:        utils.GenerateUUID(),
		CreatedAt: time.Now(),
	}
}
