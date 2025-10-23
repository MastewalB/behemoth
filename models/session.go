package models

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	// "github.com/MastewalB/behemoth/models"
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

// // Set puts a value in session data with a string key.
// func (s *Session) Set(key, value any) error {
// 	keyStr, ok := key.(string)
// 	if !ok {
// 		return errors.New("key type not supported")
// 	}

// 	s.Data[keyStr] = value
// 	return nil
// }

// // Get retrieves a session data
// func (s *Session) Get(key any) any {
// 	keyStr, ok := key.(string)
// 	if !ok {
// 		return errors.New("key type not supported")
// 	}
// 	return s.Data[keyStr]
// }

// // Delete removes a data from the session
// func (s *Session) Delete(key any) error {
// 	keyStr, ok := key.(string)
// 	if !ok {
// 		return errors.New("key type not supported")
// 	}

// 	delete(s.Data, keyStr)
// 	return nil
// }

// // SessionID returns the session ID
// func (s *Session) SessionID() string {
// 	return s.ID
// }

// // MarshalJSON serializes the session data to JSON.
// func (s *Session) MarshalJSON() ([]byte, error) {
// 	data, err := json.Marshal(s.Data)
// 	return data, err
// }

// // UnmarshalJSON deserializes JSON data into the session.
// func (s *Session) UnmarshalJSON(data []byte) error {
// 	return json.Unmarshal(data, &s.Data)
// }

type SessionStore struct {
	DB behemoth.Database
	// sessionFactory behemoth.SessionFactory
}

func (s *SessionStore) SaveSession(ctx context.Context, session behemoth.Model) error {
	return s.DB.Create(ctx, session)
}

func (s *SessionStore) GetSession(ctx context.Context, sessionModel behemoth.Session) (behemoth.Session, error) {
	// sessionModel := s.sessionFactory(sessionID)
	found, err := s.DB.Find(ctx, sessionModel, sessionModel.PrimaryKey()+" = ?", sessionModel.PrimaryValue())
	if err != nil {
		return nil, err
	}

	return found.(behemoth.Session), nil
}

func (s *SessionStore) DeleteSession(ctx context.Context, sessionModel behemoth.Session) error {
	// sessionModel := s.sessionFactory(sessionID)
	return s.DB.Delete(ctx, sessionModel)
}

// NewDefaultSession creates a new DefaultSession with the given ID.
func NewDefaultSession(ctx behemoth.SessionContext) *Session {
	return &Session{
		ID:        utils.GenerateUUID(),
		CreatedAt: time.Now(),
		// ExpiresAt: time.Now().Add(expiry),
	}
}
