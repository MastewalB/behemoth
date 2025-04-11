package behemoth

import (
	"encoding/json"
	"errors"
	"time"
)

type Session interface {

	// Set inserts a key with a value in the session
	Set(key, value any) error

	// Get returns a value associated with a key in the session
	Get(key any) any

	// Delete removes a key from the session
	Delete(key any) error

	// SessionID returns the unique session ID
	SessionID() string

	// MarshalJSON serializes the session data to JSON.
	MarshalJSON() ([]byte, error)

	// UnmarshalJSON deserializes JSON data into the session.
	UnmarshalJSON(data []byte) error
}

// SessionStore defines the interface for storing and retrieving sessions.
type SessionStore interface {

	// SaveSession stores a session with its expiration time.
	SaveSession(session Session, expiresAt time.Time) error

	// GetSession retrieves a session by ID, returning an error if not found or expired.
	GetSession(sessionID string) (Session, error)

	// DeleteSession removes a session by ID.
	DeleteSession(sessionID string) error
}

// SessionFactory is a type alias for a function that creates a new Session instance with the given ID.
type SessionFactory = func(id string) Session

// DefaultSession is a basic implementation of the Session interface using an in-memory map.
type session struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Data      map[string]any
}

// NewDefaultSession creates a new DefaultSession with the given ID.
func NewDefaultSession(id string, expiry time.Duration) Session {
	return &session{
		ID:        id,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		Data:      make(map[string]any),
	}
}

// Set puts a value in session data with a string key.
func (s *session) Set(key, value any) error {
	keyStr, ok := key.(string)
	if !ok {
		return errors.New("key type not supported")
	}

	s.Data[keyStr] = value
	return nil
}

// Get retrieves a session data
func (s *session) Get(key any) any {
	keyStr, ok := key.(string)
	if !ok {
		return errors.New("key type not supported")
	}
	return s.Data[keyStr]
}

// Delete removes a data from the session
func (s *session) Delete(key any) error {
	keyStr, ok := key.(string)
	if !ok {
		return errors.New("key type not supported")
	}

	delete(s.Data, keyStr)
	return nil
}

// SessionID returns the session ID
func (s *session) SessionID() string {
	return s.ID
}

// MarshalJSON serializes the session data to JSON.
func (s *session) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(s.Data)
	return data, err
}

// UnmarshalJSON deserializes JSON data into the session.
func (s *session) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &s.Data)
}
