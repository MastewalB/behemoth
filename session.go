package behemoth

import (
	"net/http"
	"time"
)

type Session interface {
	Model
	GetID() string
	SetExpiresAt(expiry time.Time)
	IsExpired() bool
}

// SessionStore defines the interface for storing and retrieving sessions.
// type SessionStore interface {

// 	// SaveSession stores a session with its expiration time.
// 	SaveSession(session Session, expiresAt time.Time) error

// 	// GetSession retrieves a session by ID, returning an error if not found or expired.
// 	GetSession(sessionID string) (Session, error)

// 	// DeleteSession removes a session by ID.
// 	DeleteSession(sessionID string) error
// }

// SessionFactory is a type alias for a function that creates a new Session instance with the given ID.
type SessionFactory = func(ctx SessionContext) Session

// DefaultSession is a basic implementation of the Session interface using an in-memory map.
// type session struct {
// 	ID        string
// 	CreatedAt time.Time
// 	ExpiresAt time.Time
// 	Data      map[string]any
// }

type SessionContext struct {
	UserID  any
	Request *http.Request
	Meta    map[string]any
}
