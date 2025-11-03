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

// SessionFactory is a type alias for a function that creates a new Session instance with the given ID.
type SessionFactory = func(ctx SessionContext) Session

type SessionContext struct {
	UserID    any
	IpAddress string
	UserAgent string
	Request   *http.Request
}
