package behemoth

import (
	"time"

	"github.com/MastewalB/behemoth/models"
)

type Database[T User] interface {

	// FindByPK retrieves a user object from the database
	FindByPK(val any) (T, error)

	// SaveUser persists a user object to the database
	SaveUser(user *models.User) (*models.User, error)

	// SaveSession stores a session in the database with its expiration time.
	SaveSession(session Session, expiresAt time.Time) error

	// GetSession retrieves a session by ID, returning an error if not found or expired.
	GetSession(sessionID string) (Session, error)

	// DeleteSession removes a session by ID.
	DeleteSession(sessionID string) error
}
