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

	// UpdateUser updates a user object in the database. User should be instance of models.User.
	UpdateUser(user *models.User) (*models.User, error)

	// DeleteUser removes a user object from the database. User should be instance of models.User.
	DeleteUser(user *models.User) error

	// GetAllUsers retrieves all users from the database.
	GetAllUsers() ([]T, error)

	// SaveSession stores a session in the database with its expiration time.
	SaveSession(session Session, expiresAt time.Time) error

	// GetSession retrieves a session by ID, returning an error if not found or expired.
	GetSession(sessionID string) (Session, error)

	// DeleteSession removes a session by ID.
	DeleteSession(sessionID string) error
}

// FindUser is a customized function type that takes a value of any type and returns a User type
// The database interface will use this function if provided, instead of retrieving the user by type reflection.
type FindUserFn[T User] func(val any) (T, error)