package behemoth

import (
	"database/sql"
	"time"

	"github.com/MastewalB/behemoth/models"
)

// Database is an interface that defines the methods for interacting with a database.
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
type FindUserFn func(db, val any) (User, error)

// DatabaseName is a string type that represents the name of the database.
type DatabaseName string

const (
	SQLite   DatabaseName = "sqlite"
	Postgres DatabaseName = "postgres"
)

// FindUserByEmailPG is a function that retrieves a user by email from a PostgreSQL database.
// It will be automatically passed to the database if the default user model is used.
func FindUserByEmailPG(dbConn, val any) (User, error) {
	db := dbConn.(*sql.DB)
	email := val.(string)
	var user *models.User = &models.User{}

	err := db.QueryRow(`SELECT * FROM users WHERE email = $1`,
		email).Scan(&user.ID, &user.Email, &user.Username, &user.Firstname, &user.Lastname, &user.PasswordHash)

	return user, err
}

// FindUserByEmailSQLite is a function that retrieves a user by email from a SQLite database.
// It will be automatically passed to the database if the default user model is used.
func FindUserByEmailSQLite(dbConn, val any) (User, error) {
	db := dbConn.(*sql.DB)
	email := val.(string)
	var user *models.User = &models.User{}

	err := db.QueryRow(`SELECT * FROM users WHERE email = ?`,
		email).Scan(&user.ID, &user.Email, &user.Username, &user.Firstname, &user.Lastname, &user.PasswordHash)

	return user, err
}
