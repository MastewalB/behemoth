package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
	_ "github.com/mattn/go-sqlite3"
)

type SQLite[T behemoth.User] struct {
	db             *sql.DB
	userTable          string
	primaryKey             string
	sessionFactory behemoth.SessionFactory
	findUserFn behemoth.FindUserFn
}

func NewSQLite[T behemoth.User](
	db *sql.DB,
	userTable, primaryKey string,
	sessionFactory behemoth.SessionFactory,
	findUserFn behemoth.FindUserFn,
) (*SQLite[T], error) {
	if userTable == "" {
		_, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS users (
				id TEXT PRIMARY KEY,
				email TEXT UNIQUE,
				username TEXT UNIQUE,
				firstname TEXT,
				lastname TEXT,
				password_hash TEXT
			)
		`)

		if err != nil {
			return nil, err
		}
	}

	// Create sessions table
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            data JSON NOT NULL,
            expires_at DATETIME NOT NULL
        )
    `)
	if err != nil {
		return nil, err
	}

	return &SQLite[T]{
		db:             db,
		userTable:          userTable,
		primaryKey:             primaryKey,
		sessionFactory: sessionFactory,
	}, nil

}

func (sqlt *SQLite[T]) FindByPK(val any) (T, error) {

	// Check if a custom findUser function is provided and call it if available
	if sqlt.findUserFn != nil {
		var zero T
		user, err := sqlt.findUserFn(sqlt.db, val)
		if err != nil {
			return zero, err
		}

		return user.(T), nil 
	}

	// If no custom findUser function is provided, use the default implementation
	var entity T

	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s = ?`, sqlt.userTable, sqlt.primaryKey)
	row := sqlt.db.QueryRow(query, val)

	columns, err := getSQLiteColumnNames(sqlt.db, sqlt.userTable)
	if err != nil {
		return entity, err
	}

	entity, err = mapRowToStruct(row, entity, columns)
	return entity, err
}

func (sqlt *SQLite[T]) SaveUser(user *models.User) (*models.User, error) {
	uuidStr := utils.GenerateUUID()
	user.ID = uuidStr
	err := sqlt.WithTransaction(func(tx *sql.Tx) error {

		var emailCount, usernameCount int
		err := tx.QueryRow(`
			SELECT
				EXISTS(SELECT 1 FROM users WHERE email = ?),
                EXISTS(SELECT 1 FROM users WHERE username = ?)`,
			user.Email, user.Username).Scan(&emailCount, &usernameCount)

		if err != nil {
			return err
		}

		if emailCount == 0 && usernameCount == 0 {
			_, err = tx.Exec(`
            INSERT INTO users 
                (id, email, username, firstname, lastname, password_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
        `,
				user.GetID(),
				user.GetEmail(),
				user.GetUsername(),
				user.GetFirstname(),
				user.GetLastname(),
				user.GetPasswordHash(),
			)
		}
		return err
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (sqlt *SQLite[T]) UpdateUser(user *models.User) (*models.User, error) {
	err := sqlt.WithTransaction(func(tx *sql.Tx) error {
		var emailExists, usernameExists bool

		err := tx.QueryRow(`
			SELECT 
				EXISTS(SELECT 1 FROM users WHERE email = ?),
				EXISTS(SELECT 1 FROM users WHERE username = ?)
		`, user.Email, user.Username).Scan(&emailExists, &usernameExists)

		if err != nil {
			return err
		}

		if emailExists || usernameExists {
			_, err = tx.Exec(`
				UPDATE users
				SET email = ?, username = ?, firstname = ?, lastname = ?, password_hash = ?
				WHERE id = ?
			`,
				user.GetEmail(),
				user.GetUsername(),
				user.GetFirstname(),
				user.GetLastname(),
				user.GetPasswordHash(),
				user.GetID(),
			)
		}

		return err
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (sqlt *SQLite[T]) DeleteUser(user *models.User) error {
	err := sqlt.WithTransaction(func(tx *sql.Tx) error {
		exists, err := sqlt.UserExists(user)
		if err != nil {
			return err
		}

		_, err = tx.Exec(`
			DELETE FROM sessions WHERE id = ?`,
		)

		if exists {
			_, err = tx.Exec(`
				DELETE FROM users WHERE id = ?
			`, user.GetID())
		}

		return err
	})

	return err
}

func (sqlt *SQLite[T]) GetAllUsers() ([]T, error) {
	var users []T

	rows, err := sqlt.db.Query(fmt.Sprintf("SELECT * FROM %s", sqlt.userTable))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := getSQLiteColumnNames(sqlt.db, sqlt.userTable)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var user T
		user, err = mapRowToStruct(rows, user, columns)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// SaveSession stores a session in the database with its expiration time.
func (sqlt *SQLite[T]) SaveSession(session behemoth.Session, expiresAt time.Time) error {
	// Serialize the session data (we'll use a wrapper to capture the data)
	data, err := serializeSession(session)

	if err != nil {
		return err
	}

	_, err = sqlt.db.Exec(
		"INSERT OR REPLACE INTO sessions (id, data, expires_at) VALUES (?, ?, ?)",
		session.SessionID(), data, expiresAt,
	)
	return err
}

// GetSession retrieves a session by ID, returning an error if not found or expired.
func (sqlt *SQLite[T]) GetSession(sessionID string) (behemoth.Session, error) {
	var data []byte
	var expiresAt time.Time

	err := sqlt.db.QueryRow(
		"SELECT data, expires_at FROM sessions WHERE id = ?",
		sessionID,
	).Scan(&data, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiresAt) {
		sqlt.DeleteSession(sessionID)
		return nil, errors.New("session expired")
	}

	return deserializeSession(sessionID, data, sqlt.sessionFactory)
}

// DeleteSession removes a session by ID.
func (sqlt *SQLite[T]) DeleteSession(sessionID string) error {
	_, err := sqlt.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	return err
}

func (sqlt *SQLite[T]) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := sqlt.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // re-throw panic after rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx failed: %v, rollback failed: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (sqlt *SQLite[T]) UserExists(user *models.User) (bool, error) {
	var exists bool
	err := sqlt.db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM users WHERE email = ? OR username = ?)
	`, user.Email, user.Username).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}
