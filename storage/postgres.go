package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/utils"
	_ "github.com/lib/pq"
)

type Postgres[T behemoth.User] struct {
	DB             *sql.DB
	Table          string
	PK             string
	sessionFactory behemoth.SessionFactory
}

func NewPostgres[T behemoth.User](
	db *sql.DB,
	userTable, primaryKey string,
	factory behemoth.SessionFactory,
) (*Postgres[T], error) {

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
            data JSONB NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    `)
	if err != nil {
		return nil, err
	}

	return &Postgres[T]{
		DB:             db,
		Table:          userTable,
		PK:             primaryKey,
		sessionFactory: factory,
	}, nil
}

func (pg *Postgres[T]) FindByPK(val any) (T, error) {
	var entity T

	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s = $1`, pg.Table, pg.PK)
	row := pg.DB.QueryRow(query, val)

	columns, err := getPGColumnNames(pg.DB, pg.Table)
	if err != nil {
		return entity, err
	}

	entity, err = mapRowToStruct(row, entity, columns)
	return entity, err
}

func (p *Postgres[T]) SaveUser(user *models.User) (*models.User, error) {
	uuidStr := utils.GenerateUUID()
	user.ID = uuidStr

	err := p.WithTransaction(func(tx *sql.Tx) error {
		var emailExists, usernameExists bool

		err := tx.QueryRow(`
		SELECT 
                EXISTS(SELECT 1 FROM users WHERE email = $1),
                EXISTS(SELECT 1 FROM users WHERE username = $2)
		`, user.Email, user.Username).Scan(&emailExists, &usernameExists)

		if err != nil {
			return err
		}

		if !emailExists && !usernameExists {

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

func (p *Postgres[T]) GetAllUsers() ([]T, error) {
	var users []T

	rows, err := p.DB.Query(fmt.Sprintf("SELECT * FROM %s", p.Table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := getPGColumnNames(p.DB, p.Table)
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

func (p *Postgres[T]) UpdateUser(user *models.User) (*models.User, error) {
	err := p.WithTransaction(func(tx *sql.Tx) error {
		var emailExists, usernameExists bool

		err := tx.QueryRow(`
		SELECT 
                EXISTS(SELECT 1 FROM users WHERE email = $1),
                EXISTS(SELECT 1 FROM users WHERE username = $2)
		`, user.Email, user.Username).Scan(&emailExists, &usernameExists)

		if err != nil {
			return err
		}

		if emailExists || usernameExists {
			_, err = tx.Exec(`
			UPDATE users
			SET email = $1, username = $2, firstname = $3, lastname = $4, password_hash = $5
			WHERE id = $6
			RETURNING *
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

func (p *Postgres[T]) DeleteUser(user *models.User) error {
	err := p.WithTransaction(func(tx *sql.Tx) error {
		exists, err := p.UserExists(user)
		if err != nil {
			return err
		}

		if exists {
			_, err = tx.Exec(`
			DELETE FROM users WHERE id = $1
			`, user.GetID())
		}

		return err
	})

	return err
}


// SaveSession stores a session in the database with its expiration time.
func (p *Postgres[T]) SaveSession(session behemoth.Session, expiresAt time.Time) error {
	// Serialize the session data (we'll use a wrapper to capture the data)
	data, err := serializeSession(session)
	if err != nil {
		return err
	}

	_, err = p.DB.Exec(`
		INSERT INTO sessions (id, data, expires_at) 
		VALUES ($1, $2, $3)
		ON CONFLICT (id) 
		DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
	`, session.SessionID(), data, expiresAt)

	return err
}

// GetSession retrieves a session by ID, returning an error if not found or expired.
func (p *Postgres[T]) GetSession(sessionID string) (behemoth.Session, error) {
	var data []byte
	var expiresAt time.Time

	err := p.DB.QueryRow(`
		SELECT data, expires_at FROM sessions WHERE id = $1
	`, sessionID).Scan(&data, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(expiresAt) {
		// Delete expired session
		p.DeleteSession(sessionID)
		return nil, errors.New("session expired")
	}

	// Deserialize the session
	return deserializeSession(sessionID, data, p.sessionFactory)

}

// DeleteSession removes a session by ID.
func (p *Postgres[T]) DeleteSession(sessionID string) error {
	_, err := p.DB.Exec("DELETE FROM sessions WHERE id = $1", sessionID)
	return err
}

func (p *Postgres[T]) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := p.DB.Begin()
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

func (p *Postgres[T]) UserExists(user *models.User) (bool, error) {
	var exists bool
	err := p.DB.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 OR username = $2)
	`, user.Email, user.Username).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}