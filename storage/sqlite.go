package storage

import (
	"database/sql"

	"github.com/MastewalB/behemoth/models"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteProvider struct {
	db *sql.DB
}

func NewSQLiteProvider(dsn string, cfg *DBConfig) (*SQLiteProvider, error) {
	db, err := sql.Open("sqlite3", dsn) // e.g., ":memory:" or "file.db"
	if err != nil {
		return nil, err
	}

	// Apply connection pool settings if provided
	if cfg != nil {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
		db.SetMaxIdleConns(cfg.MaxIdleConns)
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	// Create table if not exists
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT)")
	if err != nil {
		return nil, err
	}

	return &SQLiteProvider{db: db}, nil
}

func (s *SQLiteProvider) FindUserByEmail(email string) (models.User, error) {
	user := &models.DefaultUser{}
	err := s.db.QueryRow("SELECT id, email, password_hash FROM users WHERE email = ?", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SQLiteProvider) FindUserByID(id string) (models.User, error) {
	user := &models.DefaultUser{}
	err := s.db.QueryRow("SELECT id, email, password_hash FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SQLiteProvider) SaveUser(user models.User) error {
	// Use a transaction for atomicity
	return s.WithTransaction(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
            INSERT OR REPLACE INTO users (id, email, password_hash)
            VALUES (?, ?, ?)
        `, user.GetID(), user.GetEmail(), user.GetPasswordHash())
		return err
	})
}

func (s *SQLiteProvider) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *SQLiteProvider) SaveUsers(users []models.User) error {
	stmt, err := s.db.Prepare("INSERT OR REPLACE INTO users (id, email, password_hash) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, user := range users {
		_, err := stmt.Exec(user.GetID(), user.GetEmail(), user.GetPasswordHash())
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteProvider) Migrate() error {
	_, err := s.db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT
        )
    `)
	return err
}

func (s *SQLiteProvider) ExistsByEmail(email string) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
