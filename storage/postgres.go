package storage

import (
	"database/sql"

	"github.com/MastewalB/behemoth/models"
	_ "github.com/lib/pq"
)

type PostgresProvider struct {
	db *sql.DB
}

func NewPostgresProvider(dsn string, cfg *DBConfig) (*PostgresProvider, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Apply connection pool settings if provided
	if cfg != nil {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
		db.SetMaxIdleConns(cfg.MaxIdleConns)
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	// Ensure table exists
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT
        )
    `)
	if err != nil {
		return nil, err
	}

	return &PostgresProvider{db: db}, nil
}

func (p *PostgresProvider) FindUserByEmail(email string) (models.User, error) {
	user := &models.DefaultUser{}
	err := p.db.QueryRow("SELECT id, email, password_hash FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *PostgresProvider) FindUserByID(id string) (models.User, error) {
	user := &models.DefaultUser{}
	err := p.db.QueryRow("SELECT id, email, password_hash FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *PostgresProvider) SaveUser(user *models.DefaultUser) error {
	return p.WithTransaction(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
		INSERT INTO users (id, email, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET email = $2, password_hash = $3
	`, user.GetID(), user.GetEmail(), user.GetUsername(), user.GetFirstname(), user.GetLastname(), user.GetPasswordHash())
		return err
	})
}

func (p *PostgresProvider) Update(user models.DefaultUser) error {
	return nil
}

func (p *PostgresProvider) Delete(user models.DefaultUser) error {
	return nil
}

func (p *PostgresProvider) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}
