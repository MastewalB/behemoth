package main

import (
	"database/sql"

	"github.com/MastewalB/behemoth/models"
)

type CustomUser struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	Username     string
	Firstname    string
	Lastname     string
}

func (u *CustomUser) GetID() string           { return u.ID }
func (u *CustomUser) GetPasswordHash() string { return u.PasswordHash }
func (u *CustomUser) GetEmail() string        { return u.Email }
func (u *CustomUser) GetUsername() string     { return u.Username }
func (u *CustomUser) GetFirstname() string    { return u.Firstname }
func (u *CustomUser) GetLastname() string     { return u.Lastname }

// CustomPostgresProvider
type CustomPostgresProvider struct {
	db *sql.DB
}

func NewCustomPostgresProvider(dsn string) (*CustomPostgresProvider, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &CustomPostgresProvider{db: db}, nil
}

func (p *CustomPostgresProvider) FindUserByEmail(email string) (models.User, error) {
	user := &CustomUser{}
	err := p.db.QueryRow("SELECT id, email, password_hash, role FROM custom_users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *CustomPostgresProvider) FindUserByID(id string) (models.User, error) {
	user := &models.DefaultUser{}
	err := p.db.QueryRow("SELECT id, email, password_hash FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (p *CustomPostgresProvider) SaveUser(user models.User) error {
	return nil // Not used in this example
}

func (s *CustomPostgresProvider) WithTransaction(fn func(tx *sql.Tx) error) error {
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
