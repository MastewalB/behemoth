package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
)

type CustomUser struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
}

func (u *CustomUser) GetID() string           { return u.ID }
func (u *CustomUser) GetPasswordHash() string { return u.PasswordHash }
func (u *CustomUser) GetEmail() string        { return u.Email }

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

func main() {
	// DefaultUser with Register
	pg, _ := storage.NewPostgresProvider("postgres://user:pass@localhost/db", nil)
	defaultCfg := &config.Config{
		Password: config.PasswordConfig{
			DB:             pg,
			UseDefaultUser: true, // Explicitly opt into DefaultUser
		},
		JWT: config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	defaultB := auth.New(defaultCfg)

	// CustomUser without Register
	customPg, _ := NewCustomPostgresProvider("postgres://user:pass@localhost/db")
	customCfg := &config.Config{
		Password: config.PasswordConfig{
			DB:             customPg,
			UseDefaultUser: false, // Explicitly opt into custom model
		},
		JWT: config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	customB := auth.New(customCfg)

	// Prepopulate a custom user (developer responsibility)
	hash, _ := utils.GeneratePasswordHash("password123")
	customPg.db.Exec("INSERT INTO custom_users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
		"1", "test@example.com", hash, "admin")

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		user, err := defaultB.Password.Register(auth.PasswordCredentials{
			Email:    "newuser@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("Registered: " + user.GetID()))
	})

	http.HandleFunc("/login-default", func(w http.ResponseWriter, r *http.Request) {
		user, err := defaultB.Password.Authenticate(auth.PasswordCredentials{
			Email:    "newuser@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := defaultB.JWT.GenerateToken(user)
		w.Write([]byte("Default Token: " + token))
	})

	http.HandleFunc("/login-custom", func(w http.ResponseWriter, r *http.Request) {
		user, err := customB.Password.Authenticate(auth.PasswordCredentials{
			Email:    "test@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := customB.JWT.GenerateToken(user)
		w.Write([]byte("Custom Token: " + token))
	})

	// Try Register with custom model (will fail)
	http.HandleFunc("/register-custom", func(w http.ResponseWriter, r *http.Request) {
		_, err := customB.Password.Register(auth.PasswordCredentials{
			Email:    "fail@example.com",
			Password: "password123",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest) // "registration not supported"
			return
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
