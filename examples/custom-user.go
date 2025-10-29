package main

import (
	"database/sql"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/middleware"
	"github.com/go-chi/chi/v5"
)

type CustomUser struct {
	ID           string `db:"id"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
	Role         string `db:"role"`
	Username     string `db:"username"`
	Firstname    string `db:"firstname"`
	Lastname     string `db:"lastname"`
}

func (u *CustomUser) GetID() string           { return u.ID }
func (u *CustomUser) GetPasswordHash() string { return u.PasswordHash }
func (u *CustomUser) GetEmail() string        { return u.Email }
func (u *CustomUser) GetUsername() string     { return u.Username }

func (u *CustomUser) TableName() string {
	return "custom_users"
}

func (u *CustomUser) Fields() []string {
	return []string{"id", "email", "username", "firstname", "lastname", "role", "password_hash"}
}

func (u *CustomUser) ScanDestinations() []any {
	return []any{&u.ID, &u.Email, &u.Username, &u.Firstname, &u.Lastname, &u.Role, &u.PasswordHash}
}

func (u *CustomUser) PrimaryKey() string {
	return "email"
}

func (u *CustomUser) PrimaryValue() any {
	return u.Email
}

func (u *CustomUser) New() behemoth.User {
	return &CustomUser{}
}

const CreateCustomUserQuery = `
		CREATE TABLE IF NOT EXISTS custom_user (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			username TEXT UNIQUE, 
			firstname TEXT,
			lastname TEXT, 
			role TEXT,
			password_hash TEXT
		)
	`

func SetUpCustomUserRouter(bmth *auth.Behemoth[*CustomUser]) *chi.Mux {
	router := chi.NewRouter()

	router.Get("/custom/{db}/register", handleRegisterGet)
	router.Post("/custom/{db}/register", nil)

	router.Get("/custom/{db}/login", handleLoginGet)
	router.Post("/custom/{db}/login", nil)

	router.Get("/custom/{db}/users", nil)
	router.Group(func(r chi.Router) {
		r.Use(middleware.Authenticate(bmth.JWT))

		r.Get("/custom/{db}/profile", nil)

		r.Get("/custom/{db}/update", handleUpdateGet)

		r.Post("/custom/{db}/update", nil)

		r.Post("/custom/{db}/delete", nil)
	})
	return router
}

func SetUpCustomUserAuth(db *sql.DB) (*auth.Behemoth[*CustomUser], error) {
	customConf := &behemoth.Config[*CustomUser]{
		DatabaseConfig: behemoth.DatabaseConfig{
			Name:           behemoth.SQLite,
			DB:             db,
			UseDefaultUser: false,
			UserModel:      &CustomUser{},
		},
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: []behemoth.Provider{},
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseSessions:    false,
	}

	return auth.New(customConf)

}
