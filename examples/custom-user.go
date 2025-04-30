package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/middleware"
	"github.com/go-chi/chi/v5"
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
		DatabaseConfig: behemoth.DatabaseConfig[*CustomUser]{
			Name:           behemoth.SQLite,
			DB:             db,
			UseDefaultUser: false,
			UserModel:      &CustomUser{},
			UserTable:      "custom_users",
			PrimaryKey:     "email",
			FindUserFn: func(db, val any) (behemoth.User, error) {
				sqlt, ok := db.(*sql.DB)
				if !ok {
					return nil, fmt.Errorf("invalid database type")
				}
				email, ok := val.(string)
				if !ok {
					return nil, fmt.Errorf("invalid email parameter")
				}

				var user *CustomUser = &CustomUser{}
				err := sqlt.QueryRow(`SELECT * FROM users WHERE email = ?`, email).Scan(
					&user.ID, &user.Email, &user.Username, &user.Firstname, &user.Lastname, &user.PasswordHash, &user.Role,
				)
				return user, err
			},
		},
		Password:       &behemoth.PasswordConfig{HashCost: 10},
		OAuthProviders: []behemoth.Provider{},
		JWT:            &behemoth.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
		UseSessions:    false,
	}

	return auth.New(customConf)

}
