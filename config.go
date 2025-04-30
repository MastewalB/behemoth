package behemoth

import (
	"database/sql"
	"time"

	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
)

type Config[T User] struct {
	DatabaseConfig DatabaseConfig[T]
	JWT            *JWTConfig
	Session        *SessionConfig
	Password       *PasswordConfig
	OAuthProviders []Provider
	UseSessions    bool
}

// DatabaseConfig defines configuration for database connection and user model/table.
type DatabaseConfig[T User] struct {
	Name           DatabaseName
	DB             *sql.DB
	UserTable      string
	PrimaryKey     string
	FindUserFn     FindUserFn
	UserModel      User
	UseDefaultUser bool
}

type PasswordConfig struct {
	HashCost int
}

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	SigningMethod jwt.SigningMethod
	Claims        jwt.Claims
}

type SessionConfig struct {
	CookieName string
	Expiry     time.Duration
	Factory    SessionFactory
}

var DefaultJWTConfig = JWTConfig{
	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
	Expiry:        24 * time.Hour,
	SigningMethod: jwt.SigningMethodHS256,
}

var DefaultPasswordConfig = PasswordConfig{
	HashCost: 10,
}

var DefalultSessionConfig = SessionConfig{
	CookieName: "session_id",
	Expiry:     2 * time.Hour,
	Factory: func(id string) Session {
		return NewDefaultSession(id, 2*time.Hour)
	},
}
