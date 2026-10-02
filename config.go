package behemoth

import (
	"database/sql"
	"time"

	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	DatabaseConfig          DatabaseConfig
	JWT                     *JWTConfig
	Session                 *SessionConfig
	Password                *PasswordConfig
	OAuthProviders          []Provider
	UseSessions             bool
	UseEmailAndPasswordAuth bool
}

// DatabaseConfig defines configuration for the database connection. The user
// model is always models.User, extended through schema contributions.
type DatabaseConfig struct {
	Name DatabaseName
	DB   *sql.DB
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
}

var DefaultJWTConfig = JWTConfig{
	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
	Expiry:        24 * time.Hour,
	SigningMethod: jwt.SigningMethodHS256,
}

var DefaultPasswordConfig = PasswordConfig{
	HashCost: 10,
}
