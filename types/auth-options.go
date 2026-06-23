package types

import (
	"time"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
)

// type Config[T User] struct {
// 	DatabaseConfig          DatabaseConfig
// 	JWT                     *JWTConfig
// 	Session                 *SessionConfig
// 	Password                *PasswordConfig
// 	OAuthProviders          []Provider
// 	UseSessions             bool
// 	UseEmailAndPasswordAuth bool
// }

// // DatabaseConfig defines configuration for database connection and user model/table.
// type DatabaseConfig struct {
// 	Name           DatabaseName
// 	DB             *sql.DB
// 	UseDefaultUser bool
// 	UserModel      User
// 	UserFactory    func(map[string]any) User
// }

type PasswordOptions struct {
	PasswordHasher core.PasswordHasher
	HashCost       int
	MinLength      int
	MaxLength      int
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

var DefaultPasswordConfig = PasswordOptions{
	HashCost: 10,
}
