package behemoth

import (
	"time"

	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
)

type Config[T User] struct {
	DB             Database[T]
	UserModel      User
	JWT            *JWTConfig
	Session        *SessionConfig
	Password       *PasswordConfig
	OAuthProviders []Provider
	UseDefaultUser bool
	UseSessions    bool
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
	Factory:    nil,
}
