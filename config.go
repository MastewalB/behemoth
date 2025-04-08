package behemoth

import (
	"time"

	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
)

type Config[T User] struct {
	Password       *PasswordConfig
	OAuthProviders []Provider
	JWT            *JWTConfig
	UseDefaultUser bool
	UserModel      User
	DB             Database[T]
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

var DefaultJWTConfig = JWTConfig{
	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
	Expiry:        24 * time.Hour,
	SigningMethod: jwt.SigningMethodHS256,
}

var DefaultPasswordConfig = PasswordConfig{
	HashCost: 10,
}
