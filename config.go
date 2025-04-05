package behemoth

import (
	"time"

	// "github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type Config[T User] struct {
	Password       *PasswordConfig
	OAuth          *OAuthConfig
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

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

var GoogleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://accounts.google.com/o/oauth2/token",
}

var DefaultJWTConfig = JWTConfig{
	Secret:        utils.GenerateRandomString(64), // Use a secure random string for the secret
	Expiry:        24 * time.Hour,
	SigningMethod: jwt.SigningMethodHS256,
}

var DefaultPasswordConfig = PasswordConfig{
	HashCost: 10,
}
