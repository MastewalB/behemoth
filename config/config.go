package config

import (
	"time"

	"github.com/MastewalB/behemoth/storage"
	"golang.org/x/oauth2"
)

type Config struct {
	Password       PasswordConfig
	OAuth          OAuthConfig
	JWT            JWTConfig
	UseDefaultUser bool
}

type PasswordConfig struct {
	DB       storage.DatabaseProvider
	HashCost int
	DBConfig *storage.DBConfig
}

type JWTConfig struct {
	Secret string
	Expiry time.Duration
}

type OAuthConfig struct {
	DB           storage.DatabaseProvider
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

var GoogleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://accounts.google.com/o/oauth2/token",
}
