package config

import (
	"time"

	"github.com/MastewalB/behemoth/storage"
	"golang.org/x/oauth2"
)

type Config struct {
	Password PasswordConfig
	JWT      JWTConfig
}

type PasswordConfig struct {
	DB             storage.DatabaseProvider
	HashCost       int
	UseDefaultUser bool
	DBConfig       *storage.DBConfig
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
	Endpoint     oauth2.Endpoint
}
