package auth

import (
	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
)

type AuthProvider interface {
	Authenticate(credentials any) (models.User, error)
	Register(credentials any) (models.User, error)
}

type Behemoth struct {
	Password *PasswordAuth
	JWT      *JWTService
}

// New creates a new Behemoth instance with the given config.
func New(cfg *config.Config) *Behemoth {
	jwtSvc := NewJWTService(cfg.JWT)
	return &Behemoth{
		Password: NewPasswordAuth(cfg.Password, jwtSvc),
		JWT:      jwtSvc,
	}
}
