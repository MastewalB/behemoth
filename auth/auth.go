package auth

import (
	"github.com/MastewalB/behemoth"
)

type AuthProvider interface {
	Authenticate(credentials any) (*string, error)
	Register(credentials any) (behemoth.User, error)
}

type Behemoth[T behemoth.User] struct {
	DB       behemoth.Database[T]
	Password *PasswordAuth[T]
	OAuth    *OAuthAuth[T]
	JWT      *JWTService
}

// New creates a new Behemoth instance with the given config.
func New[T behemoth.User](cfg *behemoth.Config[T]) *Behemoth[T] {
	var userModel behemoth.User
	var jwtSvc *JWTService
	var oauth *OAuthAuth[T]

	if cfg.UseDefaultUser {
		userModel = &behemoth.DefaultUser{}
	} else {
		if cfg.UserModel == nil {
			// Return error or panic
		}
		userModel = cfg.UserModel
	}
	if cfg.DB == nil {
		// Return error or panic
	}

	if cfg.JWT != nil {
		jwtSvc = NewJWTService(*cfg.JWT)
	}

	if cfg.OAuth != nil {
		oauth = NewOAuthAuth(*cfg.OAuth, jwtSvc, cfg.UseDefaultUser, userModel, cfg.DB)
	}

	return &Behemoth[T]{
		DB:       cfg.DB,
		Password: NewPasswordAuth(*cfg.Password, jwtSvc, cfg.UseDefaultUser, userModel, cfg.DB),
		OAuth:    oauth,
		JWT:      jwtSvc,
	}
}
