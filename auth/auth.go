package auth

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

type Behemoth[T behemoth.User] struct {
	DB          behemoth.Database[T]
	Password    *PasswordAuth[T]
	OAuth       *OAuthAuth[T]
	JWT         *JWTService
	Session     *SessionManager
	UseSessions bool
}

// New creates a new Behemoth instance with the given config.
func New[T behemoth.User](cfg *behemoth.Config[T]) *Behemoth[T] {
	var userModel behemoth.User
	var passwordAuth *PasswordAuth[T]
	var jwtSvc *JWTService
	var oauth *OAuthAuth[T]
	var sessionMgr *SessionManager

	if cfg.UseDefaultUser {
		userModel = &models.User{}
	} else {
		if cfg.UserModel == nil {
			// Return error or panic
		}
		userModel = cfg.UserModel
	}
	if cfg.DB == nil {
		// Return error or panic
	}

	if cfg.UseSessions {
		var sessionConfig *behemoth.SessionConfig = cfg.Session
		if sessionConfig == nil {
			sessionConfig = &behemoth.DefalultSessionConfig
		}
		sessionMgr = NewSessionManager(
			cfg.DB,
			sessionConfig.Expiry,
			sessionConfig.CookieName,
			sessionConfig.Factory,
		)
	}

	if cfg.JWT != nil {
		jwtSvc = NewJWTService(*cfg.JWT)
	}

	if cfg.Password != nil {
		passwordAuth = NewPasswordAuth(
			*cfg.Password,
			jwtSvc,
			cfg.UseDefaultUser,
			userModel,
			cfg.DB,
		)
	}

	if len(cfg.OAuthProviders) > 0 {
		oauth = NewOAuthAuth(
			cfg.OAuthProviders,
			jwtSvc,
			cfg.UseDefaultUser,
			userModel,
			cfg.DB,
		)
	}

	return &Behemoth[T]{
		DB:          cfg.DB,
		Password:    passwordAuth,
		OAuth:       oauth,
		JWT:         jwtSvc,
		Session:     sessionMgr,
		UseSessions: cfg.UseSessions,
	}
}
