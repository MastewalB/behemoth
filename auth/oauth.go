package auth

import (
	"context"
	"errors"

	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
	"golang.org/x/oauth2"
)

type OAuthAuth struct {
	config oauth2.Config
	db     storage.DatabaseProvider
	jwtSvc *JWTService
}

func NewOAuthAuth(cfg config.OAuthConfig, jwtSvc *JWTService) *OAuthAuth {
	return &OAuthAuth{
		config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     cfg.Endpoint,
		},
		db:     cfg.DB,
		jwtSvc: jwtSvc,
	}
}

func (o *OAuthAuth) Authenticate(creds interface{}) (models.User, error) {
	code, ok := creds.(string) // OAuth code from redirect
	if !ok {
		return nil, errors.New("invalid OAuth code")
	}
	_, err := o.config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	// Fetch user info (provider-specific, e.g., Google API)
	// For now, assume we get an email and ID
	user := &models.DefaultUser{ID: "oauth_user_id", Email: "user@example.com"}
	return user, o.db.SaveUser(user)
}

func (o *OAuthAuth) Register(creds interface{}) (models.User, error) {
	return o.Authenticate(creds) // OAuth often combines auth/register
}
