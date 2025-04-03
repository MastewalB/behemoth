package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
	"golang.org/x/oauth2"
)

type OAuthAuth struct {
	config         oauth2.Config
	db             storage.DatabaseProvider
	jwtSvc         *JWTService
	useDefaultUser bool
}

func NewOAuthAuth(cfg config.OAuthConfig, jwtSvc *JWTService, useDefaultUser bool) *OAuthAuth {
	return &OAuthAuth{
		config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     config.GoogleEndpoint,
		},
		db:             cfg.DB,
		jwtSvc:         jwtSvc,
		useDefaultUser: useDefaultUser,
	}
}

func (o *OAuthAuth) Authenticate(creds interface{}) (models.User, error) {
	code, ok := creds.(string) // OAuth code from redirect
	if !ok {
		return nil, errors.New("invalid OAuth code")
	}
	token, err := o.config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	// Fetch user info (provider-specific, e.g., Google API)
	client := o.config.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, errors.New("failed to get user info: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("failed to read user info: " + err.Error())
	}

	var userInfo struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, errors.New("failed to parse user info: " + err.Error())
	}

	// Create or update user
	var user *models.DefaultUser
	if o.useDefaultUser {
		user = &models.DefaultUser{
			ID:    userInfo.ID,
			Email: userInfo.Email,
			// PasswordHash not needed for OAuth
		}
	} else {
		// For custom models, assume the developer handles this in their DatabaseProvider
		user = &models.DefaultUser{ID: userInfo.ID, Email: userInfo.Email} // Placeholder
	}

	// Save or update user in DB
	if err := o.db.SaveUser(user); err != nil {
		return nil, errors.New("failed to save user: " + err.Error())
	}

	return user, nil
}

func (o *OAuthAuth) Register(creds any) (models.User, error) {
	return o.Authenticate(creds) // OAuth often combines auth/register
}

func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (o *OAuthAuth) AuthURL(state string) string {
	if state == "" {
		state = GenerateState()
	}
	return o.config.AuthCodeURL(state)
}
