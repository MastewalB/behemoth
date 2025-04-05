package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
	"golang.org/x/oauth2"
)

type OAuthAuth[T behemoth.User] struct {
	config         oauth2.Config
	jwtSvc         *JWTService
	useDefaultUser bool
	db             behemoth.Database[T]
}

func NewOAuthAuth[T behemoth.User](cfg behemoth.OAuthConfig,
	jwtSvc *JWTService,
	useDefaultUser bool,
	user behemoth.User,
	db behemoth.Database[T],
) *OAuthAuth[T] {
	return &OAuthAuth[T]{
		config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     behemoth.GoogleEndpoint,
		},
		db:             db,
		jwtSvc:         jwtSvc,
		useDefaultUser: useDefaultUser,
	}
}

func (o *OAuthAuth[T]) Authenticate(creds any) (behemoth.User, error) {
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
	var user *behemoth.DefaultUser
	if o.useDefaultUser {
		user = &behemoth.DefaultUser{
			ID:    userInfo.ID,
			Email: userInfo.Email,
			// PasswordHash not needed for OAuth
		}
	} else {
		// For custom models, assume the developer handles this in their DatabaseProvider
		user = &behemoth.DefaultUser{ID: userInfo.ID, Email: userInfo.Email} // Placeholder
	}

	// Save or update user in DB
	if err := o.db.SaveUser(user); err != nil {
		return nil, errors.New("failed to save user: " + err.Error())
	}

	return user, nil
}

func (o *OAuthAuth[T]) Register(creds any) (behemoth.User, error) {
	return o.Authenticate(creds) // OAuth often combines auth/register
}

func (o *OAuthAuth[T]) AuthURL(state string) string {
	if state == "" {
		state = utils.GenerateState()
	}
	return o.config.AuthCodeURL(state)
}
