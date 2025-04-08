package behemoth

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type Provider interface {
	// Returns the name of the provider
	Name() string

	// Returns the OAuth endpoint
	GetEndpoint() oauth2.Endpoint

	GetScopes() []string

	GetConfig() *oauth2.Config

	// FetchUserInfo retrieves user information using the OAuth client.
	FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (UserInfo, error)
}

type UserInfo struct {
	Provider          string
	Email             string
	Name              string
	FirstName         string
	LastName          string
	ID                string
	AvatarURL         string
	Location          string
	AccessToken       string
	AccessTokenSecret string
	RefreshToken      string
	ExpiresAt         time.Time
	IDToken           string
}

func (ui *UserInfo) GetID() string {
	return ui.ID
}

func (ui *UserInfo) GetPasswordHash() string {
	return ""
}
