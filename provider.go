package behemoth

import (
	"context"
	"net/http"

	"github.com/MastewalB/behemoth/models"
	"golang.org/x/oauth2"
)

// Provider defines the interface for OAuth providers like Google or Facebook.
// It provides methods to retrieve provider-specific OAuth endpoints, scopes, and user information.
type Provider interface {
	// Name returns the name of the provider
	Name() string

	// GetEndpoint returns the OAuth endpoint
	GetEndpoint() oauth2.Endpoint

	// GetScopes returns the scopes provided for the OAuth.
	GetScopes() []string

	// GetConfig returns the oauth2 config
	GetConfig() *oauth2.Config

	// FetchUserInfo retrieves user information from the OAuth provider and returns UserInfo type.
	FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (models.UserInfo, error)
}
