package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"golang.org/x/oauth2"
)

// Github implements the Provider interface for Github OAuth.
// It handles Github-specific OAuth flows, including user info retrieval.
type Github struct {
	ProviderName string
	Config       *oauth2.Config
}

// NewGithub creates a new Github provider instance.
func NewGithub(clientKey, secret, callbackURL string, scopes ...string) behemoth.Provider {
	if len(scopes) == 0 {
		scopes = DefaultGithubScope
	}
	return &Github{
		ProviderName: "github",
		Config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint:     GithubEndpoint,
		},
	}
}

// githubUser represents the user information returned by the Github API.
type githubUser struct {
	ID        int64  `json:"id"` // Github uses integer IDs
	Email     string `json:"email"`
	Name      string `json:"name"`
	Login     string `json:"login"`     // Github username
	AvatarURL string `json:"avatar_url"`
	Location  string `json:"location"`
}

// Name returns the provider's name.
func (g *Github) Name() string {
	return g.ProviderName
}

// GetEndpoint returns Github's OAuth 2.0 endpoints.
func (g *Github) GetEndpoint() oauth2.Endpoint {
	return GithubEndpoint
}

// GetConfig returns the oauth2 config for Github.
func (g *Github) GetConfig() *oauth2.Config {
	return g.Config
}

// GetScopes returns the scopes configured for Github OAuth.
func (g *Github) GetScopes() []string {
	return g.Config.Scopes
}

// FetchUserInfo retrieves user information from Github using the provided OAuth client and token.
func (g *Github) FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (models.UserInfo, error) {
	resp, err := client.Get(GithubProfileEndpoint)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to get user info from github: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Github API error: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return models.UserInfo{}, fmt.Errorf("github API returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to read github user info response body: %w", err)
	}
	log.Println("Github User Info Response:", string(body))


	var ghUser githubUser
	if err := json.Unmarshal(body, &ghUser); err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to unmarshal github user info: %w", err)
	}

	// Github might return null for email if not public or scope user:email is missing
	// Name might also be null, fallback to Login
	userName := ghUser.Name
	if userName == "" {
		userName = ghUser.Login
	}


	return models.UserInfo{
		Provider:          g.ProviderName,
		ID:                fmt.Sprintf("%d", ghUser.ID), // Convert int64 ID to string
		Email:             ghUser.Email,
		Name:              userName,
		FirstName:         "",
		LastName:          "",
		AvatarURL:         ghUser.AvatarURL,
		Location:          ghUser.Location,
		AccessToken:       token.AccessToken,
		AccessTokenSecret: "", // OAuth2 doesn't use AccessTokenSecret
		RefreshToken:      token.RefreshToken,
		ExpiresAt:         token.Expiry,
		IDToken:           "", // Github doesn't typically provide an ID Token in this flow
	}, nil
}

// DefaultGithubScope specifies the default OAuth scopes for Github.
var DefaultGithubScope = []string{"user:email"}

// GithubEndpoint defines the OAuth 2.0 endpoints for Github.
var GithubEndpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

// GithubProfileEndpoint is the URL for the Github user info API.
var GithubProfileEndpoint = "https://api.github.com/user"
