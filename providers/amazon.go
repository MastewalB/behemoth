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

// Amazon implements the Provider interface for Amazon OAuth.
type Amazon struct {
	ProviderName string
	Config       *oauth2.Config
}

// NewAmazon creates a new Amazon provider instance.
func NewAmazon(clientKey, secret, callbackURL string, scopes ...string) behemoth.Provider {
	if len(scopes) == 0 {
		scopes = DefaultAmazonScope
	}
	return &Amazon{
		ProviderName: "amazon",
		Config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint:     AmazonEndpoint,
		},
	}
}

// amazonUser represents the user information returned by the Amazon API.
// Ref: https://developer.amazon.com/docs/login-with-amazon/user-profile-requests.html
type amazonUser struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	PostalCode string `json:"postal_code"` // Included if 'postal_code' scope is present
}

// Name returns the provider's name.
func (a *Amazon) Name() string {
	return a.ProviderName
}

// GetEndpoint returns Amazon's OAuth 2.0 endpoints.
func (a *Amazon) GetEndpoint() oauth2.Endpoint {
	return AmazonEndpoint
}

// GetConfig returns the oauth2 config for Amazon.
func (a *Amazon) GetConfig() *oauth2.Config {
	return a.Config
}

// GetScopes returns the scopes configured for Amazon OAuth.
func (a *Amazon) GetScopes() []string {
	return a.Config.Scopes
}

// FetchUserInfo retrieves user information from Amazon using the provided OAuth client and token.
func (a *Amazon) FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (models.UserInfo, error) {
	resp, err := client.Get(AmazonProfileEndpoint)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to get user info from amazon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Amazon API error: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return models.UserInfo{}, fmt.Errorf("amazon API returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to read amazon user info response body: %w", err)
	}
	log.Println("Amazon User Info Response:", string(body))

	var amzUser amazonUser
	if err := json.Unmarshal(body, &amzUser); err != nil {
		return models.UserInfo{}, fmt.Errorf("failed to unmarshal amazon user info: %w", err)
	}

	// Amazon doesn't provide separate first/last names directly
	// Location might be derived from postal code if needed and available

	return models.UserInfo{
		Provider:          a.ProviderName,
		ID:                amzUser.UserID,
		Email:             amzUser.Email,
		Name:              amzUser.Name,
		FirstName:         "", // Attempt to parse from Name if needed
		LastName:          "", // Attempt to parse from Name if needed
		AvatarURL:         "", // Amazon profile API doesn't typically provide avatar URL
		Location:          amzUser.PostalCode, // Use postal code if available
		AccessToken:       token.AccessToken,
		AccessTokenSecret: "",
		RefreshToken:      token.RefreshToken,
		ExpiresAt:         token.Expiry,
		IDToken:           "", // Amazon doesn't typically provide ID Token in this flow
	}, nil
}

// DefaultAmazonScope specifies the default OAuth scopes for Amazon.
// 'profile' includes name, email, and user_id.
var DefaultAmazonScope = []string{"profile"}

// AmazonEndpoint defines the OAuth 2.0 endpoints for Amazon.
// Ref: https://developer.amazon.com/docs/login-with-amazon/authorization-code-grant.html
var AmazonEndpoint = oauth2.Endpoint{
	AuthURL:  "https://www.amazon.com/ap/oa",
	TokenURL: "https://api.amazon.com/auth/o2/token",
}

// AmazonProfileEndpoint is the URL for the Amazon user profile API.
var AmazonProfileEndpoint = "https://api.amazon.com/user/profile" 