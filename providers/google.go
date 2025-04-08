package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/MastewalB/behemoth"
	"golang.org/x/oauth2"
)

// GoogleProvider implements the Provider interface for Google OAuth.
type Google struct {
	ProviderName string
	Config       *oauth2.Config
}

func NewGoogle(clientKey, secret, callbackURL string, scopes ...string) behemoth.Provider {
	if len(scopes) == 0 {
		scopes = DefaultGoogleScope
	}
	return &Google{
		ProviderName: "google",
		Config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint:     GoogleEndpoint,
		},
	}
}

type googleUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Link      string `json:"link"`
	Picture   string `json:"picture"`
}

func (g *Google) Name() string {
	return g.ProviderName
}

// GetEndpoint returns Google's OAuth 2.0 endpoints.
func (g *Google) GetEndpoint() oauth2.Endpoint {
	return GoogleEndpoint
}

func (g *Google) GetConfig() *oauth2.Config {
	return g.Config
}

func (g *Google) GetScopes() []string {
	return g.Config.Scopes
}

func (g *Google) FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (behemoth.UserInfo, error) {
	resp, err := client.Get(GoogleProfileEndpoint)
	if err != nil {
		return behemoth.UserInfo{}, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	log.Println(string(body))
	if err != nil {
		return behemoth.UserInfo{}, err
	}

	var googleUser googleUser
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return behemoth.UserInfo{}, err
	}

	return behemoth.UserInfo{
		ID:                googleUser.ID,
		Provider:          g.ProviderName,
		Email:             googleUser.Email,
		FirstName:         googleUser.FirstName,
		LastName:          googleUser.LastName,
		Name:              fmt.Sprintf("%s %s", googleUser.FirstName, googleUser.LastName),
		AvatarURL:         googleUser.Picture,
		AccessToken:       token.AccessToken,
		AccessTokenSecret: "",
		RefreshToken:      token.RefreshToken,
		ExpiresAt:         token.Expiry,
		IDToken:           "",
	}, nil

}

var DefaultGoogleScope = []string{"email"}
var GoogleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://accounts.google.com/o/oauth2/token",
}
var GoogleProfileEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
