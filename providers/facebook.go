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

// FacebookProvider implements the Provider interface for Facebook OAuth.
// It handles Facebook-specific OAuth flows, including user info retrieval.
type Facebook struct {
	ProviderName string
	Config       *oauth2.Config
}

func NewFacebook(clientKey, secret, callbackURL string, scopes ...string) behemoth.Provider {
	if len(scopes) == 0 {
		scopes = []string{"email"}
	}
	return &Facebook{
		ProviderName: "facebook",
		Config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint:     FacebookEndpoint,
		},
	}
}

func (f *Facebook) Name() string {
	return f.ProviderName
}

// GetEndpoint returns Facebook's OAuth 2.0 endpoints.
func (f *Facebook) GetEndpoint() oauth2.Endpoint {
	return FacebookEndpoint
}

func (f *Facebook) GetConfig() *oauth2.Config {
	return f.Config
}

func (f *Facebook) GetScopes() []string {
	return f.Config.Scopes
}

// FetchUserInfo retrieves user information from Facebook using the provided OAuth client and token.
// It maps the Facebook user data to a UserInfo struct, including fields like ID, email, and name.
// Returns the UserInfo or an error if the request or parsing fails.
func (f *Facebook) FetchUserInfo(client *http.Client, ctx context.Context, token *oauth2.Token) (behemoth.UserInfo, error) {

	reqUrl := fmt.Sprintf(
		"%s%s",
		FacebookProfileEndpoint,
		"email,first_name,last_name,id,name,picture,location",
	)
	resp, err := client.Get(reqUrl)
	if err != nil {
		return behemoth.UserInfo{}, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	log.Println(string(body))
	if err != nil {
		return behemoth.UserInfo{}, err
	}

	var fbUser facebookUser
	if err := json.Unmarshal(body, &fbUser); err != nil {
		return behemoth.UserInfo{}, err
	}

	return behemoth.UserInfo{
		Provider:          f.ProviderName,
		ID:                fbUser.ID,
		Email:             fbUser.Email,
		Name:              fbUser.Name,
		FirstName:         fbUser.FirstName,
		LastName:          fbUser.LastName,
		AvatarURL:         fbUser.Picture.Data.URL,
		Location:          fbUser.Location.Name,
		AccessToken:       token.AccessToken,
		AccessTokenSecret: "",
		RefreshToken:      token.RefreshToken,
		ExpiresAt:         token.Expiry,
		IDToken:           "",
	}, nil

}

var DefaultFacebookScopes = []string{"email", "public_profile"}
var FacebookEndpoint = oauth2.Endpoint{
	AuthURL:  "https://www.facebook.com/dialog/oauth",
	TokenURL: "https://graph.facebook.com/oauth/access_token",
}

const FacebookProfileEndpoint = "https://graph.facebook.com/me?fields="

type facebookUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Link      string `json:"link"`
	About     string `json:"about"`
	Location  struct {
		Name string `json:"name"`
	} `json:"location"`
	Picture struct {
		Data struct {
			Height       int    `json:"height"`
			IsSilhouette bool   `json:"is_silhouette"`
			URL          string `json:"url"`
			Width        int    `json:"width"`
		} `json:"data"`
	} `json:"picture"`
}
