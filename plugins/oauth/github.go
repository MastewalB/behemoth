package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// GitHub's endpoints. GitHub is OAuth 2.0 without OpenID Connect: there is
// no discovery document and no ID token, and the user is read from its API.
const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubAPIURL       = "https://api.github.com"
)

// githubProvider is the built-in GitHub provider.
type githubProvider struct {
	id     string
	auth   clientAuth
	scopes []string
	http   providerHTTP
}

func (p *githubProvider) ID() string { return p.id }

// AuthorizationURL implements [Provider]. GitHub has no nonce.
func (p *githubProvider) AuthorizationURL(_ context.Context, req AuthorizationRequest) (string, error) {
	return withQuery(githubAuthorizeURL, url.Values{
		"client_id":             {p.auth.clientID},
		"redirect_uri":          {req.RedirectURI},
		"scope":                 {strings.Join(p.scopes, " ")},
		"state":                 {req.State},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {"S256"},
	})
}

// Exchange implements [Provider]. The subject is the user's numeric id: a
// login can be renamed and then taken by somebody else. The email is the
// user's primary address, and only when GitHub has verified it.
//
// GitHub names no issuer, so the iss of an authorization response is not
// checked.
func (p *githubProvider) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	tokens, err := p.http.redeemCode(ctx, githubTokenURL, p.auth, authSecretPost, req)
	if err != nil {
		return nil, err
	}
	header := http.Header{
		"Authorization":        {"Bearer " + tokens.AccessToken},
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}

	var user struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if _, err := p.http.getJSON(ctx, githubAPIURL+"/user", header, &user); err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	if user.ID == 0 {
		return nil, errors.New("github user: the answer has no id")
	}
	identity := Identity{Subject: strconv.FormatInt(user.ID, 10), Name: user.Name, Picture: user.AvatarURL}

	// The addresses need the user:email scope. Without it GitHub answers
	// 404, and the identity has no email.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	status, err := p.http.getJSON(ctx, githubAPIURL+"/user/emails", header, &emails)
	switch {
	case err == nil:
		for _, e := range emails {
			if e.Primary && e.Verified {
				identity.Email, identity.EmailVerified = e.Email, true
			}
		}
	case status == http.StatusNotFound || status == http.StatusForbidden:
	default:
		return nil, fmt.Errorf("github emails: %w", err)
	}
	return &ExchangeResult{Identity: identity}, nil
}
