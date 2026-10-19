package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/outbound"
)

// This file is the part of the OAuth 2.0 protocol the built-in providers
// share: the authorization URL, the code exchange with PKCE, client
// authentication, and reading a provider's answers. The calls go through
// outbound, which gives each a timeout, no redirects, a user agent, a span,
// and a bound on the answer (ADR-0003).

// providerHTTP makes the calls of a built-in provider, with the plugin's
// client: Options.HTTPClient, or else AuthContext.HTTPClient.
type providerHTTP struct {
	client *http.Client
}

// getJSON GETs rawURL with header and decodes the answer into into. An
// answer whose status is not 2xx is an error.
func (h providerHTTP) getJSON(ctx context.Context, rawURL string, header http.Header, into any) (status int, err error) {
	return outbound.GetJSON(ctx, h.client, rawURL, header, into)
}

// tokenResponse is a token endpoint's answer (RFC 6749, sections 5.1 and
// 5.2). Only what the plugin reads is decoded.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

// clientAuth is how a client authenticates at a token endpoint (RFC 6749,
// section 2.3.1).
type clientAuth struct {
	clientID string
	// secret is the client secret's source. Nil for a public client.
	secret crypto.SecretSource
}

// Client authentication methods, by their names in OpenID Connect
// Discovery.
const (
	authSecretBasic = "client_secret_basic"
	authSecretPost  = "client_secret_post"
	authNone        = "none"
)

// currentSecret returns the current value of the client secret.
func currentSecret(ctx context.Context, source crypto.SecretSource) (string, error) {
	secrets, current, err := source.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("client secret: %w", err)
	}
	if secret := secrets[current]; secret != "" {
		return secret, nil
	}
	return "", errors.New("client secret: the source has no current secret")
}

// redeemCode posts the authorization code of req to tokenURL, authenticated
// with method, and returns the provider's answer.
//
// An answer that names an OAuth error, with any status, wraps
// ErrExchangeRefused: GitHub answers a code it refuses with 200 and an
// error. Any other answer that holds no access token is a failure of the
// system.
func (h providerHTTP) redeemCode(ctx context.Context, tokenURL string, auth clientAuth, method string, req ExchangeRequest) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code},
		"redirect_uri":  {req.RedirectURI},
		"code_verifier": {req.CodeVerifier},
	}
	header := http.Header{"Accept": {"application/json"}}
	switch method {
	case authSecretBasic, authSecretPost:
		secret, err := currentSecret(ctx, auth.secret)
		if err != nil {
			return nil, err
		}
		if method == authSecretBasic {
			// The id and the secret are form-encoded before they are
			// joined, so a ":" in either survives.
			credentials := url.QueryEscape(auth.clientID) + ":" + url.QueryEscape(secret)
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
		} else {
			form.Set("client_id", auth.clientID)
			form.Set("client_secret", secret)
		}
	default:
		form.Set("client_id", auth.clientID)
	}
	status, body, err := outbound.PostForm(ctx, h.client, tokenURL, form, header)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	var answer tokenResponse
	decodeErr := json.Unmarshal(bytes.TrimSpace(body), &answer)
	if answer.Error != "" {
		return nil, fmt.Errorf("%w: the token endpoint answered %q", ErrExchangeRefused, answer.Error)
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("token endpoint answered %d", status)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("token endpoint: %w", decodeErr)
	}
	if answer.AccessToken == "" {
		return nil, errors.New("token endpoint: the answer has no access token")
	}
	return &answer, nil
}

// withQuery returns endpoint with params added to its query. A parameter
// the endpoint already has is replaced.
func withQuery(endpoint string, params url.Values) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for k, v := range params {
		query[k] = v
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}
