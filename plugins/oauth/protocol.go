package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MastewalB/behemoth/types"
)

// This file is the part of the OAuth 2.0 protocol the built-in providers
// share: the authorization URL, the code exchange with PKCE, client
// authentication, and reading a provider's answers.

// maxResponseBytes bounds what the plugin reads of one answer of a
// provider. A discovery document, a key set or a token response is a few
// kilobytes.
const maxResponseBytes = 1 << 20

// defaultTimeout is how long one call to a provider may take when
// Options.HTTPClient is nil.
const defaultTimeout = 10 * time.Second

// userAgent is sent with every call to a provider. GitHub's API refuses a
// request without one.
const userAgent = "behemoth-oauth"

// defaultHTTPClient is the client of the built-in providers when
// Options.HTTPClient is nil. It follows no redirect: the plugin sends a code,
// a verifier and a client secret, and they go to the URL the provider's
// configuration names and nowhere else. A redirect is answered as an error.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// providerHTTP makes the calls of a built-in provider.
type providerHTTP struct {
	client *http.Client
}

// do sends req and reads at most maxResponseBytes of the answer. A longer
// answer is an error.
func (h providerHTTP) do(req *http.Request) (status int, body []byte, err error) {
	req.Header.Set("User-Agent", userAgent)
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > maxResponseBytes {
		return resp.StatusCode, nil, fmt.Errorf("the answer of %s is longer than %d bytes", req.URL.Redacted(), maxResponseBytes)
	}
	return resp.StatusCode, body, nil
}

// getJSON GETs rawURL with header and decodes the answer into into. An
// answer whose status is not 2xx is an error.
func (h providerHTTP) getJSON(ctx context.Context, rawURL string, header http.Header, into any) (status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	status, body, err := h.do(req)
	if err != nil {
		return status, err
	}
	if status/100 != 2 {
		return status, fmt.Errorf("GET %s answered %d", req.URL.Redacted(), status)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return status, fmt.Errorf("GET %s: %w", req.URL.Redacted(), err)
	}
	return status, nil
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
	secret types.SecretSource
}

// Client authentication methods, by their names in OpenID Connect
// Discovery.
const (
	authSecretBasic = "client_secret_basic"
	authSecretPost  = "client_secret_post"
	authNone        = "none"
)

// currentSecret returns the current value of the client secret.
func currentSecret(ctx context.Context, source types.SecretSource) (string, error) {
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
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
	if err != nil {
		return nil, err
	}
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
			httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
		} else {
			form.Set("client_id", auth.clientID)
			form.Set("client_secret", secret)
		}
	default:
		form.Set("client_id", auth.clientID)
	}
	encoded := form.Encode()
	httpReq.Body = io.NopCloser(strings.NewReader(encoded))
	httpReq.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	httpReq.ContentLength = int64(len(encoded))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	status, body, err := h.do(httpReq)
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

// checkEndpoint refuses a URL a provider's configuration names when the
// plugin should not send anything there: one that is not absolute https, or
// http on a loopback address for a provider in development.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Host == "" || u.User != nil || u.Fragment != "":
		return fmt.Errorf("%q is not an absolute URL without credentials or a fragment", raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%q is not https", raw)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
