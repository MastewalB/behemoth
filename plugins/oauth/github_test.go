package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/MastewalB/behemoth/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGitHub answers like GitHub's token endpoint and API.
type testGitHub struct {
	mu       sync.Mutex
	token    func() (int, any)
	user     any
	emails   func() (int, any)
	requests []recorded
}

func (g *testGitHub) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		require.NoError(t, r.ParseForm())
		g.requests = append(g.requests, recorded{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), form: r.PostForm})
		answer := func(status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			require.NoError(t, json.NewEncoder(w).Encode(body))
		}
		switch r.URL.Path {
		case "/login/oauth/access_token":
			answer(g.token())
		case "/user":
			answer(http.StatusOK, g.user)
		case "/user/emails":
			answer(g.emails())
		default:
			http.NotFound(w, r)
		}
	}
}

func (g *testGitHub) last(t *testing.T, path string) recorded {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.requests) - 1; i >= 0; i-- {
		if g.requests[i].path == path {
			return g.requests[i]
		}
	}
	require.Failf(t, "no request", "nothing was sent to %s", path)
	return recorded{}
}

func newTestGitHub(t *testing.T) (*testGitHub, *githubProvider, *rewrite) {
	g := &testGitHub{
		token: func() (int, any) {
			return http.StatusOK, map[string]any{"access_token": "gho_1", "token_type": "bearer", "scope": "read:user,user:email"}
		},
		user: map[string]any{"id": 583231, "login": "octocat", "name": "The Octocat", "avatar_url": "https://avatars.example.com/u/583231"},
		emails: func() (int, any) {
			return http.StatusOK, []map[string]any{
				{"email": "octo@old.example.com", "primary": false, "verified": true},
				{"email": "octocat@example.com", "primary": true, "verified": true},
			}
		},
	}
	srv := httptest.NewTLSServer(g.serve(t))
	t.Cleanup(srv.Close)
	client, rw := clientFor(srv)
	return g, &githubProvider{
		id: "github", auth: clientAuth{clientID: "gh-client", secret: staticSecret("gh-secret")},
		scopes: defaultScopes[KindGitHub], http: providerHTTP{client: client},
	}, rw
}

func TestGitHubAuthorizationURL(t *testing.T) {
	_, p, _ := newTestGitHub(t)
	raw, err := p.AuthorizationURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://app.example.com/cb/github", CodeChallenge: "challenge-1", Nonce: "unused",
	})
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, githubAuthorizeURL, u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, url.Values{
		"client_id": {"gh-client"}, "redirect_uri": {"https://app.example.com/cb/github"},
		"scope": {"read:user user:email"}, "state": {"state-1"},
		"code_challenge": {"challenge-1"}, "code_challenge_method": {"S256"},
	}, u.Query(), "GitHub has no nonce")
}

// The subject is the numeric id, and the email is the primary one GitHub
// verified. The secret goes in the form, and every call has a user agent.
func TestGitHubExchange(t *testing.T) {
	g, p, rw := newTestGitHub(t)
	result, err := exchange(p, "")
	require.NoError(t, err)
	assert.Equal(t, Identity{
		Subject: "583231", Email: "octocat@example.com", EmailVerified: true,
		Name: "The Octocat", Picture: "https://avatars.example.com/u/583231",
	}, result.Identity)
	assert.Equal(t, []string{"github.com", "api.github.com", "api.github.com"}, rw.hosts)

	token := g.last(t, "/login/oauth/access_token")
	assert.Equal(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {"code-1"}, "redirect_uri": {"https://app.example.com/cb/acme"},
		"code_verifier": {"verifier-1"}, "client_id": {"gh-client"}, "client_secret": {"gh-secret"},
	}, token.form)
	assert.Equal(t, "application/json", token.header.Get("Accept"), "or GitHub answers with a form")
	user := g.last(t, "/user")
	assert.Equal(t, "Bearer gho_1", user.header.Get("Authorization"))
	assert.Equal(t, outbound.DefaultUserAgent, user.header.Get("User-Agent"))
}

// Without a primary address GitHub verified, or without the scope to read
// addresses, the identity has no email.
func TestGitHubEmails(t *testing.T) {
	cases := map[string]func() (int, any){
		"the primary address is not verified": func() (int, any) {
			return http.StatusOK, []map[string]any{{"email": "octocat@example.com", "primary": true, "verified": false}}
		},
		"no scope to read addresses": func() (int, any) { return http.StatusNotFound, map[string]any{"message": "Not Found"} },
	}
	for name, emails := range cases {
		t.Run(name, func(t *testing.T) {
			g, p, _ := newTestGitHub(t)
			g.emails = emails
			result, err := exchange(p, "")
			require.NoError(t, err)
			assert.Empty(t, result.Identity.Email)
			assert.False(t, result.Identity.EmailVerified)
		})
	}

	g, p, _ := newTestGitHub(t)
	g.emails = func() (int, any) { return http.StatusInternalServerError, map[string]any{} }
	_, err := exchange(p, "")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrExchangeRefused)
}

// GitHub answers a code it refuses with 200 and an error, which refuses
// the sign-in.
func TestGitHubRefusedCode(t *testing.T) {
	g, p, _ := newTestGitHub(t)
	g.token = func() (int, any) {
		return http.StatusOK, map[string]any{"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."}
	}
	_, err := exchange(p, "")
	assert.True(t, errors.Is(err, ErrExchangeRefused), "%v", err)

	g.token = func() (int, any) { return http.StatusOK, map[string]any{"access_token": "gho_1"} }
	g.user = map[string]any{"login": "octocat"}
	_, err = exchange(p, "")
	require.Error(t, err, "a user without an id")
	assert.NotErrorIs(t, err, ErrExchangeRefused)
}
