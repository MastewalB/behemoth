package plugins_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/engine"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/plugins/oauth"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routeAnswer is a route's response, with its JSON body decoded.
type routeAnswer struct {
	*http.Response
	body behemoth.M
}

// post calls a mounted route of the plugin the way the router does, with
// the cookies a browser would attach, from one client address.
func (app *oauthApp) post(t *testing.T, path, body string, cookies ...*http.Cookie) routeAnswer {
	t.Helper()
	route, ok := app.mounted["/api/auth"+path]
	require.True(t, ok, "no route is mounted at %s", path)
	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rctx := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}, Auth: app.ac}
	rctx.Ctx = types.ContextWithRequest(req.Context(), rctx)
	w := httptest.NewRecorder()
	if err := route.Handler(rctx); err != nil {
		status, errBody := (&errs.DefaultErrorMapper{}).Map(err)
		w.Code = status
		require.NoError(t, json.NewEncoder(w.Body).Encode(errBody))
	} else {
		rctx.Response.Flush(w)
	}
	resp := w.Result()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	answer := routeAnswer{Response: resp}
	require.NoError(t, json.Unmarshal(raw, &answer.body), "the body is JSON: %s", raw)
	return answer
}

// cookie returns the response's cookie whose name starts with prefix.
func (a routeAnswer) cookie(t *testing.T, prefix string) *http.Cookie {
	t.Helper()
	for _, c := range a.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	require.Failf(t, "no cookie", "no cookie starts with %q in %v", prefix, a.Header.Values("Set-Cookie"))
	return nil
}

// stateOf returns the state in the authorization URL a begin route answered
// with.
func stateOf(t *testing.T, begun routeAnswer) string {
	t.Helper()
	raw, _ := begun.body["authorization_url"].(string)
	authURL, err := url.Parse(raw)
	require.NoError(t, err)
	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	return state
}

func withTransport(transport types.TokenTransport) func(*engine.BootConfig) {
	return func(cfg *engine.BootConfig) { cfg.Session.Transport = transport }
}

func completeBody(state string, extra ...string) string {
	return completeBodyFor("google", state, extra...)
}

func completeBodyFor(provider, state string, extra ...string) string {
	return `{"provider":"` + provider + `","code":"code-from-provider","state":"` + state + `"` + strings.Join(extra, "") + `}`
}

// Under the cookie transport the binding value never reaches a script: it is
// an HttpOnly cookie of the sign-in, and the complete route reads it from
// there. The answer is the one every sign-in route gives.
func TestOAuthRoutesUnderTheCookieTransport(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil, withTransport(types.TransportCookie))
	require.NoError(t, err)
	app.google.identity = ada

	begun := app.post(t, oauth.PathBegin, `{"provider":"google","redirect_url":"/dashboard"}`)
	require.Equal(t, http.StatusOK, begun.StatusCode, begun.body)
	assert.NotContains(t, begun.body, "binding", "the binding value is not in the body")
	assert.Equal(t, "no-store", begun.Header.Get("Cache-Control"))
	state := stateOf(t, begun)

	binding := begun.cookie(t, "__Host-"+oauth.BindingCookiePrefix)
	assert.Equal(t, "__Host-"+oauth.BindingCookiePrefix+utils.LookupHashOf(state)[:16], binding.Name, "the cookie is the sign-in's own")
	assert.NotContains(t, binding.Name, state, "the name does not carry the state")
	assert.True(t, binding.HttpOnly)
	assert.True(t, binding.Secure)
	assert.Equal(t, http.SameSiteLaxMode, binding.SameSite, "like the session cookie")
	assert.Equal(t, "/", binding.Path)
	assert.Empty(t, binding.Domain, "a host-only cookie")
	assert.InDelta(t, oauth.DefaultStateTTL.Seconds(), binding.MaxAge, 5, "it lasts as long as the sign-in")
	token, err := app.ac.TokenManager.Verify(t.Context(), types.TokenKindOAuthState, state)
	require.NoError(t, err)
	assert.Equal(t, utils.LookupHashOf(binding.Value), token.MetadataJSON["binding_hash"])

	// Without the cookie the callback is refused, and the sign-in survives.
	refused := app.post(t, oauth.PathComplete, completeBody(state))
	assert.Equal(t, http.StatusUnauthorized, refused.StatusCode)
	assert.Equal(t, oauth.ErrorCodeInvalidCallback, refused.body["code"])

	done := app.post(t, oauth.PathComplete, completeBody(state), binding)
	require.Equal(t, http.StatusOK, done.StatusCode, done.body)
	user, _ := done.body["user"].(map[string]any)
	assert.Equal(t, "ada@example.com", user["email"])
	assert.Equal(t, "/dashboard", done.body["redirect_url"])
	assert.NotContains(t, done.body, "token", "the session token is in the cookie")
	assert.NotEmpty(t, done.cookie(t, types.DefaultSessionCookieName).Value)
	cleared := done.cookie(t, binding.Name)
	assert.Empty(t, cleared.Value)
	assert.Equal(t, -1, cleared.MaxAge, "the used binding cookie is removed")

	again := app.post(t, oauth.PathComplete, completeBody(state), binding)
	assert.Equal(t, http.StatusUnauthorized, again.StatusCode, "a state works once")
}

// Two sign-ins started in one browser, from two tabs, keep a cookie each.
// Either one can be completed.
func TestOAuthRoutesKeepACookiePerSignIn(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil, withTransport(types.TransportCookie))
	require.NoError(t, err)
	app.google.identity = ada

	first := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
	second := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
	firstCookie := first.cookie(t, "__Host-"+oauth.BindingCookiePrefix)
	secondCookie := second.cookie(t, "__Host-"+oauth.BindingCookiePrefix)
	require.NotEqual(t, firstCookie.Name, secondCookie.Name)

	// The browser sends both. The route picks the one of the state.
	done := app.post(t, oauth.PathComplete, completeBody(stateOf(t, first)), firstCookie, secondCookie)
	require.Equal(t, http.StatusOK, done.StatusCode, done.body)
	done = app.post(t, oauth.PathComplete, completeBody(stateOf(t, second)), secondCookie)
	require.Equal(t, http.StatusOK, done.StatusCode, done.body)
}

// A client that keeps the session token itself gets the binding value in
// the body and sends it back in the body. No cookie is set.
func TestOAuthRoutesForAClientWithoutCookies(t *testing.T) {
	for _, transport := range []types.TokenTransport{types.TransportHeader, types.TransportBody} {
		t.Run(string(transport), func(t *testing.T) {
			app, err := bootOAuth(t, oauth.Options{}, nil, withTransport(transport))
			require.NoError(t, err)
			app.google.identity = ada

			begun := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
			require.Equal(t, http.StatusOK, begun.StatusCode, begun.body)
			binding, _ := begun.body["binding"].(string)
			require.NotEmpty(t, binding)
			assert.Empty(t, begun.Cookies(), "no cookie")

			missing := app.post(t, oauth.PathComplete, completeBody(stateOf(t, begun)))
			assert.Equal(t, http.StatusUnauthorized, missing.StatusCode)

			done := app.post(t, oauth.PathComplete, completeBody(stateOf(t, begun), `,"binding":"`+binding+`"`))
			require.Equal(t, http.StatusOK, done.StatusCode, done.body)
			assert.Empty(t, done.Cookies())
			if transport == types.TransportHeader {
				assert.NotEmpty(t, done.Header.Get(types.SessionTokenHeader))
			} else {
				assert.NotEmpty(t, done.body["token"])
			}
		})
	}
}

// Under TransportBoth the binding value goes both ways, as the session token
// does, and either way back works.
func TestOAuthRoutesUnderTransportBoth(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil, withTransport(types.TransportBoth))
	require.NoError(t, err)
	app.google.identity = ada

	begun := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
	cookie := begun.cookie(t, "__Host-"+oauth.BindingCookiePrefix)
	assert.Equal(t, cookie.Value, begun.body["binding"])
	done := app.post(t, oauth.PathComplete, completeBody(stateOf(t, begun)), cookie)
	require.Equal(t, http.StatusOK, done.StatusCode, done.body)

	begun = app.post(t, oauth.PathBegin, `{"provider":"google"}`)
	done = app.post(t, oauth.PathComplete, completeBody(stateOf(t, begun), `,"binding":"`+begun.body["binding"].(string)+`"`))
	require.Equal(t, http.StatusOK, done.StatusCode, done.body)
}

// The binding cookie reaches the complete route on the requests the session
// cookie reaches: it takes the session cookie's SameSite, and drops Secure
// and the prefix that needs it when the session cookie does.
func TestOAuthBindingCookieFollowsTheSessionCookie(t *testing.T) {
	t.Run("a front end on another site", func(t *testing.T) {
		app, err := bootOAuth(t, oauth.Options{}, nil, func(cfg *engine.BootConfig) {
			cfg.Session.Transport, cfg.Session.CookieSameSite = types.TransportCookie, types.SameSiteNone
			cfg.Router.BaseURL = "https://auth.example.com"
		})
		require.NoError(t, err)
		cookie := app.post(t, oauth.PathBegin, `{"provider":"google"}`).cookie(t, "__Host-")
		assert.Equal(t, http.SameSiteNoneMode, cookie.SameSite)
		assert.True(t, cookie.Secure)
	})
	t.Run("development over plain HTTP", func(t *testing.T) {
		app, err := bootOAuth(t, oauth.Options{}, nil, func(cfg *engine.BootConfig) {
			cfg.Session.Transport, cfg.Session.CookieInsecure = types.TransportCookie, true
		})
		require.NoError(t, err)
		app.google.identity = ada
		begun := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
		cookie := begun.cookie(t, oauth.BindingCookiePrefix)
		assert.False(t, cookie.Secure)
		assert.True(t, cookie.HttpOnly)
		done := app.post(t, oauth.PathComplete, completeBody(stateOf(t, begun)), cookie)
		require.Equal(t, http.StatusOK, done.StatusCode, done.body)
	})
}

// A body the routes can't use is a validation error with the field's code.
func TestOAuthRoutesRefuseBadBodies(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil)
	require.NoError(t, err)
	cases := []struct {
		path, body, code string
	}{
		{oauth.PathBegin, `not json`, "request_validation_error"},
		{oauth.PathBegin, `{"provider":7}`, "provider_invalid_input"},
		{oauth.PathBegin, `{"provider":"github"}`, "provider_invalid_input"},
		{oauth.PathBegin, `{"provider":"google","redirect_url":"https://evil.example.com/"}`, "redirect_url_invalid_input"},
		{oauth.PathComplete, `not json`, "request_validation_error"},
		{oauth.PathComplete, `{"provider":"google","code":7,"state":"s"}`, "code_invalid_input"},
		{oauth.PathComplete, `{"provider":"google","code":"c","state":"s","binding":["b"]}`, "binding_invalid_input"},
		{oauth.PathComplete, `{"provider":"google","code":"c"}`, "state_invalid_input"},
	}
	for _, tc := range cases {
		answer := app.post(t, tc.path, tc.body)
		assert.Equal(t, http.StatusBadRequest, answer.StatusCode, "%s %s", tc.path, tc.body)
		assert.Equal(t, tc.code, answer.body["code"], "%s %s", tc.path, tc.body)
	}
}

// Each route has a limit per client address.
func TestOAuthRoutesAreRateLimited(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil)
	require.NoError(t, err)
	for _, path := range []string{oauth.PathBegin, oauth.PathComplete} {
		var last int
		for range 11 {
			last = app.post(t, path, `{"provider":"google","code":"c","state":"s"}`).StatusCode
		}
		assert.Equal(t, http.StatusTooManyRequests, last, "the eleventh call to %s in a minute", path)
	}
}

// Boot puts the session settings on the AuthContext with their defaults
// applied, so a deployment that sets no transport gets the cookie one here
// too.
func TestOAuthRoutesReadTheSessionDefaults(t *testing.T) {
	app, err := bootOAuth(t, oauth.Options{}, nil, withTransport(""))
	require.NoError(t, err)
	assert.Equal(t, types.TransportCookie, app.ac.SessionConfig.Transport)
	assert.Equal(t, types.DefaultSessionCookieName, app.ac.SessionConfig.CookieName)

	begun := app.post(t, oauth.PathBegin, `{"provider":"google"}`)
	assert.NotContains(t, begun.body, "binding")
	assert.NotNil(t, begun.cookie(t, "__Host-"+oauth.BindingCookiePrefix))
}
