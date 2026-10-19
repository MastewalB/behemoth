package plugins_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/engine"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/keysource"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/adapters/nethttp"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tokenIssuer     = "https://auth.example.com"
	apiAudience     = "https://api.example.com"
	reportsAudience = "https://reports.example.com"
)

func sessionTokenConfig() crypto.JWTConfig {
	return crypto.JWTConfig{
		Issuer:    tokenIssuer,
		Audiences: map[crypto.JWTKind][]string{crypto.JWTExternal: {apiAudience, reportsAudience}},
	}
}

// tokenApp is core alone, booted with session tokens, and a user with an
// active session whose raw token travels as a bearer token.
type tokenApp struct {
	ac      *core.AuthContext
	mounted mountedRoutes
	user    *models.User
	session *models.Session
	raw     string
}

func bootSessionTokens(t *testing.T, jwtCfg crypto.JWTConfig, hookFn func(reg core.HookRegistry) error, configure ...func(*engine.BootConfig)) (*tokenApp, error) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "tokens.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	app := &tokenApp{mounted: mountedRoutes{}}
	prepared, err := engine.Prepare(nil, engine.PrepareConfig{})
	require.NoError(t, err)
	cfg := engine.BootConfig{
		Crypto:  crypto.Config{Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1}},
		Session: core.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: time.Minute, Transport: core.TransportHeader},
		JWT:     jwtCfg,
		Hooks:   hookFn,
		HTTP:    app.mounted,
	}
	for _, fn := range configure {
		fn(&cfg)
	}
	app.ac, err = engine.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, nil), cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { app.ac.Mailer.Close(context.Background()) })

	app.user = &models.User{Email: "ada@example.com"}
	require.NoError(t, app.ac.Store.CreateUser(ctx, app.user))
	app.session, app.raw, err = app.ac.SessionManager.Create(ctx, app.user.ID, core.SessionMeta{State: models.SessionActive})
	require.NoError(t, err)
	return app, nil
}

type answer struct {
	status int
	header http.Header
	body   behemoth.M
}

// call runs a mounted route the way the router does, with the bearer token
// raw when it is not empty.
func (app *tokenApp) call(t *testing.T, method, path, body, raw string) answer {
	t.Helper()
	route, ok := app.mounted[path]
	require.True(t, ok, "no route is mounted at %s", path)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if raw != "" {
		req.Header.Set("Authorization", "Bearer "+raw)
	}
	rctx := &core.RequestContext{Request: req, Response: core.NewResponseRecorder(), Values: behemoth.M{}, Auth: app.ac}
	rctx.Ctx = core.ContextWithRequest(req.Context(), rctx)
	w := httptest.NewRecorder()
	if err := route.Handler(rctx); err != nil {
		status, errBody := (&errs.DefaultErrorMapper{}).Map(err)
		w.Code = status
		require.NoError(t, json.NewEncoder(w.Body).Encode(errBody))
	} else {
		rctx.Response.Flush(w)
	}
	resp := w.Result()
	raw2, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := answer{status: resp.StatusCode, header: resp.Header}
	require.NoError(t, json.Unmarshal(raw2, &out.body), "%s", raw2)
	return out
}

func (app *tokenApp) issue(t *testing.T, body string) answer {
	t.Helper()
	return app.call(t, http.MethodPost, "/api/auth"+core.PathSessionToken, body, app.raw)
}

// verifyElsewhere checks token the way another service does: with the keys
// the key set route publishes, and nothing else of behemoth.
func (app *tokenApp) verifyElsewhere(t *testing.T, token, audience string) (jwt.MapClaims, error) {
	t.Helper()
	set := app.call(t, http.MethodGet, "/.well-known/jwks.json", "", "")
	require.Equal(t, http.StatusOK, set.status)
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.body["keys"].([]any) {
		key := k.(map[string]any)
		x, err := base64.RawURLEncoding.DecodeString(key["x"].(string))
		require.NoError(t, err)
		keys[key["kid"].(string)] = x
	}
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(audience), jwt.WithExpirationRequired()).
		ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
			kid, _ := tok.Header["kid"].(string)
			key, ok := keys[kid]
			if !ok {
				return nil, jwt.ErrTokenUnverifiable
			}
			return key, nil
		})
	return claims, err
}

// A Go service checks session tokens with package crypto: the key set
// fetched from the route over HTTP by keysource.JWKSet, kept by a
// CachedKeySet, and the token checked by VerifyJWT. A token for another
// service, or from another issuer, is refused.
func TestSessionTokenIsVerifiedWithVerifyJWT(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	app, err := bootSessionTokens(t, sessionTokenConfig(), nil, func(cfg *engine.BootConfig) { cfg.HTTP = nethttp.New(mux) })
	require.NoError(t, err)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issued, err := app.ac.SessionTokens.Issue(ctx, core.SessionTokenRequest{Session: app.session, Audience: reportsAudience})
	require.NoError(t, err)

	source, err := keysource.NewJWKSet(nil, srv.URL+"/.well-known/jwks.json")
	require.NoError(t, err)
	keys, err := crypto.NewCachedKeySet(source, crypto.CacheOptions{})
	require.NoError(t, err)
	opts := crypto.VerifyOptions{Issuers: []string{tokenIssuer}, Audiences: []string{reportsAudience}}

	verified, err := crypto.VerifyJWT(ctx, issued.Token, keys, opts)
	require.NoError(t, err)
	assert.Equal(t, app.user.ID, verified.Subject)
	assert.Equal(t, "EdDSA", verified.Algorithm)
	assert.Equal(t, issued.ID, verified.ID)
	var claims struct {
		SessionID string `json:"sid"`
	}
	require.NoError(t, verified.Claims(&claims))
	assert.Equal(t, app.session.ID, claims.SessionID)

	elsewhere := opts
	elsewhere.Audiences = []string{apiAudience}
	_, err = crypto.VerifyJWT(ctx, issued.Token, keys, elsewhere)
	assert.True(t, errs.IsCategory(err, errs.CategoryToken), "a token for another service: %v", err)
	forged := opts
	forged.Issuers = []string{"https://evil.example.com"}
	_, err = crypto.VerifyJWT(ctx, issued.Token, keys, forged)
	assert.True(t, errs.IsCategory(err, errs.CategoryToken), "another issuer: %v", err)
}

// A signed-in client exchanges its session for a token, and another service
// verifies the token with the published keys alone. The token says who the
// user is, which session it came from, and that it lasts 15 minutes.
func TestSessionTokenIsVerifiedElsewhere(t *testing.T) {
	app, err := bootSessionTokens(t, sessionTokenConfig(), nil)
	require.NoError(t, err)

	issued := app.issue(t, "")
	require.Equal(t, http.StatusOK, issued.status, issued.body)
	assert.Equal(t, "no-store", issued.header.Get("Cache-Control"))
	assert.Equal(t, apiAudience, issued.body["audience"], "no audience asked for: the first")
	assert.Empty(t, issued.header.Values("Set-Cookie"), "the token is in the body only")
	token := issued.body["token"].(string)

	claims, err := app.verifyElsewhere(t, token, apiAudience)
	require.NoError(t, err, "a service verifies the token with the key set")
	assert.Equal(t, app.user.ID, claims["sub"])
	assert.Equal(t, app.session.ID, claims["sid"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotContains(t, claims, "custom", "no handler added claims")
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	assert.Equal(t, int64(15*60), exp-iat, "15 minutes by default")
	expiresAt, err := time.Parse(time.RFC3339, issued.body["expires_at"].(string))
	require.NoError(t, err)
	assert.Equal(t, exp, expiresAt.Unix())

	_, err = app.verifyElsewhere(t, token, reportsAudience)
	assert.Error(t, err, "a service that is not the token's audience refuses it")

	// The token is for other services: it is not a session of behemoth.
	asSession := app.call(t, http.MethodPost, "/api/auth"+core.PathSessionToken, "", token)
	assert.Equal(t, http.StatusUnauthorized, asSession.status)
	assert.Equal(t, errs.CodeSessionInvalid, asSession.body["code"])
}

// A request may name another configured audience, and nothing else.
func TestSessionTokenAudiences(t *testing.T) {
	app, err := bootSessionTokens(t, sessionTokenConfig(), nil)
	require.NoError(t, err)

	issued := app.issue(t, `{"audience":"`+reportsAudience+`"}`)
	require.Equal(t, http.StatusOK, issued.status, issued.body)
	assert.Equal(t, reportsAudience, issued.body["audience"])
	_, err = app.verifyElsewhere(t, issued.body["token"].(string), reportsAudience)
	assert.NoError(t, err)

	for body, code := range map[string]string{
		`{"audience":"https://evil.example.com"}`: "audience_invalid_input",
		`{"audience":7}`: "audience_invalid_input",
		`not json`:       "request_validation_error",
	} {
		refused := app.issue(t, body)
		assert.Equal(t, http.StatusBadRequest, refused.status, body)
		assert.Equal(t, code, refused.body["code"], body)
	}
	assert.Equal(t, http.StatusOK, app.issue(t, `{}`).status, "an empty object asks for the default")
}

// Only a signed-in session gets a token: none, a revoked one, and one that
// waits for a second factor are refused with the session codes.
func TestSessionTokenNeedsASignedInSession(t *testing.T) {
	ctx := context.Background()
	app, err := bootSessionTokens(t, sessionTokenConfig(), nil)
	require.NoError(t, err)
	path := "/api/auth" + core.PathSessionToken

	none := app.call(t, http.MethodPost, path, "", "")
	assert.Equal(t, http.StatusUnauthorized, none.status)
	assert.Equal(t, errs.CodeSessionMissing, none.body["code"])

	_, pendingRaw, err := app.ac.SessionManager.Create(ctx, app.user.ID, core.SessionMeta{State: models.SessionPending})
	require.NoError(t, err)
	pending := app.call(t, http.MethodPost, path, "", pendingRaw)
	assert.Equal(t, http.StatusUnauthorized, pending.status)
	assert.Equal(t, errs.CodeSessionPending, pending.body["code"])

	require.NoError(t, app.ac.SessionManager.Revoke(ctx, app.session.ID, "signed_out"))
	revoked := app.issue(t, "")
	assert.Equal(t, http.StatusUnauthorized, revoked.status)

	// The flow refuses the same when it is called from code.
	expired := *app.session
	expired.RevokedAt, expired.State, expired.ExpiresAt = nil, models.SessionActive, time.Now().Add(-time.Minute)
	_, err = app.ac.SessionTokens.Issue(ctx, core.SessionTokenRequest{Session: &expired})
	assert.True(t, errs.IsCode(err, errs.CodeSessionExpired), "%v", err)
	stillPending := *app.session
	stillPending.State = models.SessionPending
	_, err = app.ac.SessionTokens.Issue(ctx, core.SessionTokenRequest{Session: &stillPending})
	assert.True(t, errs.IsCode(err, errs.CodeSessionPending), "%v", err)
}

// A handler on the before point adds claims, which travel under "custom",
// and can't change who the token is about or for whom. It can refuse the
// token. The after point gets the record without the token.
func TestSessionTokenHooks(t *testing.T) {
	var values []behemoth.M
	var records []*core.SessionToken
	var failures []core.FailureReason
	refuse := false
	app, err := bootSessionTokens(t, sessionTokenConfig(), func(reg core.HookRegistry) error {
		if err := reg.OnBefore(hooks.HookSessionTokenBeforeIssue, func(hctx *core.HookContext, payload behemoth.M) (behemoth.M, error) {
			values = append(values, behemoth.M{"userID": hctx.Values[hooks.HookValueUserID], "sessionID": hctx.Values[hooks.HookValueSessionID]})
			if refuse {
				return nil, errs.NewUnauthorized("test", "plan_required", "a paid plan is required")
			}
			payload["claims"] = behemoth.M{"role": "admin", "tenant": "acme"}
			payload["audience"] = reportsAudience
			payload["userID"] = "someone-else"
			return payload, nil
		}, nil); err != nil {
			return err
		}
		if err := reg.OnAfter(hooks.HookSessionTokenAfterIssue, func(_ *core.HookContext, result any) error {
			records = append(records, result.(*core.SessionToken))
			return nil
		}, nil); err != nil {
			return err
		}
		return reg.OnFailed(hooks.HookSessionTokenIssueFailed, func(_ *core.HookContext, reason core.FailureReason) error {
			failures = append(failures, reason)
			return nil
		}, nil)
	})
	require.NoError(t, err)

	issued := app.issue(t, "")
	require.Equal(t, http.StatusOK, issued.status, issued.body)
	claims, err := app.verifyElsewhere(t, issued.body["token"].(string), apiAudience)
	require.NoError(t, err, "the audience is still the one asked for")
	assert.Equal(t, app.user.ID, claims["sub"], "the subject is still the session's user")
	assert.Equal(t, map[string]any{"role": "admin", "tenant": "acme"}, claims["custom"])

	require.Len(t, values, 1)
	assert.Equal(t, behemoth.M{"userID": app.user.ID, "sessionID": app.session.ID}, values[0], "a rate-limit rule finds the user and the session")
	require.Len(t, records, 1)
	assert.Empty(t, records[0].Token, "a handler does not get the token")
	assert.Equal(t, app.session.ID, records[0].SessionID)
	assert.NotEmpty(t, records[0].ID)

	refuse = true
	refused := app.issue(t, "")
	assert.Equal(t, http.StatusUnauthorized, refused.status)
	assert.Equal(t, "plan_required", refused.body["code"])
	require.Len(t, failures, 1)
	assert.Equal(t, core.FailureRejectedByHook, failures[0].Code)
	assert.Len(t, records, 1, "no record for a refused token")
}

// Without an external audience, session tokens are off: neither route is
// mounted, and the flow is a configuration error. Internal JWTs still work.
func TestSessionTokensOff(t *testing.T) {
	ctx := context.Background()
	app, err := bootSessionTokens(t, crypto.JWTConfig{}, nil)
	require.NoError(t, err)
	assert.NotContains(t, app.mounted, "/api/auth"+core.PathSessionToken)
	assert.NotContains(t, app.mounted, "/.well-known/jwks.json")

	_, err = app.ac.SessionTokens.Issue(ctx, core.SessionTokenRequest{Session: app.session})
	assert.True(t, errs.IsCode(err, errs.CodeJWTExternalNotConfigured), "%v", err)

	token, err := app.ac.JWT.Sign(ctx, crypto.JWTInternal, crypto.JWTRequest{Subject: app.user.ID})
	require.NoError(t, err)
	_, err = app.ac.JWT.Verify(ctx, crypto.JWTInternal, token)
	assert.NoError(t, err)
}

// The issuer falls back to the base URL, the lifetime can be set, and a
// configuration that can't work fails Boot.
func TestSessionTokenConfiguration(t *testing.T) {
	audiences := map[crypto.JWTKind][]string{crypto.JWTExternal: {apiAudience}}

	app, err := bootSessionTokens(t, crypto.JWTConfig{Audiences: audiences, TTL: map[crypto.JWTKind]time.Duration{crypto.JWTExternal: 5 * time.Minute}}, nil,
		func(cfg *engine.BootConfig) { cfg.Router.BaseURL = tokenIssuer })
	require.NoError(t, err)
	issued := app.issue(t, "")
	require.Equal(t, http.StatusOK, issued.status, issued.body)
	claims, err := app.verifyElsewhere(t, issued.body["token"].(string), apiAudience)
	require.NoError(t, err, "the issuer is the base URL")
	assert.Equal(t, float64(5*60), claims["exp"].(float64)-claims["iat"].(float64))

	for name, cfg := range map[string]crypto.JWTConfig{
		"no issuer and no base URL": {Audiences: audiences},
		"an empty audience":         {Issuer: tokenIssuer, Audiences: map[crypto.JWTKind][]string{crypto.JWTExternal: {""}}},
		"a negative lifetime":       {Issuer: tokenIssuer, Audiences: audiences, TTL: map[crypto.JWTKind]time.Duration{crypto.JWTExternal: -time.Minute}},
		"a relative key set path":   {Issuer: tokenIssuer, Audiences: audiences, JWKSPath: "jwks.json"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bootSessionTokens(t, cfg, nil)
			assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
		})
	}
}

// The exchange has a limit per client address.
func TestSessionTokenRateLimit(t *testing.T) {
	app, err := bootSessionTokens(t, sessionTokenConfig(), nil)
	require.NoError(t, err)
	var last int
	for range 31 {
		last = app.issue(t, "").status
	}
	assert.Equal(t, http.StatusTooManyRequests, last, "the 31st request in a minute")
}
