package plugins_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/emailverification"
	"github.com/MastewalB/behemoth/plugins/magiclink"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	bmth "github.com/MastewalB/behemoth/types/init"
	dbschema "github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bootPasswords boots the email/password plugin alone with session.
func bootPasswords(t *testing.T, session types.SessionConfig, hookFn func(types.HookRegistry) error) (*types.AuthContext, mountedRoutes, error) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "signin.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	mounted := mountedRoutes{}
	app, err := bmth.Prepare([]types.Plugin{emailpassword.New(emailpassword.Options{})}, bmth.PrepareConfig{})
	require.NoError(t, err)
	ac, err := bmth.Boot(context.Background(), app, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session: session,
		HTTP:    mounted,
		Hooks:   hookFn,
	})
	return ac, mounted, err
}

// callHeaders invokes a mounted route the way call does, with request
// headers: the cookie or the bearer token of a signed-in client.
func callHeaders(t *testing.T, ac *types.AuthContext, route types.Route, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rctx := &types.RequestContext{Request: req, Response: types.NewResponseRecorder(), Values: behemoth.M{}, Auth: ac}
	rctx.Ctx = types.ContextWithRequest(req.Context(), rctx)
	err := route.Handler(rctx)
	w := httptest.NewRecorder()
	if err != nil {
		status, body := (&behemotherr.DefaultErrorMapper{}).Map(err)
		w.Code = status
		require.NoError(t, json.NewEncoder(w.Body).Encode(body))
		return w
	}
	rctx.Response.Flush(w)
	return w
}

// A sign-in hands the session token over where SessionConfig.Transport
// says, and nowhere else: a cookie, the Set-Auth-Token header, or the JSON
// body. The body has the same shape for every transport, and the user in it
// is keyed by column name. Left unset, the transport is the cookie.
func TestSignInDeliversTheTokenByTransport(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		session types.SessionConfig
		cookie  string // the cookie's name when the token is in one
		header  bool   // the token is in Set-Auth-Token
		body    bool   // the token is in the JSON body
	}{
		"nothing set":   {types.SessionConfig{}, "session_token", false, false},
		"cookie, named": {types.SessionConfig{Transport: types.TransportCookie, CookieName: "sid"}, "sid", false, false},
		"header":        {types.SessionConfig{Transport: types.TransportHeader}, "", true, false},
		"body":          {types.SessionConfig{Transport: types.TransportBody}, "", false, true},
		"both":          {types.SessionConfig{Transport: types.TransportBoth}, "session_token", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			ac, mounted, err := bootPasswords(t, tc.session, nil)
			require.NoError(t, err)

			w := call(t, ac, mounted["/api/auth/sign-up/email"],
				`{"email":"Ada@Example.com","password":"correct horse","firstname":"Ada","image_url":"https://example.com/a.png"}`)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			var signedUp map[string]map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &signedUp))
			require.Equal(t, []string{"user"}, slices.Collect(maps.Keys(signedUp)), "a sign-up creates no session: %s", w.Body.String())
			user := signedUp["user"]
			assert.ElementsMatch(t,
				[]string{"id", "email", "username", "firstname", "lastname", "email_verified", "image_url", "created_at", "updated_at"},
				slices.Collect(maps.Keys(user)), "the user is keyed by column name")
			assert.Equal(t, "ada@example.com", user["email"])
			assert.Equal(t, false, user["email_verified"])
			assert.Equal(t, "https://example.com/a.png", user["image_url"])

			w = call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "the response carries a credential")
			var signedIn struct {
				User  *models.User `json:"user"`
				Token string       `json:"token"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &signedIn))
			require.NotNil(t, signedIn.User)
			assert.Equal(t, user["id"], signedIn.User.ID)

			var fromCookie string
			cookies := (&http.Response{Header: w.Header()}).Cookies()
			if tc.cookie == "" {
				assert.Empty(t, cookies, "no cookie")
			} else {
				require.Len(t, cookies, 1)
				assert.Equal(t, tc.cookie, cookies[0].Name)
				assert.True(t, cookies[0].HttpOnly)
				fromCookie = cookies[0].Value
			}
			fromHeader := w.Header().Get(types.SessionTokenHeader)
			assert.Equal(t, tc.header, fromHeader != "", "%s header", types.SessionTokenHeader)
			assert.Equal(t, tc.body, signedIn.Token != "", "token in the body: %s", w.Body.String())

			// Wherever it arrived, it is the session's token, and the route
			// behind RequireSession accepts it where this client sends it.
			signOut := mounted["/api/auth/sign-out"]
			assert.Equal(t, http.StatusUnauthorized, call(t, ac, signOut, "").Code, "without the token")
			var present map[string]string
			token := fromCookie
			switch {
			case tc.header:
				token = fromHeader
				present = map[string]string{"Authorization": "Bearer " + token}
			case tc.body:
				token = signedIn.Token
				present = map[string]string{"Authorization": "Bearer " + token}
			default:
				present = map[string]string{"Cookie": tc.cookie + "=" + token}
			}
			if tc.cookie != "" && tc.header {
				assert.Equal(t, fromCookie, fromHeader, "the cookie and the header carry one token")
				// A browser under both transports sends the cookie by
				// itself, next to the bearer token.
				present["Cookie"] = tc.cookie + "=" + token
			}
			session, err := ac.SessionManager.Validate(ctx, token)
			require.NoError(t, err)
			assert.Equal(t, signedIn.User.ID, session.UserID)
			out := callHeaders(t, ac, signOut, "", present)
			assert.Equal(t, http.StatusOK, out.Code)

			// The sign-out takes the token back. A browser can't drop an
			// HttpOnly cookie by itself, so the response replaces it with
			// an expired one. A client of the other transports holds the
			// token itself, and gets no cookie.
			gone := (&http.Response{Header: out.Header()}).Cookies()
			if tc.cookie == "" {
				assert.Empty(t, gone, "no cookie to remove")
			} else {
				require.Len(t, gone, 1)
				assert.Equal(t, tc.cookie, gone[0].Name)
				assert.Empty(t, gone[0].Value)
				assert.Negative(t, gone[0].MaxAge, "Max-Age=0 deletes the cookie")
			}
			assert.Empty(t, out.Header().Get(types.SessionTokenHeader), "a sign-out hands out no token")
		})
	}
}

// A session that ended in another request, here with all of its user's
// sessions, leaves its cookie in the browser. The next request to a route
// behind the session check is refused, and the refusal removes the cookie.
func TestASessionEndedElsewhereLosesItsCookie(t *testing.T) {
	ctx := context.Background()
	ac, mounted, err := bootPasswords(t, types.SessionConfig{}, nil)
	require.NoError(t, err)
	call(t, ac, mounted["/api/auth/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	w := call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	require.Len(t, cookies, 1)
	cookie := map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value}

	user, err := ac.Store.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, ac.SessionManager.RevokeAllForUser(ctx, user.ID, "signed_out_everywhere", ""))

	out := callHeaders(t, ac, mounted["/api/auth/sign-out"], "", cookie)
	assert.Equal(t, http.StatusUnauthorized, out.Code)
	assert.JSONEq(t, `{"error":"session has been revoked","code":"session_revoked"}`, out.Body.String())
	gone := (&http.Response{Header: out.Header()}).Cookies()
	require.Len(t, gone, 1, "the refusal removes the cookie: %q", out.Header().Values("Set-Cookie"))
	assert.Equal(t, cookies[0].Name, gone[0].Name)
	assert.Empty(t, gone[0].Value)
	assert.Negative(t, gone[0].MaxAge)

	// The browser has dropped it, so the next request is one without a
	// session.
	out = call(t, ac, mounted["/api/auth/sign-out"], "")
	assert.Equal(t, http.StatusUnauthorized, out.Code)
	assert.JSONEq(t, `{"error":"missing session token","code":"session_missing"}`, out.Body.String())
	assert.Empty(t, out.Header().Values("Set-Cookie"))
}

// A sign-out that a hook handler refused has ended nothing. The response
// leaves the cookie alone, because the client still needs it for a session
// that is live.
func TestRefusedSignOutKeepsTheCookie(t *testing.T) {
	refuse := func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignOutBefore, func(*types.HookContext, behemoth.M) (behemoth.M, error) {
			return nil, behemotherr.NewInvalidInputError("test", "session", "not now", nil)
		}, nil)
	}
	ac, mounted, err := bootPasswords(t, types.SessionConfig{}, refuse)
	require.NoError(t, err)
	call(t, ac, mounted["/api/auth/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	w := call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	require.Len(t, cookies, 1)

	out := callHeaders(t, ac, mounted["/api/auth/sign-out"], "", map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value})
	assert.Equal(t, http.StatusBadRequest, out.Code, out.Body.String())
	assert.Empty(t, out.Header().Values("Set-Cookie"), "the cookie is not removed")
	_, err = ac.SessionManager.Validate(context.Background(), cookies[0].Value)
	assert.NoError(t, err, "the session is still live")
}

// A sign-in that waits for a second factor answers with a status and no
// user. The pending session's token is delivered like any other: the client
// needs it to present the second factor.
func TestSignInPendingSecondFactorCarriesTheToken(t *testing.T) {
	ctx := context.Background()
	stepUp := func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(_ *types.HookContext, payload behemoth.M) (behemoth.M, error) {
			payload["requireStepUp"] = true
			return payload, nil
		}, nil)
	}
	for transport, read := range map[types.TokenTransport]func(w *httptest.ResponseRecorder, body map[string]any) string{
		types.TransportBody: func(_ *httptest.ResponseRecorder, body map[string]any) string {
			token, _ := body["token"].(string)
			return token
		},
		types.TransportHeader: func(w *httptest.ResponseRecorder, _ map[string]any) string {
			return w.Header().Get(types.SessionTokenHeader)
		},
	} {
		ac, mounted, err := bootPasswords(t, types.SessionConfig{Transport: transport}, stepUp)
		require.NoError(t, err)
		call(t, ac, mounted["/api/auth/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`)
		w := call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, "requires_second_factor", body["status"], transport)
		assert.NotContains(t, body, "user", "%s: the user is not signed in yet", transport)
		token := read(w, body)
		require.NotEmpty(t, token, "%s: %s", transport, w.Body.String())
		session, err := ac.SessionManager.Get(ctx, token)
		require.NoError(t, err, transport)
		assert.Equal(t, models.SessionPending, session.State, transport)
		if transport == types.TransportHeader {
			assert.NotContains(t, body, "token", "under the header transport the body has no token")
		}
	}
}

// The sign-out route sits behind RequireSession, which extends the cookie of
// a rolling session that is due. The sign-out then removes that cookie. The
// response sets it once, and what it sets is the removal.
func TestSignOutOfARollingSessionSetsTheCookieOnce(t *testing.T) {
	ac, mounted, err := bootPasswords(t, types.SessionConfig{ExpiresIn: time.Hour, UpdateAge: 2 * time.Hour}, nil) // always due
	require.NoError(t, err)
	call(t, ac, mounted["/api/auth/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	w := call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	require.Len(t, cookies, 1)

	out := callHeaders(t, ac, mounted["/api/auth/sign-out"], "", map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value})
	require.Equal(t, http.StatusOK, out.Code, out.Body.String())
	gone := (&http.Response{Header: out.Header()}).Cookies()
	require.Len(t, gone, 1, "one Set-Cookie for the session cookie: %q", out.Header().Values("Set-Cookie"))
	assert.Empty(t, gone[0].Value)
	assert.Negative(t, gone[0].MaxAge)
	_, err = ac.SessionManager.Validate(context.Background(), cookies[0].Value)
	assert.Error(t, err, "the session is revoked")
}

// A transport Boot does not know stops it, instead of leaving sign-in
// without a way to hand the token over.
func TestBootRefusesAnUnknownSessionTransport(t *testing.T) {
	_, _, err := bootPasswords(t, types.SessionConfig{Transport: "Header"}, nil)
	require.Error(t, err)
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	assert.Contains(t, err.Error(), "Transport")
}

// The three columns visibilityPlugin contributes to users.
var (
	planField = dbschema.Field[string]{Table: models.UserTable, Name: "plan"}
	betaField = dbschema.Field[bool]{Table: models.UserTable, Name: "beta"}
	riskField = dbschema.Field[string]{Table: models.UserTable, Name: "risk_note"}
)

// visibilityPlugin contributes two columns a client may see and one it may
// not, and fills them when a user is created.
type visibilityPlugin struct{}

func (visibilityPlugin) Meta() types.PluginMeta          { return types.PluginMeta{Name: "visibility"} }
func (visibilityPlugin) Version() string                 { return "0.0.0" }
func (visibilityPlugin) Init(*types.AuthContext) error   { return nil }
func (visibilityPlugin) Routes() []types.Route           { return nil }
func (visibilityPlugin) Middlewares() []types.Middleware { return nil }
func (visibilityPlugin) Declare(ic *types.PluginInitContext) error {
	for _, c := range []dbschema.ColumnContribution{
		planField.Contribution(dbschema.Column{Type: dbschema.ColTypeString, Length: 32, Nullable: true, Public: true}),
		betaField.Contribution(dbschema.Column{Type: dbschema.ColTypeBoolean, Nullable: true, Public: true}),
		riskField.Contribution(dbschema.Column{Type: dbschema.ColTypeText, Nullable: true}), // private: nothing to mark
	} {
		if err := ic.Schemas.ExtendColumn(c); err != nil {
			return err
		}
	}
	return nil
}
func (visibilityPlugin) Register(reg types.HookRegistry) error {
	return reg.OnBefore(hooks.HookUserBeforeCreate, func(_ *types.HookContext, row behemoth.M) (behemoth.M, error) {
		row[planField.Name], row[betaField.Name], row[riskField.Name] = "pro", true, "flagged: disposable email domain"
		return row, nil
	}, nil)
}

// Every route that returns a user answers with its public columns: the
// table's own, and the contributed columns their plugin marked Public, flat
// next to them and in their declared types. A contributed column that was
// not marked stays on the server, where its plugin still reads it.
func TestResponsesCarryOnlyPublicColumns(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "public.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema + `
ALTER TABLE users ADD COLUMN plan TEXT;
ALTER TABLE users ADD COLUMN beta BOOLEAN;
ALTER TABLE users ADD COLUMN risk_note TEXT;`)
	require.NoError(t, err)

	mail := &outbox{}
	mounted := mountedRoutes{}
	links := magiclink.New(magiclink.Options{LinkURL: "https://app.example.com/magic"})
	verification := emailverification.New(emailverification.Options{
		LinkURL:       "https://app.example.com/verify",
		ChangeLinkURL: "https://app.example.com/change",
		RevertLinkURL: "https://app.example.com/undo",
	})
	app, err := bmth.Prepare([]types.Plugin{emailpassword.New(emailpassword.Options{}), links, verification, visibilityPlugin{}}, bmth.PrepareConfig{})
	require.NoError(t, err)
	// The adapter is built with the resolver, so it reads the contributed
	// columns into the model.
	ac, err := bmth.Boot(ctx, app, sqliteAdapter.NewSQLiteAdapter(db, app.Resolver), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Mail: types.MailConfig{Sender: mail},
		HTTP: mounted,
	})
	require.NoError(t, err)
	t.Cleanup(func() { ac.Mailer.Close(context.Background()) })

	// lastMail waits for a message of kind and returns the latest.
	lastMail := func(kind types.MailKind) types.MailMessage {
		t.Helper()
		var found types.MailMessage
		require.Eventually(t, func() bool {
			mail.mu.Lock()
			defer mail.mu.Unlock()
			for i := len(mail.links) - 1; i >= 0; i-- {
				if mail.links[i].Kind == kind {
					found = mail.links[i]
					return true
				}
			}
			return false
		}, 5*time.Second, time.Millisecond, "no %s message", kind)
		return found
	}
	wantColumns := []string{"id", "email", "username", "firstname", "lastname", "email_verified", "image_url", "created_at", "updated_at", "plan", "beta"}
	check := func(route string, w *httptest.ResponseRecorder, wantStatus int) {
		t.Helper()
		require.Equal(t, wantStatus, w.Code, "%s: %s", route, w.Body.String())
		var body struct {
			User map[string]any `json:"user"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), route)
		assert.ElementsMatch(t, wantColumns, slices.Collect(maps.Keys(body.User)), "%s: the user's columns", route)
		assert.Equal(t, "pro", body.User["plan"], "%s: a public contributed column, next to the table's own", route)
		assert.Equal(t, true, body.User["beta"], "%s: a boolean, though SQLite returned 1", route)
		assert.NotContains(t, w.Body.String(), "flagged", "%s: the private column's value is nowhere in the response", route)
	}

	check("sign-up", call(t, ac, mounted["/api/auth/sign-up/email"], `{"email":"ada@example.com","password":"correct horse"}`), http.StatusCreated)
	check("sign-in", call(t, ac, mounted["/api/auth/sign-in/email"], `{"email":"ada@example.com","password":"correct horse"}`), http.StatusOK)

	verify := lastMail(types.MailEmailVerification)
	check("email verify", call(t, ac, mounted["/api/auth"+emailverification.PathVerify], `{"token":"`+verify.Token+`"}`), http.StatusOK)

	require.Equal(t, http.StatusOK, call(t, ac, mounted["/api/auth"+magiclink.PathRequest], `{"email":"ada@example.com"}`).Code)
	link := lastMail(types.MailMagicLink)
	check("magic link verify", call(t, ac, mounted["/api/auth"+magiclink.PathVerify], `{"token":"`+link.Token+`"}`), http.StatusOK)

	user, err := ac.Store.FindUserByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	_, err = verification.RequestChange(ctx, emailverification.ChangeRequest{UserID: user.ID, NewEmail: "ada@new.example.com"})
	require.NoError(t, err)
	change := lastMail(types.MailEmailChange)
	check("email change confirm", call(t, ac, mounted["/api/auth"+emailverification.PathChangeConfirm], `{"token":"`+change.Token+`"}`), http.StatusOK)

	// On the server the column is where it was: the plugin that owns it,
	// and any hook handler, still reads it from the model.
	stored, err := ac.Store.FindUserByID(ctx, user.ID)
	require.NoError(t, err)
	note, ok, err := riskField.Get(stored)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "flagged: disposable email domain", note)
	view, err := ac.Public.Of(stored)
	require.NoError(t, err)
	assert.NotContains(t, view, riskField.Name)
	assert.Equal(t, "pro", view[planField.Name])
}
