package plugins_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/core/hooks"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/httpapi"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/username"
	sqliteAdapter "github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// usernameSchema is the schema with the columns the plugin contributes.
const usernameSchema = magicLinkSchema + `
ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD COLUMN display_username TEXT;
CREATE UNIQUE INDEX users_username_key ON users (username);`

type usernameApp struct {
	ac        *core.AuthContext
	passwords *emailpassword.Plugin
	names     *username.Plugin
	routes    mountedRoutes
	db        *sql.DB
}

// bootUsernames boots the email/password and username plugins.
func bootUsernames(t *testing.T, opts username.Options, hookFn func(reg core.HookRegistry) error) *usernameApp {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "username.db")+"?_busy_timeout=10000&_txlock=immediate")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(usernameSchema)
	require.NoError(t, err)

	app := &usernameApp{routes: mountedRoutes{}, db: db}
	app.passwords = emailpassword.New(emailpassword.Options{})
	app.names = username.New(app.passwords, opts)
	// The username plugin is listed first: its dependency orders the two.
	prepared, err := engine.Prepare([]core.Plugin{app.names, app.passwords}, engine.PrepareConfig{})
	require.NoError(t, err)
	// The adapter is built with the resolver, so it reads and finds by the
	// contributed columns. The transactions take SQLite's write lock at
	// their start (_txlock=immediate): one that reads first and writes later
	// is refused with "database is locked" when another did the same, which
	// the concurrent sign-ups would hit.
	app.ac, err = engine.Boot(context.Background(), prepared, sqliteAdapter.NewSQLiteAdapter(db, prepared.Resolver), engine.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Router: httpapi.RouterConfig{Carrier: httpapi.TokenCarrierConfig{Delivery: httpapi.DeliveryHeader}},
		HTTP:   app.routes,
		Hooks:  hookFn,
	})
	require.NoError(t, err)
	return app
}

func (app *usernameApp) signUp(t *testing.T, email, name string) *models.User {
	t.Helper()
	in := behemoth.M{"email": email, "password": "correct horse"}
	if name != "" {
		in["username"] = name
	}
	user, err := app.passwords.SignUp(context.Background(), in)
	require.NoError(t, err)
	return user
}

func (app *usernameApp) nameOf(t *testing.T, userID string) (string, bool) {
	t.Helper()
	user, err := app.ac.Store.FindUserByID(context.Background(), userID)
	require.NoError(t, err)
	name, ok, err := username.Column.Get(user)
	require.NoError(t, err)
	return name, ok
}

func hasCode(err error, category errs.Category, code string) bool {
	return errs.IsCategory(err, category) && errs.IsCode(err, code)
}

// A sign-up stores the username in its stored form, and the user signs in
// with it in any casing, or with the email as before. Every refusal of a
// username sign-in is the email sign-in's one answer.
func TestUsernameSignUpAndSignIn(t *testing.T) {
	ctx := context.Background()
	var before []behemoth.M
	var beforeValues, failed []string
	var after []*core.SignInResult
	app := bootUsernames(t, username.Options{}, func(reg core.HookRegistry) error {
		if err := reg.OnBefore(hooks.HookSignInBefore, func(hctx *core.HookContext, p behemoth.M) (behemoth.M, error) {
			before = append(before, p)
			name, _ := hctx.Values[username.HookValueUsername].(string)
			beforeValues = append(beforeValues, name)
			return nil, nil
		}, nil); err != nil {
			return err
		}
		if err := reg.OnFailed(hooks.HookSignInFailed, func(_ *core.HookContext, reason core.FailureReason) error {
			failed = append(failed, reason.Code)
			return nil
		}, nil); err != nil {
			return err
		}
		return reg.OnAfter(hooks.HookSignInAfter, func(_ *core.HookContext, result any) error {
			after = append(after, result.(*core.SignInResult))
			return nil
		}, nil)
	})

	user := app.signUp(t, "ada@example.com", "  Ada_L ")
	name, ok, err := username.Column.Get(user)
	require.NoError(t, err)
	require.True(t, ok, "the sign-up's result carries the username")
	assert.Equal(t, "ada_l", name, "trimmed and lowercased")
	shown, _, err := username.DisplayColumn.Get(user)
	require.NoError(t, err)
	assert.Equal(t, "Ada_L", shown, "the display form is the username as it was typed")

	result, err := app.names.SignIn(ctx, username.Credentials{
		Username: "ADA_L", Password: "correct horse", Extra: behemoth.M{"captchaToken": "x"},
	})
	require.NoError(t, err)
	assert.Equal(t, user.ID, result.User.ID)
	assert.Equal(t, username.PluginName, result.Method)
	assert.NotEmpty(t, result.RawToken)
	assert.Equal(t, models.SessionActive, result.Session.State)

	require.Len(t, before, 1)
	assert.Equal(t, behemoth.M{"username": "ada_l", "password": "correct horse", "captchaToken": "x"}, before[0],
		"the before payload is flat, with the username where an email sign-in has the email")
	assert.Equal(t, []string{"ada_l"}, beforeValues, "the username is published for rate-limit rules")
	require.Len(t, after, 1)
	assert.Equal(t, username.PluginName, after[0].Method)

	// The email still signs in, through the email/password plugin.
	byEmail, err := app.passwords.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{Email: "ada@example.com", Password: "correct horse"})
	require.NoError(t, err)
	assert.Equal(t, emailpassword.PluginName, byEmail.Method)

	// A user without a password: created directly, with a username.
	passwordless := &models.User{Email: "grace@example.com"}
	require.NoError(t, username.Column.Set(passwordless, "grace"))
	require.NoError(t, app.ac.Store.CreateUser(ctx, passwordless))

	for attempt, tc := range map[string]struct {
		creds username.Credentials
		code  string
	}{
		"unknown username":        {username.Credentials{Username: "nobody", Password: "correct horse"}, "user_not_found"},
		"wrong password":          {username.Credentials{Username: "ada_l", Password: "wrong"}, "invalid_credentials"},
		"no password":             {username.Credentials{Username: "grace", Password: "correct horse"}, "no_credential_account"},
		"empty username":          {username.Credentials{Password: "correct horse"}, "user_not_found"},
		"the email as a username": {username.Credentials{Username: "ada@example.com", Password: "correct horse"}, "user_not_found"},
	} {
		failed = nil
		_, err := app.names.SignIn(ctx, tc.creds)
		require.Error(t, err, attempt)
		assert.True(t, hasCode(err, errs.CategoryUnauthorized, emailpassword.ErrorCodeInvalidCredentials), "%s: %v", attempt, err)
		var refusal *errs.DomainError
		require.ErrorAs(t, err, &refusal, attempt)
		assert.Equal(t, "invalid username or password", refusal.PublicMessage, attempt)
		assert.Equal(t, []string{tc.code}, failed, "%s: the failed point tells the refusals apart", attempt)
	}
}

// The rules are applied at sign-up, with the plugin's codes, and a refused
// sign-up creates no user.
func TestUsernameRulesAtSignUp(t *testing.T) {
	ctx := context.Background()
	var failed []string
	app := bootUsernames(t, username.Options{Reserved: []string{"Admin"}}, func(reg core.HookRegistry) error {
		return reg.OnFailed(hooks.HookSignUpFailed, func(_ *core.HookContext, reason core.FailureReason) error {
			failed = append(failed, reason.Code)
			return nil
		}, nil)
	})
	app.signUp(t, "ada@example.com", "ada")

	for name, code := range map[string]string{
		"ab":                    username.ErrorCodeInvalidUsername, // too short
		strings.Repeat("a", 31): username.ErrorCodeInvalidUsername, // too long
		"ada lovelace":          username.ErrorCodeInvalidUsername, // a space
		"ada@example.com":       username.ErrorCodeInvalidUsername, // an email address
		"_ada":                  username.ErrorCodeInvalidUsername, // starts with a symbol
		"ädä":                   username.ErrorCodeInvalidUsername, // not ASCII
		"admin":                 username.ErrorCodeInvalidUsername, // reserved, in any casing
		"ADA":                   username.ErrorCodeUsernameTaken,   // taken, in any casing
	} {
		failed = nil
		_, err := app.passwords.SignUp(ctx, behemoth.M{"email": "new@example.com", "password": "correct horse", "username": name})
		require.Error(t, err, name)
		assert.True(t, errs.IsCode(err, code), "%q: %v", name, err)
		assert.Equal(t, []string{"rejected_by_hook"}, failed, "%q: the sign-up's failed point fires", name)
		_, err = app.ac.Store.FindUserByEmail(ctx, "new@example.com")
		assert.True(t, errs.IsNotFound(err), "%q: no user was created", name)
	}
	_, err := app.passwords.SignUp(ctx, behemoth.M{"email": "new@example.com", "password": "correct horse", "username": 7})
	assert.True(t, hasCode(err, errs.CategoryValidation, username.ErrorCodeInvalidUsername), "a username that is not a string: %v", err)
	_, err = app.passwords.SignUp(ctx, behemoth.M{"email": "new@example.com", "password": "correct horse", "username": "ADA"})
	assert.True(t, errs.IsCategory(err, errs.CategoryConflict), "a taken username is a conflict: %v", err)

	// A username is optional, and any number of users go without one.
	first := app.signUp(t, "one@example.com", "")
	second := app.signUp(t, "two@example.com", "   ")
	for _, user := range []*models.User{first, second} {
		_, ok := app.nameOf(t, user.ID)
		assert.False(t, ok, "no value is stored for a user without a username")
	}
	var stored sql.NullString
	require.NoError(t, app.db.QueryRow(`SELECT username FROM users WHERE id = ?`, first.ID).Scan(&stored))
	assert.False(t, stored.Valid, "the column is NULL, not an empty string")
}

func TestUsernameRequiredAtSignUp(t *testing.T) {
	ctx := context.Background()
	app := bootUsernames(t, username.Options{RequireAtSignUp: true}, nil)

	_, err := app.passwords.SignUp(ctx, behemoth.M{"email": "ada@example.com", "password": "correct horse"})
	assert.True(t, hasCode(err, errs.CategoryValidation, username.ErrorCodeInvalidUsername), "%v", err)
	app.signUp(t, "ada@example.com", "ada")

	// The option is about sign-up. A user created another way needs none.
	require.NoError(t, app.ac.Store.CreateUser(ctx, &models.User{Email: "grace@example.com"}))
}

// The rules hold for every write of a user, not for sign-up alone.
func TestUsernameRulesOnDirectWrites(t *testing.T) {
	ctx := context.Background()
	app := bootUsernames(t, username.Options{}, nil)
	ada := app.signUp(t, "ada@example.com", "ada")
	grace := app.signUp(t, "grace@example.com", "")

	updated, err := app.names.SetUsername(asAdmin(ctx), grace.ID, " Grace.H ")
	require.NoError(t, err)
	name, _, err := username.Column.Get(updated)
	require.NoError(t, err)
	assert.Equal(t, "grace.h", name)

	_, err = app.names.SetUsername(asAdmin(ctx), grace.ID, "ADA")
	assert.True(t, hasCode(err, errs.CategoryConflict, username.ErrorCodeUsernameTaken), "%v", err)
	_, err = app.names.SetUsername(asAdmin(ctx), grace.ID, "no spaces")
	assert.True(t, hasCode(err, errs.CategoryValidation, username.ErrorCodeInvalidUsername), "%v", err)
	_, err = app.ac.Store.UpdateUser(ctx, grace.ID, behemoth.M{username.Column.Name: "ada"})
	assert.True(t, errs.IsCode(err, username.ErrorCodeUsernameTaken), "Store.UpdateUser goes through the same handler: %v", err)
	name, _ = app.nameOf(t, grace.ID)
	assert.Equal(t, "grace.h", name, "a refused update changes nothing")

	// Setting the name a user already holds is not a conflict with itself,
	// and an update of another column is left alone.
	_, err = app.names.SetUsername(asAdmin(ctx), ada.ID, "Ada")
	require.NoError(t, err)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{models.UserFirstname: "Ada"})
	require.NoError(t, err)
	name, _ = app.nameOf(t, ada.ID)
	assert.Equal(t, "ada", name)

	// A create that carries the username on the row.
	direct := &models.User{Email: "linus@example.com"}
	require.NoError(t, username.Column.Set(direct, "Ada"))
	err = app.ac.Store.CreateUser(ctx, direct)
	assert.True(t, errs.IsCode(err, username.ErrorCodeUsernameTaken), "%v", err)

	// An empty username removes it, and the name is free again.
	_, err = app.names.SetUsername(asAdmin(ctx), grace.ID, "")
	require.NoError(t, err)
	_, ok := app.nameOf(t, grace.ID)
	assert.False(t, ok)
	_, err = app.names.SignIn(ctx, username.Credentials{Username: "grace.h", Password: "correct horse"})
	assert.True(t, errs.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "%v", err)
	_, err = app.names.SetUsername(asAdmin(ctx), ada.ID, "grace.h")
	require.NoError(t, err)
	result, err := app.names.SignIn(ctx, username.Credentials{Username: "grace.h", Password: "correct horse"})
	require.NoError(t, err)
	assert.Equal(t, ada.ID, result.User.ID)
}

// Two sign-ups racing for one username: one user holds it afterwards.
func TestUsernameIsUniqueUnderConcurrentSignUps(t *testing.T) {
	ctx := context.Background()
	app := bootUsernames(t, username.Options{}, nil)

	const racers = 6
	results := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = app.passwords.SignUp(ctx, behemoth.M{
				"email": string(rune('a'+i)) + "@example.com", "password": "correct horse", "username": "ada",
			})
		}()
	}
	wg.Wait()

	won := 0
	for _, err := range results {
		if err == nil {
			won++
			continue
		}
		assert.True(t, hasCode(err, errs.CategoryConflict, username.ErrorCodeUsernameTaken), "a loser is refused with username_taken: %v", err)
	}
	assert.Equal(t, 1, won)
	var holders int
	require.NoError(t, app.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'ada'`).Scan(&holders))
	assert.Equal(t, 1, holders)
}

// The route answers in the shape every sign-in route does, and the sign-up
// route takes the username and returns it with the user.
func TestUsernameRoutes(t *testing.T) {
	app := bootUsernames(t, username.Options{}, nil)
	signUp, signIn := app.routes["/api/auth/sign-up/email"], app.routes["/api/auth"+username.PathSignIn]
	require.NotNil(t, signIn.Handler, "the route is mounted next to the email sign-in")

	w := call(t, app.ac, signUp, `{"email":"ada@example.com","password":"correct horse","username":"Ada"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var body struct {
		User  map[string]any `json:"user"`
		Token string         `json:"token"`
		Code  string         `json:"code"`
		Error string         `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "ada", body.User["username"], "the column is public")

	w = call(t, app.ac, signUp, `{"email":"grace@example.com","password":"correct horse","username":"ADA"}`)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, username.ErrorCodeUsernameTaken, body.Code)

	w = call(t, app.ac, signUp, `{"email":"grace@example.com","password":"correct horse","username":"a b"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, username.ErrorCodeInvalidUsername, body.Code)

	w = call(t, app.ac, signIn, `{"username":"Ada","password":"correct horse","captchaToken":"x"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.NotEmpty(t, w.Header().Get("Set-Auth-Token"), "the token travels by the configured delivery")
	body.User = nil
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "ada@example.com", body.User["email"])
	assert.Equal(t, "ada", body.User["username"])

	for name, tc := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"wrong password":   {`{"username":"ada","password":"nope"}`, http.StatusUnauthorized, emailpassword.ErrorCodeInvalidCredentials},
		"unknown username": {`{"username":"nobody","password":"correct horse"}`, http.StatusUnauthorized, emailpassword.ErrorCodeInvalidCredentials},
		"no username":      {`{"password":"correct horse"}`, http.StatusUnauthorized, emailpassword.ErrorCodeInvalidCredentials},
		"not a string":     {`{"username":7,"password":"correct horse"}`, http.StatusBadRequest, username.ErrorCodeInvalidUsername},
		"not JSON":         {`{`, http.StatusBadRequest, "request_validation_error"},
	} {
		w := call(t, app.ac, signIn, tc.body)
		require.Equal(t, tc.status, w.Code, "%s: %s", name, w.Body.String())
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), name)
		assert.Equal(t, tc.code, body.Code, name)
	}
}

// A second factor asked for at the shared checkpoint applies to a sign-in
// by username too: the password check is the email/password plugin's.
func TestUsernameSignInPassesTheSecondFactorCheckpoint(t *testing.T) {
	var factor any
	app := bootUsernames(t, username.Options{}, func(reg core.HookRegistry) error {
		return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(_ *core.HookContext, p behemoth.M) (behemoth.M, error) {
			factor = p[hooks.HookValueFactor]
			p[hooks.HookValueRequireStepUp] = true
			return p, nil
		}, nil)
	})
	app.signUp(t, "ada@example.com", "ada")
	result, err := app.names.SignIn(context.Background(), username.Credentials{Username: "ada", Password: "correct horse"})
	require.NoError(t, err)
	assert.Equal(t, models.SessionPending, result.Session.State)
	assert.Equal(t, core.FactorPassword, factor)
	assert.Equal(t, []string{core.FactorPassword}, result.Session.Factors)
}

// An application's rule per username counts sign-ins by username, from the
// route and from code, for a known and an unknown name alike.
func TestUsernameSignInsCanBeLimitedPerUsername(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "limit.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(usernameSchema)
	require.NoError(t, err)

	passwords := emailpassword.New(emailpassword.Options{})
	names := username.New(passwords, username.Options{})
	prepared, err := engine.Prepare([]core.Plugin{passwords, names, perUsernameLimit{}}, engine.PrepareConfig{})
	require.NoError(t, err)
	_, err = engine.Boot(ctx, prepared, sqliteAdapter.NewSQLiteAdapter(db, prepared.Resolver), engine.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		HTTP: mountedRoutes{},
	})
	require.NoError(t, err)

	for _, name := range []string{"Nobody", "nobody "} {
		_, err = names.SignIn(ctx, username.Credentials{Username: name, Password: "x"})
		assert.True(t, errs.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "%v", err)
	}
	_, err = names.SignIn(ctx, username.Credentials{Username: "NOBODY", Password: "x"})
	assert.True(t, errs.IsCategory(err, errs.CategoryRateLimited), "the third attempt on one username, in any casing: %v", err)
	_, err = names.SignIn(ctx, username.Credentials{Username: "someone", Password: "x"})
	assert.True(t, errs.IsCode(err, emailpassword.ErrorCodeInvalidCredentials), "another username has its own count: %v", err)
}

// perUsernameLimit declares the rule an application would: two sign-in
// attempts per username.
type perUsernameLimit struct{}

func (perUsernameLimit) Meta() core.PluginMeta             { return core.PluginMeta{Name: "per-username"} }
func (perUsernameLimit) Version() string                   { return "0.0.0" }
func (perUsernameLimit) Init(*core.AuthContext) error      { return nil }
func (perUsernameLimit) Routes() []httpapi.Route           { return nil }
func (perUsernameLimit) Middlewares() []httpapi.Middleware { return nil }
func (perUsernameLimit) Register(core.HookRegistry) error  { return nil }
func (perUsernameLimit) Declare(ic *core.PluginInitContext) error {
	return ic.RateLimits.DeclareHookRateLimitRule(core.HookRateLimitRule{
		Name: "per-username.signin", Point: hooks.HookSignInBefore,
		KeyFunc: core.KeyByValues(username.HookValueUsername), Limit: core.Limit{Max: 2, Window: time.Minute},
	})
}

func TestUsernameOptionsAndWiring(t *testing.T) {
	ctx := context.Background()
	passwords := emailpassword.New(emailpassword.Options{})

	meta := username.New(passwords, username.Options{}).Meta()
	assert.Equal(t, username.PluginName, meta.Name)
	assert.Equal(t, []core.PluginDependency{{Name: emailpassword.PluginName}}, meta.Dependencies)

	// The email/password plugin has to be installed.
	_, err := engine.Prepare([]core.Plugin{username.New(passwords, username.Options{})}, engine.PrepareConfig{})
	require.Error(t, err)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%v", err)

	for name, p := range map[string]*username.Plugin{
		"no email/password plugin": username.New(nil, username.Options{}),
		"min above max":            username.New(passwords, username.Options{MinLength: 10, MaxLength: 5}),
		"negative min":             username.New(passwords, username.Options{MinLength: -1}),
		"max above the column":     username.New(passwords, username.Options{MaxLength: username.MaxColumnLength + 1}),
	} {
		err := p.Init(&core.AuthContext{})
		require.Error(t, err, name)
		assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%s: %v", name, err)
	}

	// Before Boot the flows report that the plugin is not initialized.
	unbooted := username.New(passwords, username.Options{})
	_, err = unbooted.SignIn(ctx, username.Credentials{Username: "ada", Password: "x"})
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%v", err)
	_, err = unbooted.SetUsername(asAdmin(ctx), "id", "ada")
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%v", err)

	// SignInWith refuses credentials that can't name an identifier.
	app := bootUsernames(t, username.Options{MinLength: 2, MaxLength: 4}, nil)
	_, err = app.passwords.SignInWith(ctx, emailpassword.IdentifierCredentials{Key: "password", Value: "x"})
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%v", err)
	_, err = app.passwords.SignInWith(ctx, emailpassword.IdentifierCredentials{Key: "handle", Value: "x"})
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "no Find: %v", err)

	// The limits are the options'.
	_, err = app.names.Validate("ab")
	require.NoError(t, err)
	_, err = app.names.Validate("abcde")
	assert.True(t, errs.IsCode(err, username.ErrorCodeInvalidUsername), "%v", err)
}

func (app *usernameApp) shownAs(t *testing.T, userID string) (string, bool) {
	t.Helper()
	user, err := app.ac.Store.FindUserByID(context.Background(), userID)
	require.NoError(t, err)
	shown, ok, err := username.DisplayColumn.Get(user)
	require.NoError(t, err)
	return shown, ok
}

// The display username is how the username is spelled for showing. It
// follows the username, can be given with it or changed alone, and never
// spells another name.
func TestDisplayUsername(t *testing.T) {
	ctx := context.Background()
	app := bootUsernames(t, username.Options{}, nil)
	invalidDisplay := func(err error) bool {
		return hasCode(err, errs.CategoryValidation, username.ErrorCodeInvalidDisplayUsername)
	}

	// Given at sign-up next to the username.
	ada, err := app.passwords.SignUp(ctx, behemoth.M{
		"email": "ada@example.com", "password": "correct horse", "username": "ada_l", "display_username": " Ada_L ",
	})
	require.NoError(t, err)
	shown, _ := app.shownAs(t, ada.ID)
	assert.Equal(t, "Ada_L", shown)
	name, _ := app.nameOf(t, ada.ID)
	assert.Equal(t, "ada_l", name)

	// Refused at sign-up: another name, a display form without a username,
	// a value that is not a string. No user is created.
	for attempt, in := range map[string]behemoth.M{
		"another name": {"username": "grace", "display_username": "Ada_L"},
		"no username":  {"display_username": "Grace"},
		"not a string": {"username": "grace", "display_username": 7},
	} {
		in["email"], in["password"] = "grace@example.com", "correct horse"
		_, err := app.passwords.SignUp(ctx, in)
		assert.True(t, invalidDisplay(err), "%s: %v", attempt, err)
		_, err = app.ac.Store.FindUserByEmail(ctx, "grace@example.com")
		assert.True(t, errs.IsNotFound(err), "%s: no user was created", attempt)
	}

	// A user without a username has no display form.
	grace := app.signUp(t, "grace@example.com", "")
	_, ok := app.shownAs(t, grace.ID)
	assert.False(t, ok)
	var stored sql.NullString
	require.NoError(t, app.db.QueryRow(`SELECT display_username FROM users WHERE id = ?`, grace.ID).Scan(&stored))
	assert.False(t, stored.Valid, "the column is NULL")
	_, err = app.ac.Store.UpdateUser(ctx, grace.ID, behemoth.M{username.DisplayColumn.Name: "Grace"})
	assert.True(t, invalidDisplay(err), "a display form needs a username: %v", err)

	// Changed alone: another casing passes, another name does not, and an
	// empty one puts the stored form back.
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{username.DisplayColumn.Name: "ADA_L"})
	require.NoError(t, err)
	shown, _ = app.shownAs(t, ada.ID)
	assert.Equal(t, "ADA_L", shown)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{username.DisplayColumn.Name: "Grace"})
	assert.True(t, invalidDisplay(err), "%v", err)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{username.DisplayColumn.Name: ""})
	require.NoError(t, err)
	shown, _ = app.shownAs(t, ada.ID)
	assert.Equal(t, "ada_l", shown)
	name, _ = app.nameOf(t, ada.ID)
	assert.Equal(t, "ada_l", name, "the username is untouched by a display change")

	// A new username brings its display form, and removing it removes both.
	_, err = app.names.SetUsername(asAdmin(ctx), ada.ID, "Countess.Ada")
	require.NoError(t, err)
	name, _ = app.nameOf(t, ada.ID)
	shown, _ = app.shownAs(t, ada.ID)
	assert.Equal(t, "countess.ada", name)
	assert.Equal(t, "Countess.Ada", shown)
	_, err = app.ac.Store.UpdateUser(ctx, ada.ID, behemoth.M{username.Column.Name: "ada", username.DisplayColumn.Name: "Grace"})
	assert.True(t, invalidDisplay(err), "both set together still have to agree: %v", err)
	_, err = app.names.SetUsername(asAdmin(ctx), ada.ID, "")
	require.NoError(t, err)
	_, ok = app.shownAs(t, ada.ID)
	assert.False(t, ok)

	// A create that carries both on the row.
	direct := &models.User{Email: "linus@example.com"}
	require.NoError(t, username.Column.Set(direct, "linus"))
	require.NoError(t, username.DisplayColumn.Set(direct, "LINUS"))
	require.NoError(t, app.ac.Store.CreateUser(ctx, direct))
	shown, _ = app.shownAs(t, direct.ID)
	assert.Equal(t, "LINUS", shown)
}

// Available answers for a free, a taken and a reserved username, and
// refuses one that could never be stored. The route exists only when the
// option asks for it.
func TestUsernameAvailability(t *testing.T) {
	ctx := context.Background()
	off := bootUsernames(t, username.Options{}, nil)
	_, mounted := off.routes["/api/auth"+username.PathAvailable]
	assert.False(t, mounted, "the route is off by default")
	free, err := off.names.Available(ctx, "ada")
	require.NoError(t, err)
	assert.True(t, free, "the flow works without the route")

	app := bootUsernames(t, username.Options{AvailabilityRoute: true, Reserved: []string{"admin"}}, nil)
	app.signUp(t, "ada@example.com", "Ada")
	for name, want := range map[string]bool{"grace": true, " Grace ": true, "ada": false, "ADA": false, "Admin": false} {
		got, err := app.names.Available(ctx, name)
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
	_, err = app.names.Available(ctx, "a b")
	assert.True(t, hasCode(err, errs.CategoryValidation, username.ErrorCodeInvalidUsername), "%v", err)
	_, err = username.New(app.passwords, username.Options{}).Available(ctx, "ada")
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "before Boot: %v", err)

	route := app.routes["/api/auth"+username.PathAvailable]
	require.NotNil(t, route.Handler)
	for body, want := range map[string]string{
		`{"username":"grace"}`: `{"available":true}`,
		`{"username":"Ada"}`:   `{"available":false}`,
		`{"username":"admin"}`: `{"available":false}`,
	} {
		w := call(t, app.ac, route, body)
		require.Equal(t, http.StatusOK, w.Code, "%s: %s", body, w.Body.String())
		assert.JSONEq(t, want, w.Body.String(), body)
	}
	for _, body := range []string{`{"username":"a b"}`, `{"username":7}`, `{}`} {
		w := call(t, app.ac, route, body)
		require.Equal(t, http.StatusBadRequest, w.Code, "%s: %s", body, w.Body.String())
		assert.Contains(t, w.Body.String(), username.ErrorCodeInvalidUsername, body)
	}
	assert.Equal(t, http.StatusBadRequest, call(t, app.ac, route, `{`).Code)
}
