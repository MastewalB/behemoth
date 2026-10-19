// Package username is the username plugin: it gives users a unique username
// and lets them sign in with it and their password instead of their email.
//
// It builds on the email/password plugin (plugins/emailpassword) and depends
// on it. That plugin still owns the password: this one adds the username
// column to users, applies the username rules wherever a user row is
// written, and signs in through emailpassword.Plugin.SignInWith, which looks
// the user up by username and does the rest as an email sign-in does.
//
// Sign-up needs no route of its own. A "username" field in the body of the
// email/password plugin's sign-up is picked up by this plugin's handlers.
package username

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/schema"
	"github.com/MastewalB/behemoth/store"
)

// PluginName is the name the plugin registers under (PluginMeta.Name). It
// owns the plugin's route, column, handlers and rate-limit rule, and is the
// Method of the sign-ins it makes.
const PluginName = "username"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// Column is the username column the plugin contributes to users: unique,
// nullable and public. It holds the username in its stored form (Normalize),
// and no value for a user without one. Read it with Column.Get(user); write
// it with Plugin.SetUsername, or with Column.Update and Store.UpdateUser.
var Column = schema.Field[string]{Table: models.UserTable, Name: "username"}

// DisplayColumn is the second column the plugin contributes to users: the
// username as the user typed it, such as "Ada_L" for the username "ada_l".
// It is nullable and public, and is for showing; sign-in and uniqueness use
// Column. It always spells the user's username, in some casing, and has no
// value for a user without one.
var DisplayColumn = schema.Field[string]{Table: models.UserTable, Name: "display_username"}

// Username length limits. MaxColumnLength is the column's length, and so
// the upper bound of Options.MaxLength.
const (
	DefaultMinLength = 3
	DefaultMaxLength = 30
	MaxColumnLength  = 64
)

// Paths of the plugin's routes, below the router's base path. PathAvailable
// is mounted only with Options.AvailabilityRoute.
const (
	PathSignIn    = "/sign-in/username"
	PathAvailable = "/username/available"
)

// Names of the rate-limit rules the plugin declares, both per client
// address: sign-in attempts, like core's rule on the email sign-in route,
// and availability checks, which bounds how fast one client can list the
// usernames that exist.
const (
	RuleSignInRoute    = "username.signin.route"
	RuleAvailableRoute = "username.available.route"
)

// HookValueUsername is the key a sign-in's username is published under in
// HookContext.Values, in its stored form. A rate-limit rule on
// auth.signIn.before counts sign-ins per username with
// core.KeyByValues(username.HookValueUsername). It is also the key of the
// username in the auth.signIn.before and auth.signUp.before payloads and in
// the request bodies.
const HookValueUsername = "username"

const (
	keyPassword  = "password"
	keyAvailable = "available"
)

// valueSignUpUsername is the note the plugin's auth.signUp.before handler
// leaves in the sign-up's Values for its data.user.beforeCreate handler: the
// username the sign-up asked for, checked and in its stored form.
// valueSignUpDisplay is the display form that goes with it.
const (
	valueSignUpUsername = PluginName + ".signUp"
	valueSignUpDisplay  = PluginName + ".signUpDisplay"
)

// Codes of the errors the plugin rejects a username with. A client tells
// them apart by the code, not by the message.
const (
	// ErrorCodeInvalidUsername is the code of the validation error (400) for
	// a username that is not a string, breaks the plugin's rules, is
	// reserved, or is missing at a sign-up that requires one.
	ErrorCodeInvalidUsername = "username_invalid_input"
	// ErrorCodeInvalidDisplayUsername is the code of the validation error
	// (400) for a display username that is not a string or does not spell
	// the user's username.
	ErrorCodeInvalidDisplayUsername = "display_username_invalid_input"
	// ErrorCodeUsernameTaken is the code of the conflict error (409) for a
	// username another user holds.
	ErrorCodeUsernameTaken = "username_taken"
)

// Options configures the plugin. The zero value is usable.
type Options struct {
	// MinLength and MaxLength bound a username's length in characters. Zero
	// means the default (3 and 30). MaxLength can't exceed MaxColumnLength.
	// Like the password limits, they apply where a username is set and not
	// at sign-in.
	MinLength int
	MaxLength int

	// Reserved lists usernames nobody may take, such as "admin" or
	// "support". They are compared in stored form, so "Admin" is covered by
	// "admin".
	Reserved []string

	// RequireAtSignUp refuses a sign-up that names no username. By default
	// a username is optional, and a user without one signs in by email.
	RequireAtSignUp bool

	// AvailabilityRoute mounts POST /username/available, which says whether
	// a username is free. It is off by default: the route tells anyone who
	// asks which usernames exist. Plugin.Available works either way.
	AvailabilityRoute bool
}

// Plugin is the username plugin. It contributes the username column to
// users, registers handlers that apply the username rules to every write of
// a user, adds the sign-in route and declares its rate-limit rule. It fires
// no points of its own: a sign-in by username fires core's auth.signIn.*
// points through the email/password plugin.
type Plugin struct {
	opts        Options
	passwords   *emailpassword.Plugin
	reserved    map[string]bool
	authContext *core.AuthContext
}

// New returns the plugin configured with opts. passwords is the
// email/password plugin of the same application, the one passed to Prepare:
// sign-in by username runs through it. Limits left at zero take their
// defaults. A missing plugin and limits that can't work are reported by
// Init, as a configuration error from Boot.
func New(passwords *emailpassword.Plugin, opts Options) *Plugin {
	if opts.MinLength == 0 {
		opts.MinLength = DefaultMinLength
	}
	if opts.MaxLength == 0 {
		opts.MaxLength = DefaultMaxLength
	}
	reserved := make(map[string]bool, len(opts.Reserved))
	for _, name := range opts.Reserved {
		reserved[Normalize(name)] = true
	}
	return &Plugin{opts: opts, passwords: passwords, reserved: reserved}
}

// Meta implements [core.Plugin]. The plugin depends on the email/password
// plugin, so that plugin is initialized first. It has no mount path: its
// route sits next to /sign-in/email.
func (p *Plugin) Meta() core.PluginMeta {
	return core.PluginMeta{
		Name:         PluginName,
		Dependencies: []core.PluginDependency{{Name: emailpassword.PluginName}},
	}
}

// Version implements [core.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [core.Plugin]. The plugin declares:
//   - the username column on users (Column). It is nullable, so a user
//     without a username holds no value and the unique constraint allows any
//     number of them, and so that a version of the application without the
//     plugin can still insert users;
//   - the display username column (DisplayColumn), nullable for the same
//     reasons;
//   - a rate-limit rule per client address on each of its routes: sign-in
//     attempts and, with Options.AvailabilityRoute, availability checks.
//
// It declares no hook points, no token kind and no rule per username. A
// limit per username would let anyone keep a user out by failing on purpose;
// an application that wants one declares it on auth.signIn.before with
// HookValueUsername.
func (p *Plugin) Declare(ic *core.PluginInitContext) error {
	if err := ic.Schemas.ExtendColumn(Column.Contribution(schema.Column{
		Type: schema.ColTypeString, Length: MaxColumnLength, Nullable: true, Unique: true, Public: true,
	})); err != nil {
		return err
	}
	if err := ic.Schemas.ExtendColumn(DisplayColumn.Contribution(schema.Column{
		Type: schema.ColTypeString, Length: MaxColumnLength, Nullable: true, Public: true,
	})); err != nil {
		return err
	}
	byAddress := func(_ *http.Request, ip string) string { return ip }
	if err := ic.RateLimits.DeclareRouteRateLimitRule(core.RouteRateLimitRule{
		Name: RuleSignInRoute, Method: http.MethodPost, Path: PathSignIn,
		KeyFunc: byAddress, Limit: core.Limit{Max: 10, Window: time.Minute},
	}); err != nil {
		return err
	}
	if !p.opts.AvailabilityRoute {
		return nil
	}
	// More generous than sign-in: a form checks as the user types.
	return ic.RateLimits.DeclareRouteRateLimitRule(core.RouteRateLimitRule{
		Name: RuleAvailableRoute, Method: http.MethodPost, Path: PathAvailable,
		KeyFunc: byAddress, Limit: core.Limit{Max: 30, Window: time.Minute},
	})
}

// Register implements [core.Plugin]. The rules are applied where a user row
// is written, so they hold for every way of writing one: a sign-up, a
// Store.UpdateUser from the application, another plugin.
//   - auth.signUp.before: the sign-up's "username" and "display_username"
//     are checked before the password is hashed, and kept for the create;
//   - data.user.beforeCreate: the username is checked, refused when another
//     user holds it, and stored in its stored form, with its display form
//     next to it;
//   - data.user.beforeUpdate: the same for an update that sets the username.
//     An empty one removes both. An update of the display form alone has to
//     spell the username the user has.
func (p *Plugin) Register(reg core.HookRegistry) error {
	if err := reg.OnBefore(hooks.HookSignUpBefore, p.onSignUp, nil); err != nil {
		return err
	}
	if err := reg.OnBefore(hooks.HookUserBeforeCreate, p.onUserCreate, nil); err != nil {
		return err
	}
	return reg.OnBefore(hooks.HookUserBeforeUpdate, p.onUserUpdate, nil)
}

// Middlewares implements [core.Plugin]. The plugin has no middleware.
func (p *Plugin) Middlewares() []core.Middleware {
	return nil
}

// Init implements [core.Plugin]. It checks the options and keeps the
// AuthContext.
func (p *Plugin) Init(ac *core.AuthContext) error {
	const op = "username.Init"
	if p.passwords == nil {
		return errs.NewConfigurationError(op, "no email/password plugin was given to New; sign-in by username runs through it", nil)
	}
	if p.opts.MinLength < 1 || p.opts.MaxLength < p.opts.MinLength || p.opts.MaxLength > MaxColumnLength {
		return errs.NewConfigurationError(op,
			fmt.Sprintf("username length limits are invalid: min %d, max %d (the column holds %d)", p.opts.MinLength, p.opts.MaxLength, MaxColumnLength), nil)
	}
	p.authContext = ac
	return nil
}

// Routes implements [core.Plugin]. The availability route is added only
// with Options.AvailabilityRoute.
func (p *Plugin) Routes() []core.Route {
	routes := []core.Route{
		{Method: http.MethodPost, Path: PathSignIn, Handler: p.handleSignIn},
	}
	if p.opts.AvailabilityRoute {
		routes = append(routes, core.Route{Method: http.MethodPost, Path: PathAvailable, Handler: p.handleAvailable})
	}
	return routes
}

// Normalize returns username in its stored form: trimmed and lowercased.
// Usernames are compared in this form, so "Ada" and "ada" are one username.
// The form a user typed is kept next to it, in DisplayColumn.
func Normalize(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// Validate applies the plugin's rules to username and returns its stored
// form. A username is MinLength to MaxLength characters of a to z, 0 to 9,
// "_" and ".", starts with a letter or a digit, and is not reserved. An "@"
// is not allowed, so a username is never mistaken for an email address. The
// error is a validation error with ErrorCodeInvalidUsername. Validate does
// not check whether the username is taken.
func (p *Plugin) Validate(username string) (string, error) {
	name, err := p.wellFormed(username)
	if err != nil {
		return "", err
	}
	if p.reserved[name] {
		return "", errInvalidUsername("this username is not available")
	}
	return name, nil
}

// wellFormed applies the rules about a username's shape, its length and its
// characters, and returns its stored form. Validate adds the reserved names.
func (p *Plugin) wellFormed(username string) (string, error) {
	name := Normalize(username)
	if n := len(name); n < p.opts.MinLength || n > p.opts.MaxLength {
		return "", errInvalidUsername(fmt.Sprintf("username must be %d to %d characters long", p.opts.MinLength, p.opts.MaxLength))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alphanumeric := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alphanumeric && (i == 0 || (c != '_' && c != '.')) {
			return "", errInvalidUsername(`username may hold letters, digits, "_" and ".", and starts with a letter or a digit`)
		}
	}
	return name, nil
}

// errInvalidUsername is the plugin's validation error (400). The messages
// are the plugin's own and describe the rule, so they are sent to the
// client.
func errInvalidUsername(message string) error {
	return errs.NewInvalidInputError("username.Validate", HookValueUsername, message, nil)
}

// errInvalidDisplay is the validation error (400) for a display username.
func errInvalidDisplay(message string) error {
	return errs.NewInvalidInputError("username.Validate", DisplayColumn.Name, message, nil)
}

// errUsernameTaken is the plugin's typed conflict (409).
func errUsernameTaken() error {
	const op, message = "username.Validate", "this username is taken"
	return &errs.DomainError{
		Category: errs.CategoryConflict, Op: op, Code: ErrorCodeUsernameTaken,
		PublicMessage: message, InternalMessage: op + ": " + message,
	}
}

// onSignUp handles auth.signUp.before. The email/password plugin stores
// only its own profile fields, so the username and its display form travel
// from here to the user's create in the operation's Values.
func (p *Plugin) onSignUp(hctx *core.HookContext, payload behemoth.M) (behemoth.M, error) {
	delete(hctx.Values, valueSignUpUsername) // an enclosing sign-up's, if any
	delete(hctx.Values, valueSignUpDisplay)
	name, display, err := p.resolve(payload[Column.Name], payload[DisplayColumn.Name])
	if err != nil {
		return nil, err
	}
	if name == "" {
		if p.opts.RequireAtSignUp {
			return nil, errInvalidUsername("a username is required")
		}
		return nil, nil
	}
	hctx.Values[valueSignUpUsername], hctx.Values[valueSignUpDisplay] = name, display
	return nil, nil
}

// onUserCreate handles data.user.beforeCreate. A username already on the
// row (set by the code that creates the user) is used, and otherwise the one
// a sign-up left in Values. A row without one is stored without a value in
// either column.
func (p *Plugin) onUserCreate(hctx *core.HookContext, row behemoth.M) (behemoth.M, error) {
	rawName, rawDisplay := row[Column.Name], row[DisplayColumn.Name]
	if rawName == nil || rawName == "" {
		if noted, ok := hctx.Values[valueSignUpUsername]; ok {
			rawName, rawDisplay = noted, hctx.Values[valueSignUpDisplay]
		}
	}
	name, display, err := p.resolve(rawName, rawDisplay)
	if err != nil {
		return nil, err
	}
	if name == "" {
		// No value, not an empty string: the username column is unique.
		delete(row, Column.Name)
		delete(row, DisplayColumn.Name)
		return row, nil
	}
	if err := p.free(hctx, name, ""); err != nil {
		return nil, err
	}
	row[Column.Name], row[DisplayColumn.Name] = name, display
	return row, nil
}

// onUserUpdate handles data.user.beforeUpdate. An update that names neither
// column is left alone. One that sets the username sets the display form
// with it, and an empty or nil username removes both. One that sets the
// display form alone changes how the user's username is spelled, and an
// empty one puts the stored form back.
func (p *Plugin) onUserUpdate(hctx *core.HookContext, changes behemoth.M) (behemoth.M, error) {
	rawName, naming := changes[Column.Name]
	rawDisplay, displaying := changes[DisplayColumn.Name]
	if !naming && !displaying {
		return nil, nil
	}
	id, _ := hctx.Values[hooks.HookValueUserID].(string)
	if !naming {
		return p.respell(hctx, id, rawDisplay, changes)
	}
	name, display, err := p.resolve(rawName, rawDisplay)
	if err != nil {
		return nil, err
	}
	if name == "" {
		changes[Column.Name], changes[DisplayColumn.Name] = nil, nil
		return changes, nil
	}
	if err := p.free(hctx, name, id); err != nil {
		return nil, err
	}
	changes[Column.Name], changes[DisplayColumn.Name] = name, display
	return changes, nil
}

// respell handles an update that sets the display form and not the
// username. The username the user holds is not checked against the rules
// again: one accepted under older limits can still be respelled.
func (p *Plugin) respell(hctx *core.HookContext, id string, rawDisplay any, changes behemoth.M) (behemoth.M, error) {
	var display string
	switch v := rawDisplay.(type) {
	case nil:
	case string:
		display = strings.TrimSpace(v)
	default:
		return nil, errInvalidDisplay("display_username must be a string")
	}
	current, err := hctx.Tx.FindUserByID(hctx.Ctx, id)
	if err != nil {
		return nil, err
	}
	held, has, err := Column.Get(current)
	if err != nil {
		return nil, err
	}
	switch {
	case !has && display == "":
		changes[DisplayColumn.Name] = nil
	case !has:
		return nil, errInvalidDisplay("display_username needs a username")
	case display == "":
		changes[DisplayColumn.Name] = held
	case Normalize(display) != held:
		return nil, errInvalidDisplay("display_username must be the username, in any casing")
	default:
		changes[DisplayColumn.Name] = display
	}
	return changes, nil
}

// resolve checks a username and a display username about to be stored
// together, as they arrive in a payload or a row, and returns both in the
// form to store. Both are "" when rawName holds no username.
//
// The display form defaults to the username as it was typed, trimmed. One
// that is given has to spell the username: "Ada_L" for "ada_l". A display
// form that could differ from the username would let a user show another
// user's name.
func (p *Plugin) resolve(rawName, rawDisplay any) (name, display string, err error) {
	var typed string
	switch v := rawName.(type) {
	case nil:
	case string:
		typed = strings.TrimSpace(v)
	default:
		return "", "", errInvalidUsername("username must be a string")
	}
	switch v := rawDisplay.(type) {
	case nil:
	case string:
		display = strings.TrimSpace(v)
	default:
		return "", "", errInvalidDisplay("display_username must be a string")
	}
	if typed == "" {
		if display != "" {
			return "", "", errInvalidDisplay("display_username needs a username")
		}
		return "", "", nil
	}
	if name, err = p.Validate(typed); err != nil {
		return "", "", err
	}
	if display == "" {
		return name, typed, nil
	}
	if Normalize(display) != name {
		return "", "", errInvalidDisplay("display_username must be the username, in any casing")
	}
	return name, display, nil
}

// free refuses name, a username in its stored form about to be written to a
// user row, when a user other than ownerID holds it. The lookup runs in the
// write's transaction. Two writes racing for one username can both pass it;
// the column's unique constraint then refuses the second.
func (p *Plugin) free(hctx *core.HookContext, name, ownerID string) error {
	holder, err := hctx.Tx.FindUserBy(hctx.Ctx, Column.Name, name)
	switch {
	case err == nil:
		if holder.ID != ownerID {
			return errUsernameTaken()
		}
	case !errs.IsNotFound(err):
		return err
	}
	return nil
}

// Credentials is sign-in's input: a username and a password.
type Credentials struct {
	Username string
	Password string

	// Extra holds input the flow does not read but a handler on
	// auth.signIn.before may, such as a captcha token. The route fills it
	// with the request fields other than username and password. Nothing in
	// it is stored.
	Extra behemoth.M
}

// FromMap sets the credentials from a request body. "username" and
// "password" fill the fields and every other key goes to Extra. A missing or
// null username or password is left empty, for sign-in to refuse; one that
// is not a string is a validation error.
func (c *Credentials) FromMap(data map[string]any) error {
	field := func(key string) (string, error) {
		switch v := data[key].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			return "", errs.NewInvalidInputError("username.SignIn", key, key+" must be a string", nil)
		}
	}
	name, err := field(HookValueUsername)
	if err != nil {
		return err
	}
	password, err := field(keyPassword)
	if err != nil {
		return err
	}
	extra := behemoth.M{}
	maps.Copy(extra, data)
	delete(extra, HookValueUsername)
	delete(extra, keyPassword)
	if len(extra) == 0 {
		extra = nil
	}
	c.Username, c.Password, c.Extra = name, password, extra
	return nil
}

// SignIn verifies a username and a password and creates a session for the
// user. It is the email/password plugin's sign-in with another lookup
// (emailpassword.Plugin.SignInWith): the password check, the second-factor
// checkpoint and the session are the same, it fires the same auth.signIn.*
// points, and an unknown username, a user without a password and a wrong
// password get the same typed error, with the code
// emailpassword.ErrorCodeInvalidCredentials. The result's Method is
// "username".
//
// Handlers on auth.signIn.before see "username" where an email sign-in has
// "email", in its stored form, next to "password" and the keys of
// creds.Extra. The username is also published in Values under
// HookValueUsername.
//
// It is the flow behind POST /sign-in/username, for callers that are not
// that route. The raw session token is in the result and is the caller's to
// deliver. The plugin must have been initialized by Boot.
func (p *Plugin) SignIn(ctx context.Context, creds Credentials) (*core.SignInResult, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError("username.SignIn", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	return p.passwords.SignInWith(ctx, emailpassword.IdentifierCredentials{
		Key:      HookValueUsername,
		Value:    Normalize(creds.Username),
		Password: creds.Password,
		Extra:    creds.Extra,
		Method:   PluginName,
		// The value is normalized again: a before handler may have rewritten
		// it. The rules are not applied, so a username accepted under older
		// limits still signs in, and one that could never be stored finds
		// no user.
		Find: func(ctx context.Context, s *store.Store, value string) (*models.User, error) {
			return s.FindUserBy(ctx, Column.Name, Normalize(value))
		},
	})
}

// Available reports whether username can be taken: it is not reserved and
// no user holds it. A username that breaks the rules of length or characters
// is a validation error with ErrorCodeInvalidUsername, whose message says
// which rule, so a form can show it. It is the flow behind POST
// /username/available, and works whether or not that route is mounted.
//
// The answer can be out of date by the time it is used: the write that
// takes the username checks again.
func (p *Plugin) Available(ctx context.Context, username string) (bool, error) {
	if p.authContext == nil {
		return false, errs.NewConfigurationError("username.Available", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	name, err := p.wellFormed(username)
	if err != nil {
		return false, err
	}
	if p.reserved[name] {
		return false, nil
	}
	_, err = p.authContext.Store.FindUserBy(ctx, Column.Name, name)
	if errs.IsNotFound(err) {
		return true, nil
	}
	return false, err
}

// SetUsername gives the user with userID a username, or removes it when
// username is empty, and returns the stored user. The display form is the
// username as it is passed, so "Ada_L" stores "ada_l" and shows "Ada_L". The rules and the taken
// check are the same as at sign-up, and the errors carry the same codes. It
// is for the application's own code: a settings screen, or a job that
// assigns usernames to the users an application had before it added the
// plugin.
//
// It does not check who is asking. The old username is free for another
// user at once.
func (p *Plugin) SetUsername(ctx context.Context, userID, username string) (*models.User, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError("username.SetUsername", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	// The data.user.beforeUpdate handler checks and normalizes the value.
	return p.authContext.Store.UpdateUser(ctx, userID, behemoth.M{Column.Name: username})
}

// handleSignIn decodes the body, calls SignIn and answers the way every
// sign-in route does (core.WriteSignIn). It returns the flow's error
// unchanged, and the router maps it.
func (p *Plugin) handleSignIn(rctx *core.RequestContext) error {
	// The body is decoded as a map so that fields other than the username
	// and password reach the before handlers, in creds.Extra.
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return errs.NewValidationError("username.SignIn", "request", err)
	}
	var creds Credentials
	if err := creds.FromMap(body); err != nil {
		return err
	}
	result, err := p.SignIn(rctx.Ctx, creds)
	if err != nil {
		return err
	}
	return core.WriteSignIn(rctx, result, nil)
}

// handleAvailable decodes the body, calls Available and answers
// {"available": true} or {"available": false}. A username that is not a
// string or breaks the rules is the flow's validation error.
func (p *Plugin) handleAvailable(rctx *core.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return errs.NewValidationError("username.Available", "request", err)
	}
	name, ok := body[HookValueUsername].(string)
	if !ok {
		return errInvalidUsername("username must be a string")
	}
	available, err := p.Available(rctx.Ctx, name)
	if err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{keyAvailable: available})
}

var _ core.Plugin = (*Plugin)(nil)
