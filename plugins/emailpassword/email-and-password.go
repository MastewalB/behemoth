package emailpassword

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/utils"
)

// PluginName is the name the plugin registers under (PluginMeta.Name). It
// owns the plugin's routes, and other plugins use it to depend on this one
// or to order their hook handlers around it.
const PluginName = "emailpassword"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// Plugin is the email and password authentication plugin. It adds the
// sign-up, sign-in and sign-out routes. Users, credential accounts and
// sessions are core tables, written through the store and the session
// manager, and the auth.* hook points it fires are declared by core, so the
// plugin contributes routes only.
type Plugin struct {
	opts        Options
	authContext *types.AuthContext
	log         telemetry.Logger
	signUp      func(hctx *types.HookContext, in behemoth.M) (*models.User, error)
	signIn      func(hctx *types.HookContext, in EmailAndPasswordCredentials) (*SignInResult, error)
}

// Meta implements [types.Plugin]. The plugin depends on no other plugin and
// has no mount path, so its routes sit directly under the router's base path
// (for example /api/auth/sign-in/email).
func (p *Plugin) Meta() types.PluginMeta {
	return types.PluginMeta{Name: PluginName}
}

// Version implements [types.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [types.Plugin]. The plugin declares nothing:
//   - hook points: it fires core's auth.signUp.*, auth.signIn.* and
//     auth.signOut.* points, which core declares before any plugin's Declare
//     runs (CoreDeclareHookPoints);
//   - tables: the password hash lives on the core accounts table;
//   - token kinds: none yet. Password reset and email verification are not
//     built, and will declare their kinds here;
//   - rate limits: core declares the baseline rule for /sign-in/email.
func (p *Plugin) Declare(ic *types.PluginInitContext) error {
	return nil
}

// Register implements [types.Plugin]. The plugin attaches no handlers to
// other points; its contribution is its routes. A second-factor plugin, by
// contrast, would register on auth.signIn.credentialsVerified here.
func (p *Plugin) Register(reg types.HookRegistry) error {
	return nil
}

// Middlewares implements [types.Plugin]. The plugin has no middleware that
// should run on every route of the application. The session check that
// sign-out needs is attached to that route alone (see Routes).
func (p *Plugin) Middlewares() []types.Middleware {
	return nil
}

// Default password length limits, used when Options leaves them zero.
const (
	DefaultMinPasswordLength = 8
	DefaultMaxPasswordLength = 128
)

// Options configures the plugin. The zero value is usable.
//
// The email and password rules live here and not on types.AuthContext: this
// plugin is the only place a password enters the system. A plugin that also
// sets passwords (password reset, an admin screen) should depend on this one
// and go through it, so the rules have one owner.
type Options struct {
	// MinPasswordLength and MaxPasswordLength bound a new password's length
	// at sign-up, counted in characters. Zero means the default (8 and 128).
	// The upper bound also caps the work the password hasher does for one
	// request. Sign-in does not apply them: a password accepted under an
	// older policy still signs in.
	MinPasswordLength int
	MaxPasswordLength int

	// ValidatePassword is an optional extra check at sign-up, run after the
	// length check, for example a breached-password lookup. nil = none.
	ValidatePassword func(password string) error

	// ValidateEmail checks the normalized (trimmed, lowercased) email at
	// sign-up. nil = utils.IsValidEmail, a check of the address's shape.
	ValidateEmail func(email string) error
}

// New returns the plugin configured with opts. Limits left at zero take
// their defaults. Limits that contradict each other are reported by Init, as
// a configuration error from Boot.
func New(opts Options) *Plugin {
	if opts.MinPasswordLength == 0 {
		opts.MinPasswordLength = DefaultMinPasswordLength
	}
	if opts.MaxPasswordLength == 0 {
		opts.MaxPasswordLength = DefaultMaxPasswordLength
	}
	if opts.ValidateEmail == nil {
		opts.ValidateEmail = func(email string) error {
			if !utils.IsValidEmail(email) {
				return errors.New("invalid email")
			}
			return nil
		}
	}
	return &Plugin{opts: opts}
}

// Init implements [types.Plugin]. It checks the options, keeps the
// AuthContext and wraps the sign-up and sign-in flows with their hook points.
// Passwords are hashed with the AuthContext's Crypto.Passwords.
func (p *Plugin) Init(ac *types.AuthContext) error {
	if p.opts.MinPasswordLength < 1 || p.opts.MaxPasswordLength < p.opts.MinPasswordLength {
		return behemotherr.NewConfigurationError("emailpassword.Init",
			fmt.Sprintf("password length limits are invalid: min %d, max %d", p.opts.MinPasswordLength, p.opts.MaxPasswordLength), nil)
	}
	if ac.Crypto.Passwords == nil {
		return behemotherr.NewConfigurationError("emailpassword.Init", "AuthContext.Crypto has no password hasher", nil)
	}
	p.authContext = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.signUp = types.WithLifecycle(ac.Dispatcher, hooks.HookSignUpBefore, hooks.HookSignUpAfter, hooks.HookSignUpFailed, p.signUpBody)
	p.signIn = types.WithLifecycle(ac.Dispatcher, hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed, p.signInBody)
	return nil
}

// validatePassword applies the plugin's rules to a new password.
func (p *Plugin) validatePassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < p.opts.MinPasswordLength || n > p.opts.MaxPasswordLength {
		return fmt.Errorf("password must be %d to %d characters long", p.opts.MinPasswordLength, p.opts.MaxPasswordLength)
	}
	if p.opts.ValidatePassword != nil {
		return p.opts.ValidatePassword(password)
	}
	return nil
}

func (p *Plugin) Routes() []types.Route {
	return []types.Route{
		{Method: http.MethodPost, Path: "/sign-up/email", Handler: p.handleSignUp},
		{Method: http.MethodPost, Path: "/sign-in/email", Handler: p.handleSignIn},
		{Method: http.MethodPost, Path: "/sign-out", Handler: p.handleSignOut,
			Middlewares: []types.Middleware{
				types.RequireSession(p.authContext.SessionManager),
			},
		},
	}
}

// EmailAndPasswordCredentials is sign-in's input. Email and Password are all
// the flow itself reads.
//
// It implements [behemoth.Serializable], which is how WithLifecycle turns it
// into the auth.signIn.before payload and back: handlers see "email",
// "password" and the keys of Extra side by side, the way they see a sign-up's
// fields.
type EmailAndPasswordCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`

	// Extra holds input the flow does not read but a handler on
	// auth.signIn.before may: a captcha token, a device id. The route fills
	// it with the request fields other than email and password. Nothing in
	// it is stored. After the before chain it holds what the handlers left.
	Extra behemoth.M `json:"-"`
}

// Payload keys of the credentials' two fields.
const (
	credentialEmailKey    = "email"
	credentialPasswordKey = "password"
)

// ToMap returns the credentials as a hook payload: a copy of Extra with
// "email" and "password" set from the fields, so a key of Extra with one of
// those names does not replace them.
func (c *EmailAndPasswordCredentials) ToMap() (map[string]any, error) {
	m := make(map[string]any, len(c.Extra)+2)
	maps.Copy(m, c.Extra)
	m[credentialEmailKey], m[credentialPasswordKey] = c.Email, c.Password
	return m, nil
}

// FromMap sets the credentials from a request body or a rewritten payload.
// "email" and "password" fill the fields and every other key goes to Extra,
// which is replaced. A missing or null email or password is left empty, for
// sign-in to refuse; one that is not a string is a validation error.
func (c *EmailAndPasswordCredentials) FromMap(data map[string]any) error {
	field := func(key string) (string, error) {
		switch v := data[key].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			return "", behemotherr.NewValidationError("emailpassword.SignIn", key, fmt.Errorf("%s must be a string", key))
		}
	}
	email, err := field(credentialEmailKey)
	if err != nil {
		return err
	}
	password, err := field(credentialPasswordKey)
	if err != nil {
		return err
	}

	var extra behemoth.M
	for k, v := range data {
		if k == credentialEmailKey || k == credentialPasswordKey {
			continue
		}
		if extra == nil {
			extra = behemoth.M{}
		}
		extra[k] = v
	}
	c.Email, c.Password, c.Extra = email, password, extra
	return nil
}

func (p *Plugin) signUpBody(hctx *types.HookContext, userData behemoth.M) (*models.User, error) {
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	emailStr, ok := userData["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}
	email := strings.ToLower(strings.TrimSpace(emailStr))

	if err := p.opts.ValidateEmail(email); err != nil {
		return nil, errors.New("invalid email")
	}

	password, _ := userData["password"].(string)
	if err := p.validatePassword(password); err != nil {
		return nil, errors.New("invalid password")
	}

	_, err := ac.Store.FindUserByEmail(hctx.Ctx, email)
	if err == nil {
		hashPassword(hctx, password) // timing mitigation, unchanged
		if err := dispatcher.Fail(hctx, hooks.HookSignUpFailed, types.FailureReason{Code: "userExists", Metadata: behemoth.M{hooks.HookValueEmail: email}}); err != nil {
			return nil, err
		}
		return nil, errors.New("user already exists")
	}
	if !behemotherr.IsNotFound(err) {
		return nil, err // infra error (DB down): not "no such user"
	}

	passwordHash, err := hashPassword(hctx, password)
	if err != nil {
		return nil, err // infra error - no Fail()
	}

	// Only these profile fields are taken from the request. Never the whole
	// payload: every column a model knows — contributed ones included — would
	// become client-writable (mass assignment: "role": "admin", a verified
	// flag, ...). The store assigns the id and timestamps, and fires
	// data.user.beforeCreate / afterCreate (Tier 1) — hooks are where other
	// plugins add their columns. The password hash goes to the user's
	// "credential" account, created with the user or not at all. The data
	// hooks run inside this transaction, so data.user.afterCreate can see a
	// user that the account insert then rolls back; auth.signUp.after fires
	// only once the transaction has committed.
	profile := func(key string) string { v, _ := userData[key].(string); return strings.TrimSpace(v) }
	user := &models.User{
		Username:  profile(models.UserUsername),
		Firstname: profile(models.UserFirstname),
		Lastname:  profile(models.UserLastname),
		ImageUrl:  profile(models.UserImageURL),
	}
	user.Email = email
	user.EmailVerified = false
	err = ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
		if err := tx.CreateUser(ctx, user); err != nil {
			return err
		}
		return tx.CreateAccount(ctx, &models.Account{
			UserID:       user.ID,
			ProviderID:   models.ProviderCredential,
			AccountID:    user.ID,
			PasswordHash: passwordHash,
		})
	})
	if err != nil {
		// A typed error is returned as it is, so the caller keeps its
		// category and public message: a data hook's veto on
		// data.user.beforeCreate or afterCreate, or a classified store
		// error. An untyped one may carry driver detail and is replaced.
		if _, typed := errors.AsType[*behemotherr.DomainError](err); !typed {
			return nil, errors.New("user create failed")
		}
		if isRejection(err) {
			if failErr := dispatcher.Fail(hctx, hooks.HookSignUpFailed,
				types.FailureReason{Code: "rejectedByHook", Cause: err, Metadata: behemoth.M{hooks.HookValueEmail: email}}); failErr != nil {
				return nil, failErr
			}
		}
		return nil, err
	}

	return user, nil
}

// hashPassword hashes password inside a span. Hashing is the slowest step of
// a sign-up and of a refused sign-in, where it runs to keep the response
// time the same, so a trace shows it by name. The span lives here and not in
// the hasher because PasswordHasher's methods take no context.
func hashPassword(hctx *types.HookContext, password string) (string, error) {
	_, span := hctx.Auth.Telemetry.StartSpan(hctx.Ctx, telemetry.SpanPasswordHash, nil)
	hash, err := hctx.Auth.Crypto.Passwords.Hash(password)
	telemetry.FinishSpan(span, err)
	return hash, err
}

// isRejection reports whether err is a refusal of the request, as opposed to
// a failure of the system: a typed error in one of the categories a hook
// handler or a rate limit answers with. Only rejections fire a failed point,
// so an outage is not counted as a refused sign-up.
func isRejection(err error) bool {
	de, ok := errors.AsType[*behemotherr.DomainError](err)
	if !ok {
		return false
	}
	switch de.Category {
	case behemotherr.CategoryValidation, behemotherr.CategoryConflict, behemotherr.CategoryUnauthorized,
		behemotherr.CategoryForbidden, behemotherr.CategoryRateLimited:
		return true
	}
	return false
}

// ErrorCodeInvalidCredentials is the code of the error sign-in returns for an
// unknown email, a user without a password and a wrong password.
const ErrorCodeInvalidCredentials = "invalid_credentials"

// errInvalidCredentials is sign-in's one answer to every credential it
// refuses. The three cases share a code and a message so the response does
// not tell which emails have an account. It is typed (unauthorized, 401), so
// a caller can tell it from a failure of the system, which is any other
// error SignIn returns apart from a hook handler's typed rejection.
func errInvalidCredentials() error {
	return behemotherr.NewUnauthorized("emailpassword.SignIn", ErrorCodeInvalidCredentials, "invalid email or password")
}

func (p *Plugin) signInBody(hctx *types.HookContext, creds EmailAndPasswordCredentials) (*SignInResult, error) {
	ac := hctx.Auth
	hasher := ac.Crypto.Passwords
	dispatcher := ac.Dispatcher
	user, err := ac.Store.FindUserByEmail(hctx.Ctx, creds.Email) // the store normalizes the email
	if err != nil {
		hashPassword(hctx, creds.Password) // timing mitigation
		if behemotherr.IsNotFound(err) {
			if err := dispatcher.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{
				Code: "userNotFound", Metadata: behemoth.M{hooks.HookValueEmail: strings.ToLower(strings.TrimSpace(creds.Email))},
			}); err != nil {
				return nil, err
			}
			return nil, errInvalidCredentials()
		}
		return nil, err // infra error (DB down) — must NOT count toward lockout
	}

	// Every rejection from here on is an attempt on a known account, and
	// its audit event says which.
	rejected := func(code string, cause error) types.FailureReason {
		return types.FailureReason{Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID}
	}

	// The password lives on the user's "credential" account. A user without
	// one (signed up through an OAuth provider only) has no password to
	// match, and is answered exactly like a wrong password.
	credential, err := ac.Store.FindAccount(hctx.Ctx, models.ProviderCredential, user.ID)
	if err != nil {
		hashPassword(hctx, creds.Password) // timing mitigation
		if behemotherr.IsNotFound(err) {
			if err := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("noCredentialAccount", nil)); err != nil {
				return nil, err
			}
			return nil, errInvalidCredentials()
		}
		return nil, err // infra error — must NOT count toward lockout
	}

	_, span := ac.Telemetry.StartSpan(hctx.Ctx, telemetry.SpanPasswordVerify, nil) // the hasher takes no context; the span times the call
	isValid, err := hasher.Verify(credential.PasswordHash, creds.Password)
	telemetry.FinishSpan(span, err)
	if err != nil {
		return nil, err // a malformed stored hash or key error — not a wrong password, so not counted as one
	}

	if !isValid {
		if err := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("invalidCredentials", nil)); err != nil {
			return nil, err
		}
		return nil, errInvalidCredentials()
	}

	// The seam a 2FA plugin hooks. requireStepUp travels back via the mutated
	// payload - this is the mechanism by which SignIn decides Pending vs Active
	// without knowing anything about TOTP, backup codes, etc.
	checkpoint, err := dispatcher.RunBefore(hctx, hooks.HookSignInCredentialsVerified,
		behemoth.M{hooks.HookValueUserID: user.ID})
	if err != nil {
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed,
			rejected("secondFactorRejected", err)); failErr != nil {
			return nil, failErr
		}
		return nil, err
	}

	state := types.SessionActive
	if requireStepUp, _ := checkpoint["requireStepUp"].(bool); requireStepUp {
		state = types.SessionPending
	}

	// The session manager reads the IP address and user agent from the
	// request on hctx.Ctx, so sign-in also works without one (a job, another
	// plugin calling in).
	session, rawToken, err := ac.SessionManager.Create(hctx.Ctx, user.ID, types.SessionMeta{State: state})
	if err != nil {
		return nil, err
	}

	return &SignInResult{User: user, Session: session, RawToken: rawToken}, nil
}

type SignInResult struct {
	User     *models.User
	Session  *models.Session
	RawToken string
}

// AuditSubject implements [types.AuditSubject]: a sign-in is about its user.
func (r *SignInResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.User == nil {
		return "", ""
	}
	return models.UserTable, r.User.ID
}

// SignUp creates a user with an email and a password, and the user's
// credential account. input holds the sign-up fields under their column
// names ("email", "password", and optionally "username", "firstname",
// "lastname", "image_url"); other keys are not stored, but handlers on
// auth.signUp.before see them. It fires auth.signUp.before, .after and
// .failed.
//
// It is the flow behind POST /sign-up/email, for callers that are not that
// route: a CLI, a job, another plugin. Pass the context of the request being
// handled when there is one; hook handlers get the request from it. The
// plugin must have been initialized by Boot.
func (p *Plugin) SignUp(ctx context.Context, input behemoth.M) (*models.User, error) {
	hctx, err := p.operation(ctx, "emailpassword.SignUp")
	if err != nil {
		return nil, err
	}
	email, _ := input[credentialEmailKey].(string)
	publishEmail(hctx, email)
	return p.signUp(hctx, input)
}

// SignIn verifies creds and creates a session for the user. The session is
// pending instead of active when a handler on auth.signIn.credentialsVerified
// asked for a second factor. It fires auth.signIn.before, .after and
// .failed. Handlers on auth.signIn.before see creds.Extra next to the email
// and password.
//
// It is the flow behind POST /sign-in/email. Like SignUp it runs without an
// HTTP request; the session then records no IP address or user agent unless
// the caller's context carries a request. The raw session token is in the
// result and is the caller's to deliver.
func (p *Plugin) SignIn(ctx context.Context, creds EmailAndPasswordCredentials) (*SignInResult, error) {
	hctx, err := p.operation(ctx, "emailpassword.SignIn")
	if err != nil {
		return nil, err
	}
	publishEmail(hctx, creds.Email)
	return p.signIn(hctx, creds)
}

// publishEmail puts the email a sign-up or sign-in was called with in the
// operation's Values, under hooks.HookValueEmail and in its stored form
// (store.NormalizeEmail). A rate-limit rule on the flow's before point keys
// on it there: HookRateLimitRule.KeyFunc gets the HookContext and not the
// payload. It is the email the caller sent, so a before handler that
// rewrites the payload's email does not move the attempt to another count.
// A call without an email leaves no entry, and removes the one inherited
// from an enclosing operation, so a rule per email does not apply to it.
func publishEmail(hctx *types.HookContext, email string) {
	if email = store.NormalizeEmail(email); email == "" {
		delete(hctx.Values, hooks.HookValueEmail)
		return
	}
	hctx.Values[hooks.HookValueEmail] = email
}

// operation builds the HookContext one flow call runs with. Its Values start
// as a copy of the operation ctx already belongs to, if any, and Request is
// the request ctx carries, or nil.
func (p *Plugin) operation(ctx context.Context, op string) (*types.HookContext, error) {
	if p.authContext == nil {
		return nil, behemotherr.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	return &types.HookContext{
		Ctx:     ctx,
		Auth:    p.authContext,
		Values:  types.NestedHookValues(ctx),
		Request: types.RequestFrom(ctx),
	}, nil
}

// SignOut revokes the session with sessionID. It fires auth.signOut.before
// and .after around the revoke, as one operation: both points share
// hctx.Values, and the session manager's revoke points start from a copy of
// them.
func SignOut(hctx *types.HookContext, sessionID string) error {
	hctx = types.AsOperation(hctx)
	hctx.Values[hooks.HookValueSessionID] = sessionID // for the operation's later points and its audit event
	ac := hctx.Auth
	// The returned payload is not read: a handler can stop the sign-out, but
	// it can't point it at another session.
	if _, err := ac.Dispatcher.RunBefore(hctx, hooks.HookSignOutBefore, behemoth.M{"sessionID": sessionID}); err != nil {
		return err
	}
	if err := ac.SessionManager.Revoke(hctx.Ctx, sessionID, "user_logout"); err != nil {
		return err
	}
	return ac.Dispatcher.RunAfter(hctx, hooks.HookSignOutAfter, nil)
}

func (p *Plugin) handleSignUp(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return rctx.Response.Error(http.StatusBadRequest, "invalid request body")
	}

	user, err := p.SignUp(rctx.Ctx, body)
	if err != nil {
		// A typed error carries its own status and public message, and the
		// router maps it (RouterConfig.ErrorMapper). The flow's own untyped
		// rejections ("invalid email", "user already exists") are a 400.
		if _, typed := errors.AsType[*behemotherr.DomainError](err); typed {
			return err
		}
		return rctx.Response.Error(http.StatusBadRequest, err.Error())
	}
	return rctx.Response.JSON(http.StatusCreated, user)
}

// handleSignIn returns the flow's error unchanged, and the router maps and
// logs it (RouterConfig.ErrorMapper). A refused credential is a typed
// unauthorized error (401), and a hook handler's typed rejection keeps its
// own status. Anything else is a failure of the system: the router answers
// 500 without the error's text and logs it at Error.
func (p *Plugin) handleSignIn(rctx *types.RequestContext) error {
	// The body is decoded as a map so that fields other than the email and
	// password reach the before handlers, in creds.Extra.
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("SignIn", "request", err)
	}
	var creds EmailAndPasswordCredentials
	if err := creds.FromMap(body); err != nil {
		return err
	}

	result, err := p.SignIn(rctx.Ctx, creds)
	if err != nil {
		return err
	}

	rctx.Auth.SessionManager.WriteToken(rctx, result.RawToken, result.Session) // honors SessionConfig.Transport
	if result.Session.State == models.SessionPending {
		return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "requires_second_factor"})
	}
	return rctx.Response.JSON(http.StatusOK, result.User)
}

// handleSignOut returns SignOut's error unchanged, like handleSignIn. A typed
// error keeps its status (a hook handler's rejection, a session that no
// longer exists). A failed revoke is a 500 from the router, which does not
// send the error's text.
func (p *Plugin) handleSignOut(rctx *types.RequestContext) error {
	sessionID, _ := rctx.Values["sessionID"].(string) // populated by session middleware upstream
	hctx := &types.HookContext{Ctx: rctx.Ctx, Auth: rctx.Auth, Request: rctx}
	if err := SignOut(hctx, sessionID); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "signed_out"})
}

var _ types.Plugin = (*Plugin)(nil)
