package emailpassword

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

const PluginName = "emailpassword"

type Plugin struct {
	authContext *types.AuthContext
	signUp      func(hctx *types.HookContext, in behemoth.M) (*models.User, error)
	signIn      func(hctx *types.HookContext, in EmailAndPasswordCredentials) (*SignInResult, error)
}

// Declare implements [types.Plugin].
func (p *Plugin) Declare(ic *types.PluginInitContext) error {
	panic("unimplemented")
}

// Meta implements [types.Plugin].
func (p *Plugin) Meta() types.PluginMeta {
	panic("unimplemented")
}

// Middlewares implements [types.Plugin].
func (p *Plugin) Middlewares() []types.Middleware {
	panic("unimplemented")
}

// Register implements [types.Plugin].
func (p *Plugin) Register(reg types.HookRegistry) error {
	panic("unimplemented")
}

// Version implements [types.Plugin].
func (p *Plugin) Version() string {
	panic("unimplemented")
}

func New(authContext types.AuthContext) *Plugin {
	// p := &Plugin{authContext: authContext}
	// p.signUp = types.WithLifecycle(
	// 	authContext.Dispatcher,
	// 	hooks.HookSignInBefore, hooks.HookSignUpAfter, hooks.HookSignUpFailed,
	// 	signUpBody,
	// )
	// p.signIn = types.WithLifecycle(
	// 	authContext.Dispatcher,
	// 	hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed,
	// 	signInBody,
	// )

	return &Plugin{}
}

func (p *Plugin) Init(ac *types.AuthContext) error {
	p.authContext = ac
	p.signUp = types.WithLifecycle(ac.Dispatcher, hooks.HookSignUpBefore, hooks.HookSignUpAfter, hooks.HookSignUpFailed, signUpBody)
	p.signIn = types.WithLifecycle(ac.Dispatcher, hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed, signInBody)
	return nil
}

// Declare: no plugin-owned hook points — this plugin only fires core's
// auth.signUp.* / auth.signIn.* / auth.signOut.* points, which core already
// declared before any plugin's Declare() runs.
func (p *Plugin) DeclareHooks() []types.HookPointDef {
	return []types.HookPointDef{}
}

// Register: this plugin has no hook handlers of its own to attach elsewhere.
// Its entire contribution is the endpoints below. A plugin like TOTP, by
// contrast, would use Register() here to attach to
// behemoth.HookSignInCredentialsVerified.
func (p *Plugin) RegisterHooks() []types.Listener {
	return []types.Listener{}
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

type EmailAndPasswordCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func signUpBody(hctx *types.HookContext, userData behemoth.M) (*models.User, error) {
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	emailStr, ok := userData["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}
	email := strings.ToLower(strings.TrimSpace(emailStr))

	if err := ac.Validator.ValidateEmail(email); err != nil {
		return nil, errors.New("invalid email")
	}

	password, _ := userData["password"].(string)
	if err := ac.Validator.ValidatePassword(password, ac.PasswordOptions); err != nil {
		return nil, errors.New("invalid password")
	}

	_, err := ac.Store.FindUserByEmail(hctx.Ctx, email)
	if err == nil {
		ac.PasswordOptions.PasswordHasher.Hash(password) // timing mitigation, unchanged
		dispatcher.Fail(hctx, hooks.HookSignUpFailed, types.FailureReason{Code: "userExists"})
		return nil, errors.New("user already exists")
	}
	if !behemotherr.IsNotFound(err) {
		return nil, err // infra error (DB down): not "no such user"
	}

	passwordHash, err := ac.PasswordOptions.PasswordHasher.Hash(password)
	if err != nil {
		return nil, err // infra error - no Fail()
	}

	// Only these profile fields are taken from the request. Never the whole
	// payload: every column a model knows — contributed ones included — would
	// become client-writable (mass assignment: "role": "admin", a verified
	// flag, ...). The store assigns the id and timestamps, and fires
	// data.user.beforeCreate / afterCreate (Tier 1) — hooks are where other
	// plugins add their columns. The password hash goes to the user's
	// "credential" account, created with the user or not at all.
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
		return nil, errors.New("user create failed")
	}

	return user, nil
}

func signInBody(hctx *types.HookContext, creds EmailAndPasswordCredentials) (*SignInResult, error) {
	ac := hctx.Auth
	dispatcher := ac.Dispatcher
	user, err := ac.Store.FindUserByEmail(hctx.Ctx, creds.Email) // the store normalizes the email
	if err != nil {
		ac.PasswordOptions.PasswordHasher.Hash(creds.Password) // timing mitigation
		if behemotherr.IsNotFound(err) {
			dispatcher.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "userNotFound"})
			return nil, errors.New("invalid email or password")
		}
		return nil, err // infra error (DB down) — must NOT count toward lockout
	}

	// The password lives on the user's "credential" account. A user without
	// one (signed up through an OAuth provider only) has no password to
	// match, and is answered exactly like a wrong password.
	credential, err := ac.Store.FindAccount(hctx.Ctx, models.ProviderCredential, user.ID)
	if err != nil {
		ac.PasswordOptions.PasswordHasher.Hash(creds.Password) // timing mitigation
		if behemotherr.IsNotFound(err) {
			dispatcher.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "noCredentialAccount"})
			return nil, errors.New("invalid email or password")
		}
		return nil, err // infra error — must NOT count toward lockout
	}

	isValid, err := ac.PasswordOptions.PasswordHasher.Verify(credential.PasswordHash, creds.Password)
	if err != nil {
		return nil, err // a malformed stored hash or key error — not a wrong password, so not counted as one
	}

	if !isValid {
		dispatcher.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "invalidCredentials"})
		return nil, errors.New("invalid email or password")
	}

	// The seam a 2FA plugin hooks. requireStepUp travels back via the mutated
	// payload - this is the mechanism by which SignIn decides Pending vs Active
	// without knowing anything about TOTP, backup codes, etc.
	checkpoint, err := dispatcher.RunBefore(hctx, hooks.HookSignInCredentialsVerified,
		behemoth.M{hooks.HookValueUserID: user.ID})
	if err != nil {
		dispatcher.Fail(hctx, hooks.HookSignInFailed,
			types.FailureReason{Code: "secondFactorRejected", Cause: err})
		return nil, err
	}

	state := types.SessionActive
	if requireStepUp, _ := checkpoint["requireStepUp"].(bool); requireStepUp {
		state = types.SessionPending
	}

	session, rawToken, err := ac.SessionManager.Create(hctx.Ctx, user.ID, types.SessionMeta{
		IPAddress: hctx.Request.Request.RemoteAddr,
		UserAgent: hctx.Request.Request.UserAgent(),
		State:     state,
	})
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

func SignOut(hctx *types.HookContext, sessionID string) error {
	ac := hctx.Auth
	if _, err := ac.Dispatcher.RunBefore(hctx, hooks.HookSignOutBefore, behemoth.M{"sessionID": sessionID}); err != nil {
		return err
	}
	if err := ac.SessionManager.Revoke(hctx.Ctx, sessionID, "user_logout"); err != nil {
		return err
	}
	ac.Dispatcher.RunAfter(hctx, hooks.HookSignOutAfter, nil)
	return nil
}

func (p *Plugin) handleSignUp(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return rctx.Response.Error(http.StatusBadRequest, "invalid request body")
	}

	hctx := &types.HookContext{Ctx: rctx.Ctx, Auth: rctx.Auth, Request: rctx, Values: behemoth.M{}}

	user, err := p.signUp(hctx, body)
	if err != nil {
		return rctx.Response.Error(http.StatusBadRequest, err.Error()) // real status mapping deferred to HTTP layer pillar
	}
	return rctx.Response.JSON(http.StatusCreated, user)
}

func (p *Plugin) handleSignIn(rctx *types.RequestContext) error {
	var creds EmailAndPasswordCredentials
	if err := json.NewDecoder(rctx.Request.Body).Decode(&creds); err != nil {
		return behemotherr.NewValidationError("SignIn", "request", err)
		// return rctx.Response.Error(http.StatusBadRequest, "invalid request body")
	}

	hctx := &types.HookContext{Ctx: rctx.Ctx, Auth: rctx.Auth, Request: rctx, Values: behemoth.M{}}

	result, err := p.signIn(hctx, creds)
	if err != nil {
		return behemotherr.NewValidationError("SignIn", "request", err)
		// return rctx.Response.Error(http.StatusUnauthorized, err.Error())
	}

	rctx.Auth.SessionManager.WriteToken(rctx, result.RawToken, result.Session) // honors SessionConfig.Transport
	if result.Session.State == models.SessionPending {
		return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "requires_second_factor"})
	}
	return rctx.Response.JSON(http.StatusOK, result.User)
}

func (p *Plugin) handleSignOut(rctx *types.RequestContext) error {
	sessionID, _ := rctx.Values["sessionID"].(string) // populated by session middleware upstream
	hctx := &types.HookContext{Ctx: rctx.Ctx, Auth: rctx.Auth, Request: rctx, Values: behemoth.M{}}
	if err := SignOut(hctx, sessionID); err != nil {
		return rctx.Response.Error(http.StatusInternalServerError, err.Error())
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "signed_out"})
}

var _ types.Plugin = (*Plugin)(nil)
