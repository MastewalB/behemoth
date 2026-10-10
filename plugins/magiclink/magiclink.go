// Package magiclink is the magic link authentication plugin: a user asks for
// a link by email and signs in by following it, without a password.
//
// It has two flows. RequestLink issues a single-use token for the user and
// hands the link to the application's mail sender (AuthContext.Mailer). Verify consumes the
// token and creates a session. Tokens come from the token manager, sessions
// from the session manager, and the sign-in itself fires core's auth.signIn.*
// points, so a handler written for the email/password plugin's sign-ins sees
// these too.
package magiclink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

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
// owns the plugin's routes, hook points and rate-limit rules, and is the
// Method of the sign-ins it makes.
const PluginName = "magiclink"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// DefaultTTL is how long a link works when Options.TTL is zero.
const DefaultTTL = 15 * time.Minute

// The points the plugin declares and fires around a link request. Verifying
// a link is a sign-in and fires core's auth.signIn.* points instead.
const (
	// HookRequestBefore runs on a link request's input: "email",
	// "redirectURL" and "metadata". A handler may rewrite them or stop the
	// request.
	HookRequestBefore types.HookPoint = "auth.magicLink.beforeRequest"
	// HookRequestAfter runs once the link has been handed to the mail
	// sender, with a *LinkResult.
	HookRequestAfter types.HookPoint = "auth.magicLink.afterRequest"
	// HookRequestFailed fires for a request that sent no link: codes
	// "userNotFound", "issueFailed", "sendFailed" and "rejectedByHook".
	HookRequestFailed types.HookPoint = "auth.magicLink.requestFailed"
)

// Names of the rate-limit rules the plugin declares. An application that
// wants another limit declares a more specific rule, or for the route rules
// the same method and path with Disabled set.
const (
	RuleRequestRoute = "magiclink.request.route" // link requests per client address
	RuleVerifyRoute  = "magiclink.verify.route"  // verify attempts per client address
	RuleRequestEmail = "magiclink.request.email" // link requests per email, from any caller
)

// Paths of the plugin's routes, below the router's base path.
const (
	PathRequest = "/sign-in/magic-link"
	PathVerify  = "/magic-link/verify"
)

// Keys of a link request's hook payload and request body.
const (
	keyEmail       = "email"
	keyRedirectURL = "redirectURL"
	keyMetadata    = "metadata"
	keyToken       = "token"
)

// ErrorCodeInvalidLink is the code of the error Verify returns for a link it
// refuses: unknown, expired, already used, replaced by a newer link, or for
// a user who is gone or has changed email since.
const ErrorCodeInvalidLink = "invalid_magic_link"

// ErrNoAccount is returned by RequestLink when no user has the email. The
// route does not report it: it answers the same for every email, so the
// response does not tell which addresses have an account.
var ErrNoAccount = errors.New("magiclink: no account with this email")

// LinkRequest is the input of RequestLink.
//
// It implements [behemoth.Serializable], which is how WithLifecycle turns it
// into the auth.magicLink.beforeRequest payload and back.
type LinkRequest struct {
	// Email is the address of the account to sign in.
	Email string
	// RedirectURL is where the application should send the user after the
	// sign-in. Optional. It has to be a path on the application's own site
	// or a URL on one of RouterConfig.TrustedOrigins. Verify returns it.
	RedirectURL string
	// Metadata is passed to the mail sender as it is, in
	// MailMessage.Metadata: a locale, a template name, a device label.
	// Optional. The plugin does not read or store it.
	Metadata behemoth.M
}

// ToMap returns the request as a hook payload.
func (r *LinkRequest) ToMap() (map[string]any, error) {
	m := map[string]any{keyEmail: r.Email, keyRedirectURL: r.RedirectURL}
	if r.Metadata != nil {
		m[keyMetadata] = r.Metadata
	}
	return m, nil
}

// FromMap sets the request from a request body or a rewritten payload. A
// missing key leaves its field empty. A value of the wrong type is a
// validation error.
func (r *LinkRequest) FromMap(data map[string]any) error {
	const op = "magiclink.RequestLink"
	field := func(key string) (string, error) {
		switch v := data[key].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			return "", behemotherr.NewInvalidInputError(op, key, key+" must be a string", nil)
		}
	}
	email, err := field(keyEmail)
	if err != nil {
		return err
	}
	redirect, err := field(keyRedirectURL)
	if err != nil {
		return err
	}
	var metadata behemoth.M
	switch v := data[keyMetadata].(type) {
	case nil:
	case behemoth.M: // a payload a handler built, or a caller's request
		metadata = v
	case map[string]any: // a decoded request body
		metadata = v
	default:
		return behemotherr.NewInvalidInputError(op, keyMetadata, keyMetadata+" must be an object", nil)
	}
	r.Email, r.RedirectURL, r.Metadata = email, redirect, metadata
	return nil
}

// LinkResult is what RequestLink returns and what handlers on
// auth.magicLink.afterRequest receive. It does not hold the token.
type LinkResult struct {
	UserID    string
	Email     string
	TokenID   string
	ExpiresAt time.Time
}

// AuditSubject implements [types.AuditSubject]: a link request is about the
// user the link signs in.
func (r *LinkResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// VerifyResult is what Verify returns: the sign-in, and where the request
// for the link asked to go afterwards.
type VerifyResult struct {
	*types.SignInResult
	// RedirectURL is LinkRequest.RedirectURL, checked against the trusted
	// origins when the link was requested. Empty when none was given.
	RedirectURL string
}

// verifyInput is the input of the wrapped verify flow. Its payload on
// auth.signIn.before is "method" and, when the token names one, "email".
// The token is not in the payload, and nothing is read back from it: a
// handler can stop the sign-in, but it can't point it at another link.
type verifyInput struct {
	token string
	email string
}

func (v *verifyInput) ToMap() (map[string]any, error) {
	m := map[string]any{"method": PluginName}
	if v.email != "" {
		m[keyEmail] = v.email
	}
	return m, nil
}

func (v *verifyInput) FromMap(map[string]any) error { return nil }

// Options configures the plugin. LinkURL is required, and so is a mail
// sender in BootConfig.Mail: the plugin sends nothing itself. The link goes
// out as a types.MailMessage of kind types.MailMagicLink.
type Options struct {
	// WaitForSend chooses how the link is handed to the mail sender.
	//
	// false (the default): the request returns once the message is queued
	// (Mailer.SendAsync). A failed send is logged by the mailer. The link
	// stays valid until it expires or the user's next request replaces it.
	// The sender's speed then does not show in the response time, which
	// would tell a known email from an unknown one.
	//
	// true: the request waits for the sender (Mailer.Send). A failed send
	// revokes the link and fires auth.magicLink.requestFailed. Choose it
	// when the sender only enqueues, so waiting costs nothing.
	WaitForSend bool

	// LinkURL is the page of the application the link points to, such as
	// "https://app.example.com/auth/magic". Required, absolute, http or
	// https. The plugin adds the token as the "token" query parameter. The
	// page posts that token to the verify route; a link that verified on a
	// GET would be used up by mail scanners that open links.
	LinkURL string

	// TTL is how long a link works. Zero means DefaultTTL.
	// TokenConfig.TTLOverrides for types.TokenKindMagicLink takes precedence.
	TTL time.Duration

	// RequestLimit bounds link requests per email, from any caller: the
	// route, a CLI, another plugin. It keeps one address from being sent
	// link after link. Zero means 5 per 15 minutes.
	RequestLimit types.Limit

	// LeaveEmailUnverified turns off marking the address as verified. By
	// default a verified link sets EmailVerified on a user who did not have
	// it: the link was sent to the address, so following it shows the user
	// controls it. Set it when verified should only ever mean "went through
	// the application's own verification". A handler that refuses sign-ins
	// of unverified users (emailverification's RequireVerified) then also
	// refuses these.
	LeaveEmailUnverified bool
}

// Plugin is the magic link plugin. It adds the request and verify routes,
// declares the magic_link token kind, the auth.magicLink.* points and its
// rate-limit rules, and fires core's auth.signIn.* points when a link is
// verified. It needs no table of its own.
type Plugin struct {
	opts        Options
	linkURL     *url.URL
	authContext *types.AuthContext
	log         telemetry.Logger
	request     func(hctx *types.HookContext, in LinkRequest) (*LinkResult, error)
	verify      func(hctx *types.HookContext, in verifyInput) (*types.SignInResult, error)
}

// New returns the plugin configured with opts. Values left at zero take
// their defaults. Missing or invalid options are reported by Init, as a
// configuration error from Boot.
func New(opts Options) *Plugin {
	if opts.TTL == 0 {
		opts.TTL = DefaultTTL
	}
	if opts.RequestLimit == (types.Limit{}) {
		opts.RequestLimit = types.Limit{Max: 5, Window: 15 * time.Minute}
	}
	return &Plugin{opts: opts}
}

// Meta implements [types.Plugin]. The plugin depends on no other plugin and
// has no mount path, so its routes sit directly under the router's base path
// (for example /api/auth/sign-in/magic-link).
func (p *Plugin) Meta() types.PluginMeta {
	return types.PluginMeta{Name: PluginName}
}

// Version implements [types.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [types.Plugin]. The plugin declares:
//   - the token kind types.TokenKindMagicLink: single use, kept in the
//     database, so that a new link can revoke the user's earlier ones and a
//     deleted user's links go with the user;
//   - the auth.magicLink.* points around a link request;
//   - three rate-limit rules: link requests and verify attempts per client
//     address, and link requests per email.
//
// It declares no table and no sign-in points: core declares auth.signIn.*.
func (p *Plugin) Declare(ic *types.PluginInitContext) error {
	if err := ic.Tokens.Declare(types.TokenKindDef{
		Kind: types.TokenKindMagicLink, SingleUse: true, DefaultTTL: p.opts.TTL, Backend: types.TokenBackendDB,
	}); err != nil {
		return err
	}

	for _, def := range []types.HookPointDef{
		{Point: HookRequestBefore, Phase: types.BeforeHookPhase},
		{Point: HookRequestAfter, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookRequestFailed, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
	} {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}

	// Per address on the routes, like core's sign-in rule: it slows one
	// client down and can't be used to keep another one out.
	byAddress := func(_ *http.Request, ip string) string { return ip }
	for _, rule := range []types.RouteRateLimitRule{
		{Name: RuleRequestRoute, Method: http.MethodPost, Path: PathRequest, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
		{Name: RuleVerifyRoute, Method: http.MethodPost, Path: PathVerify, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
	} {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(rule); err != nil {
			return err
		}
	}
	// Per email on the request itself, so it also holds for RequestLink
	// called from code. It counts requests for unknown emails too, and so
	// answers the same for both.
	return ic.RateLimits.DeclareHookRateLimitRule(types.HookRateLimitRule{
		Name: RuleRequestEmail, Point: HookRequestBefore,
		KeyFunc: types.KeyByValues(hooks.HookValueEmail), Limit: p.opts.RequestLimit,
	})
}

// Register implements [types.Plugin]. The plugin attaches no handlers to
// other points.
func (p *Plugin) Register(reg types.HookRegistry) error {
	return nil
}

// Middlewares implements [types.Plugin]. The plugin has no middleware.
func (p *Plugin) Middlewares() []types.Middleware {
	return nil
}

// Init implements [types.Plugin]. It checks the options, keeps the
// AuthContext and wraps the two flows with their hook points.
func (p *Plugin) Init(ac *types.AuthContext) error {
	const op = "magiclink.Init"
	if ac.Mailer == nil || !ac.Mailer.Configured() {
		return behemotherr.NewConfigurationError(op, "no mail sender is configured; set BootConfig.Mail.Sender: the plugin does not send email itself", nil)
	}
	if p.opts.TTL < 0 {
		return behemotherr.NewConfigurationError(op, fmt.Sprintf("Options.TTL is negative: %s", p.opts.TTL), nil)
	}
	linkURL, err := url.Parse(p.opts.LinkURL)
	if err != nil || (linkURL.Scheme != "http" && linkURL.Scheme != "https") || linkURL.Host == "" {
		return behemotherr.NewConfigurationError(op,
			fmt.Sprintf("Options.LinkURL %q is not an absolute http or https URL", p.opts.LinkURL), err)
	}
	p.linkURL = linkURL
	p.authContext = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.request = types.WithLifecycle(ac.Dispatcher, HookRequestBefore, HookRequestAfter, HookRequestFailed, p.requestBody)
	p.verify = types.WithLifecycle(ac.Dispatcher, hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed, p.verifyBody)
	return nil
}

// Routes implements [types.Plugin].
func (p *Plugin) Routes() []types.Route {
	return []types.Route{
		{Method: http.MethodPost, Path: PathRequest, Handler: p.handleRequest},
		{Method: http.MethodPost, Path: PathVerify, Handler: p.handleVerify},
	}
}

// afterLookupError marks a failure of a link request that happened after
// the user was found: the token could not be issued, or the send failed. It
// can only happen for an email that has an account, so the route hides it
// like ErrNoAccount. A caller from code gets it, and the error it wraps.
type afterLookupError struct{ err error }

func (e *afterLookupError) Error() string { return e.err.Error() }
func (e *afterLookupError) Unwrap() error { return e.err }

// RequestLink sends a sign-in link to the user with req.Email. It replaces
// the user's earlier links: they stop working once the new one is issued.
// It fires auth.magicLink.beforeRequest, .afterRequest and .requestFailed.
//
// It returns ErrNoAccount when no user has the email, and nothing is sent:
// the plugin does not sign users up. An email of the wrong shape and a
// redirect URL outside the trusted origins are validation errors.
//
// It is the flow behind POST /sign-in/magic-link, for callers that are not
// that route: a CLI, a job, another plugin. Unlike the route it reports
// ErrNoAccount and a failed send. Pass the context of the request being
// handled when there is one. The plugin must have been initialized by Boot.
func (p *Plugin) RequestLink(ctx context.Context, req LinkRequest) (*LinkResult, error) {
	hctx, err := p.operation(ctx, "magiclink.RequestLink")
	if err != nil {
		return nil, err
	}
	publishEmail(hctx, req.Email)
	return p.request(hctx, req)
}

func (p *Plugin) requestBody(hctx *types.HookContext, req LinkRequest) (*LinkResult, error) {
	const op = "magiclink.RequestLink"
	ac := hctx.Auth

	// Both checks come before the lookup, so their answer does not depend
	// on whether the email has an account.
	email := store.NormalizeEmail(req.Email)
	if !utils.IsValidEmail(email) {
		return nil, behemotherr.NewInvalidInputError(op, keyEmail, "invalid email", nil)
	}
	if req.RedirectURL != "" && !types.TrustedRedirect(ac.Origins, req.RedirectURL) {
		return nil, behemotherr.NewInvalidInputError(op, "redirect_url", "redirect URL is not allowed", nil)
	}

	user, err := ac.Store.FindUserByEmail(hctx.Ctx, email)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err // infra error (DB down): not "no such user"
		}
		// Sign-up by link is not built: an unknown email gets no link.
		if failErr := ac.Dispatcher.Fail(hctx, HookRequestFailed, types.FailureReason{
			Code: "userNotFound", Metadata: behemoth.M{hooks.HookValueEmail: email},
		}); failErr != nil {
			return nil, failErr
		}
		return nil, ErrNoAccount
	}

	// From here on a failure is one of a known account, and its audit event
	// says which.
	failed := func(code string, cause error) error {
		if failErr := ac.Dispatcher.Fail(hctx, HookRequestFailed, types.FailureReason{
			Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID,
		}); failErr != nil {
			return failErr
		}
		return &afterLookupError{err: cause}
	}

	// One live link per user. The subject is the user's id and not the
	// email, so Store.DeleteUser removes the links with the user. The email
	// the link was sent to is kept next to it and checked at verify.
	if err := ac.TokenManager.RevokeAllForSubject(hctx.Ctx, types.TokenKindMagicLink, user.ID); err != nil {
		return nil, failed("issueFailed", err)
	}
	meta := behemoth.M{keyEmail: email}
	if req.RedirectURL != "" {
		meta[keyRedirectURL] = req.RedirectURL
	}
	token, rawToken, err := ac.TokenManager.Issue(hctx.Ctx, types.TokenKindMagicLink, user.ID, meta)
	if err != nil {
		return nil, failed("issueFailed", err)
	}

	link := *p.linkURL
	query := link.Query()
	query.Set(keyToken, rawToken)
	link.RawQuery = query.Encode()

	msg := types.MailMessage{
		Kind: types.MailMagicLink, To: email, URL: link.String(), Token: rawToken,
		ExpiresAt: token.ExpiresAt, User: user, Metadata: req.Metadata,
	}
	if p.opts.WaitForSend {
		err = ac.Mailer.Send(hctx.Ctx, msg)
	} else {
		err = ac.Mailer.SendAsync(hctx.Ctx, msg) // an error here means it was not queued
	}
	if err != nil {
		// A link nobody received should not stay valid.
		if revokeErr := ac.TokenManager.Revoke(hctx.Ctx, token.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the link that could not be sent was not revoked", telemetry.ErrorFields(revokeErr))
		}
		return nil, failed("sendFailed", fmt.Errorf("magiclink: send link: %w", err))
	}

	return &LinkResult{UserID: user.ID, Email: email, TokenID: token.ID, ExpiresAt: token.ExpiresAt}, nil
}

// errInvalidLink is Verify's one answer to every link it refuses, so the
// response does not tell an expired link from one that never existed. It is
// typed (unauthorized, 401).
func errInvalidLink() error {
	return behemotherr.NewUnauthorized("magiclink.Verify", ErrorCodeInvalidLink, "invalid or expired link")
}

// isTokenRejection reports whether err says the token is not usable (not
// found, expired, consumed, revoked), as opposed to a failure of the system.
func isTokenRejection(err error) bool {
	return behemotherr.Is(err, behemotherr.CategoryToken) || behemotherr.IsNotFound(err)
}

// Verify signs in the user a link was sent to. rawToken is the "token"
// query parameter of the link. A link works once: the token is consumed
// here, also when a later step refuses the sign-in.
//
// The sign-in fires core's auth.signIn.before, .credentialsVerified, .after
// and .failed, like the email/password plugin's, with Method "magiclink".
// The session is pending instead of active when a handler on
// auth.signIn.credentialsVerified asked for a second factor. Following the
// link shows the user controls the address, so a user whose email was not
// verified is marked verified, unless Options.LeaveEmailUnverified is set.
//
// A link that is unknown, expired, used or replaced by a newer one gets one
// error, with the code ErrorCodeInvalidLink. So does a link of a user who
// was deleted or whose email changed after it was sent.
//
// It is the flow behind POST /magic-link/verify. The raw session token is
// in the result and is the caller's to deliver.
func (p *Plugin) Verify(ctx context.Context, rawToken string) (*VerifyResult, error) {
	hctx, err := p.operation(ctx, "magiclink.Verify")
	if err != nil {
		return nil, err
	}

	// Read the token without consuming it, for what the before point needs:
	// the email, in the payload and published for rate-limit rules. A token
	// that does not check out still goes through the flow, which refuses it
	// and fires auth.signIn.failed.
	in := verifyInput{token: rawToken}
	var redirect string
	token, err := p.authContext.TokenManager.Verify(ctx, types.TokenKindMagicLink, rawToken)
	switch {
	case err == nil:
		in.email, _ = token.MetadataJSON[keyEmail].(string)
		redirect, _ = token.MetadataJSON[keyRedirectURL].(string)
	case !isTokenRejection(err):
		return nil, err
	}
	publishEmail(hctx, in.email)

	result, err := p.verify(hctx, in)
	if err != nil {
		return nil, err
	}
	return &VerifyResult{SignInResult: result, RedirectURL: redirect}, nil
}

func (p *Plugin) verifyBody(hctx *types.HookContext, in verifyInput) (*types.SignInResult, error) {
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	token, err := ac.TokenManager.Consume(hctx.Ctx, types.TokenKindMagicLink, in.token)
	if err != nil {
		if !isTokenRejection(err) {
			return nil, err // infra error: not a bad link
		}
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, types.FailureReason{Code: "invalidMagicLink", Cause: err}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidLink()
	}

	userID := fmt.Sprint(token.Subject)
	rejected := func(code string, cause error) types.FailureReason {
		return types.FailureReason{Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: userID}
	}

	user, err := ac.Store.FindUserByID(hctx.Ctx, userID)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err
		}
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("userNotFound", nil)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidLink()
	}

	// The link proves control of the address it was sent to. If the user's
	// email has changed since, that is no longer the account's address.
	sentTo, _ := token.MetadataJSON[keyEmail].(string)
	if sentTo == "" || sentTo != store.NormalizeEmail(user.Email) {
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("emailChanged", nil)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidLink()
	}

	if !user.EmailVerified && !p.opts.LeaveEmailUnverified {
		user, err = ac.Store.UpdateUser(hctx.Ctx, user.ID, behemoth.M{models.UserEmailVerified: true})
		if err != nil {
			return nil, err
		}
	}

	// The seam a 2FA plugin hooks, as in the email/password sign-in.
	checkpoint, err := dispatcher.RunBefore(hctx, hooks.HookSignInCredentialsVerified,
		behemoth.M{hooks.HookValueUserID: user.ID})
	if err != nil {
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("secondFactorRejected", err)); failErr != nil {
			return nil, failErr
		}
		return nil, err
	}
	state := types.SessionActive
	if requireStepUp, _ := checkpoint["requireStepUp"].(bool); requireStepUp {
		state = types.SessionPending
	}

	session, rawToken, err := ac.SessionManager.Create(hctx.Ctx, user.ID, types.SessionMeta{State: state})
	if err != nil {
		return nil, err
	}
	return &types.SignInResult{User: user, Session: session, RawToken: rawToken, Method: PluginName}, nil
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

// publishEmail puts the normalized email of a flow in the operation's
// Values, under hooks.HookValueEmail, where a rate-limit rule on the flow's
// before point keys on it. A call without an email leaves no entry and
// removes an inherited one, so a rule per email does not apply to it.
func publishEmail(hctx *types.HookContext, email string) {
	if email = store.NormalizeEmail(email); email == "" {
		delete(hctx.Values, hooks.HookValueEmail)
		return
	}
	hctx.Values[hooks.HookValueEmail] = email
}

// handleRequest answers every well-formed request the same, whether or not
// the email has an account: an unknown email, a token that could not be
// issued and a failed send are all a 200. A validation error and a rate
// limit are reported, since they do not depend on the account. Anything else
// is a failure of the system and a 500 from the router.
func (p *Plugin) handleRequest(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("magiclink.RequestLink", "request", err)
	}
	var req LinkRequest
	if err := req.FromMap(body); err != nil {
		return err
	}

	_, err := p.RequestLink(rctx.Ctx, req)
	if hidden, ok := errors.AsType[*afterLookupError](err); ok {
		// Nothing tells the client, so this line is the only report.
		p.log.Error(rctx.Ctx, "magic link was not sent", telemetry.ErrorFields(hidden.err))
		err = nil
	}
	if err != nil && !errors.Is(err, ErrNoAccount) {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// handleVerify returns Verify's error unchanged, and the router maps it: a
// refused link is a typed unauthorized error (401), and a hook handler's
// typed rejection keeps its own status.
func (p *Plugin) handleVerify(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("magiclink.Verify", "request", err)
	}
	rawToken, _ := body[keyToken].(string)
	if rawToken == "" {
		return behemotherr.NewInvalidInputError("magiclink.Verify", keyToken, "token is required", nil)
	}

	result, err := p.Verify(rctx.Ctx, rawToken)
	if err != nil {
		return err
	}

	// The body every sign-in route answers with, plus the redirect, and
	// the session token by whichever transport SessionConfig.Transport names.
	return types.WriteSignIn(rctx, result.SignInResult, behemoth.M{keyRedirectURL: result.RedirectURL})
}

var _ types.Plugin = (*Plugin)(nil)
