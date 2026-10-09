// Package emailverification is the email verification plugin: it sends a
// user a link that confirms they control their address, and sets
// EmailVerified on the user when the link is followed.
//
// It does not depend on how the user signed up. It listens to the store's
// data points for users, so a user created by the email/password plugin, by
// another sign-in plugin or from a CLI is sent a link the same way. The
// magic link plugin needs nothing from it: following a sign-in link
// verifies the address already.
//
// It also has the flow for changing an address (change.go, off unless
// Options.ChangeLinkURL and RevertLinkURL are set): the address is replaced
// once the new one has confirmed, and the old one is told and can undo it.
package emailverification

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
// owns the plugin's routes, hook points, handlers and rate-limit rules.
const PluginName = "emailverification"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// DefaultTTL is how long a link works when Options.TTL is zero. It is
// longer than a sign-in link's: the link grants nothing but the verified
// flag, and people confirm an address hours after signing up.
const DefaultTTL = 24 * time.Hour

// The points the plugin declares and fires.
const (
	// HookSendBefore runs before a link is sent, on "email", "redirectURL"
	// and "metadata". A handler may rewrite the last two or stop the send.
	HookSendBefore types.HookPoint = "auth.emailVerification.beforeSend"
	// HookSendAfter runs once the message has been queued, with a
	// *SendResult.
	HookSendAfter types.HookPoint = "auth.emailVerification.afterSend"
	// HookSendFailed fires for a send that queued nothing: codes
	// "userNotFound", "issueFailed", "sendFailed" and "rejectedByHook".
	HookSendFailed types.HookPoint = "auth.emailVerification.sendFailed"

	// HookVerifyBefore runs before a link is verified. Veto only.
	HookVerifyBefore types.HookPoint = "auth.emailVerification.beforeVerify"
	// HookVerifyAfter runs once the user is marked verified, with the
	// *models.User.
	HookVerifyAfter types.HookPoint = "auth.emailVerification.afterVerify"
	// HookVerifyFailed fires for a link that was refused: codes
	// "invalidLink", "userNotFound", "emailChanged" and "rejectedByHook".
	HookVerifyFailed types.HookPoint = "auth.emailVerification.verifyFailed"
)

// Names of the rate-limit rules the plugin declares.
const (
	RuleSendRoute   = "emailverification.send.route"   // send requests per client address
	RuleVerifyRoute = "emailverification.verify.route" // verify attempts per client address
	RuleSendEmail   = "emailverification.send.email"   // links sent per email, from any caller
)

// Paths of the plugin's routes, below the router's base path.
const (
	PathSend   = "/email/send-verification"
	PathVerify = "/email/verify"
)

// Keys of the hook payloads and request bodies.
const (
	keyEmail       = "email"
	keyRedirectURL = "redirectURL"
	keyMetadata    = "metadata"
	keyToken       = "token"
)

// valueEmailChanged is the note the plugin's data.user.beforeUpdate handler
// leaves in the update's Values for its data.user.updated handler: this
// update changed the address, so a new link is due once it has committed.
const valueEmailChanged = PluginName + ".emailChanged"

// ErrorCodeInvalidLink is the code of the error Verify returns for a link
// it refuses: unknown, expired, already used, replaced by a newer link, or
// for a user who is gone or has changed email since.
const ErrorCodeInvalidLink = "invalid_verification_link"

// ErrorCodeEmailNotVerified is the code of the error a sign-in gets when
// Options.RequireVerified is set and the user's email is not verified.
const ErrorCodeEmailNotVerified = "email_not_verified"

// ErrNoAccount is returned by SendVerification when no user matches. The
// route does not report it: it answers the same for every email.
var ErrNoAccount = errors.New("emailverification: no account matches")

// ErrAlreadyVerified is returned by SendVerification for a user whose email
// is verified. Nothing is sent, and the route does not report it either.
var ErrAlreadyVerified = errors.New("emailverification: the email is already verified")

// SendRequest is the input of SendVerification. Set UserID or Email.
//
// It implements [behemoth.Serializable], which is how WithLifecycle turns it
// into the auth.emailVerification.beforeSend payload and back.
type SendRequest struct {
	// UserID names the user to send to. It takes precedence over Email.
	UserID string
	// Email names the user by address, for a caller that has no user yet:
	// the route.
	Email string
	// RedirectURL is where the application should send the user after the
	// link is verified. Optional. It has to be a path on the application's
	// own site or a URL on one of RouterConfig.TrustedOrigins. Verify
	// returns it.
	RedirectURL string
	// Metadata is passed to the mail sender as it is, in
	// MailMessage.Metadata. Optional. The plugin does not read or store it.
	Metadata behemoth.M

	// user is the user UserID named, looked up before the flow so that its
	// email can be published for rate-limit rules.
	user *models.User
	// inFlow is set once the request has entered the flow. FromMap then
	// reads a rewritten payload and not a request body.
	inFlow bool
}

// ToMap returns the request as a hook payload.
func (r *SendRequest) ToMap() (map[string]any, error) {
	m := map[string]any{keyEmail: r.Email, keyRedirectURL: r.RedirectURL}
	if r.Metadata != nil {
		m[keyMetadata] = r.Metadata
	}
	return m, nil
}

// FromMap sets the request from a request body or a rewritten payload. From
// a payload only the redirect URL and the metadata are taken: who the link
// goes to is not a handler's to change. A value of the wrong type is a
// validation error.
func (r *SendRequest) FromMap(data map[string]any) error {
	email, redirect, metadata, err := requestFields("emailverification.SendVerification", data)
	if err != nil {
		return err
	}
	if !r.inFlow {
		r.Email = email
	}
	r.RedirectURL, r.Metadata = redirect, metadata
	return nil
}

// requestFields reads the three fields a request body and a before payload
// share: "email", "redirectURL" and "metadata". A missing key is empty; a
// value of the wrong type is a validation error.
func requestFields(op string, data map[string]any) (email, redirect string, metadata behemoth.M, err error) {
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
	if email, err = field(keyEmail); err != nil {
		return "", "", nil, err
	}
	if redirect, err = field(keyRedirectURL); err != nil {
		return "", "", nil, err
	}
	switch v := data[keyMetadata].(type) {
	case nil:
	case behemoth.M: // a payload a handler built, or a caller's request
		metadata = v
	case map[string]any: // a decoded request body
		metadata = v
	default:
		return "", "", nil, behemotherr.NewInvalidInputError(op, keyMetadata, keyMetadata+" must be an object", nil)
	}
	return email, redirect, metadata, nil
}

// SendResult is what SendVerification returns and what handlers on
// auth.emailVerification.afterSend receive. It does not hold the token.
type SendResult struct {
	UserID    string
	Email     string
	TokenID   string
	ExpiresAt time.Time
}

// AuditSubject implements [types.AuditSubject]: a verification is about the
// user whose address it confirms.
func (r *SendResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// VerifyResult is what Verify returns.
type VerifyResult struct {
	// User is the user, with EmailVerified set.
	User *models.User
	// RedirectURL is SendRequest.RedirectURL, checked against the trusted
	// origins when the link was sent. Empty when none was given.
	RedirectURL string
}

// verifyInput is the input of the wrapped verify flow. Its payload on
// auth.emailVerification.beforeVerify is "email", when the token names one.
// The token is not in the payload and nothing is read back.
type verifyInput struct {
	token string
	email string
}

func (v *verifyInput) ToMap() (map[string]any, error) {
	m := map[string]any{}
	if v.email != "" {
		m[keyEmail] = v.email
	}
	return m, nil
}

func (v *verifyInput) FromMap(map[string]any) error { return nil }

// Options configures the plugin. LinkURL is required, and so is a mail
// sender in BootConfig.Mail: the plugin sends nothing itself. The link goes
// out as a types.MailMessage of kind types.MailEmailVerification.
type Options struct {
	// LinkURL is the page of the application the link points to, such as
	// "https://app.example.com/auth/verify-email". Required, absolute, http
	// or https. The plugin adds the token as the "token" query parameter.
	// The page posts that token to the verify route; a link that verified
	// on a GET would be used up by mail scanners that open links.
	LinkURL string

	// TTL is how long a link works. Zero means DefaultTTL.
	// TokenConfig.TTLOverrides for types.TokenKindEmailVerification takes
	// precedence.
	TTL time.Duration

	// SendLimit bounds the links sent per email, from any caller: the
	// route, the automatic send for a new user, a CLI. Zero means 5 per 15
	// minutes.
	SendLimit types.Limit

	// RequireVerified refuses the sign-in of a user whose email is not
	// verified, with a forbidden error (ErrorCodeEmailNotVerified). It
	// applies to every sign-in that fires auth.signIn.credentialsVerified.
	// The user asks for a new link through the send route, which needs no
	// session.
	RequireVerified bool

	// ChangeLinkURL and RevertLinkURL turn the email change flow on (see
	// RequestChange). Set both or neither. Like LinkURL they are pages of
	// the application, absolute, http or https, and get the token as the
	// "token" query parameter. The page at ChangeLinkURL posts it to the
	// confirm route, the one at RevertLinkURL to the revert route.
	ChangeLinkURL string
	RevertLinkURL string

	// ChangeTTL is how long the link that confirms a new address works.
	// Zero means DefaultChangeTTL.
	ChangeTTL time.Duration

	// RevertTTL is how long the link sent to the old address can undo the
	// change. Zero means DefaultRevertTTL. For that long the old mailbox
	// keeps a say over the account, which is the point of it and also its
	// cost: see docs/api/emailverification.md.
	RevertTTL time.Duration

	// ChangeLimit bounds change requests per user, from any caller. Each
	// request sends a notice to the current address. Zero means 3 an hour.
	ChangeLimit types.Limit
}

// Plugin is the email verification plugin. It adds the send and verify
// routes, declares the email_verification token kind, the
// auth.emailVerification.* points and its rate-limit rules, and registers
// handlers on the user data points that send a link when a user is created
// unverified or changes address. With the email change flow on it adds that
// flow's routes, token kinds, points and rules too. It needs no table of its
// own.
type Plugin struct {
	opts        Options
	linkURL     *url.URL
	changeURL   *url.URL // nil when the change flow is off
	revertURL   *url.URL
	authContext *types.AuthContext
	log         telemetry.Logger
	send        func(hctx *types.HookContext, in SendRequest) (*SendResult, error)
	verify      func(hctx *types.HookContext, in verifyInput) (*models.User, error)

	// the email change flow (change.go)
	changeRequest func(hctx *types.HookContext, in ChangeRequest) (*ChangeResult, error)
	changeConfirm func(hctx *types.HookContext, in changeTokenInput) (*models.User, error)
	changeRevert  func(hctx *types.HookContext, in changeTokenInput) (*models.User, error)
}

// New returns the plugin configured with opts. Values left at zero take
// their defaults. Missing or invalid options are reported by Init, as a
// configuration error from Boot.
func New(opts Options) *Plugin {
	if opts.TTL == 0 {
		opts.TTL = DefaultTTL
	}
	if opts.SendLimit == (types.Limit{}) {
		opts.SendLimit = types.Limit{Max: 5, Window: 15 * time.Minute}
	}
	if opts.ChangeTTL == 0 {
		opts.ChangeTTL = DefaultChangeTTL
	}
	if opts.RevertTTL == 0 {
		opts.RevertTTL = DefaultRevertTTL
	}
	if opts.ChangeLimit == (types.Limit{}) {
		opts.ChangeLimit = types.Limit{Max: 3, Window: time.Hour}
	}
	return &Plugin{opts: opts}
}

// Meta implements [types.Plugin]. The plugin depends on no other plugin: it
// works with any plugin that creates users, and without one.
func (p *Plugin) Meta() types.PluginMeta {
	return types.PluginMeta{Name: PluginName}
}

// Version implements [types.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [types.Plugin]. The plugin declares:
//   - the token kind types.TokenKindEmailVerification: single use, kept in
//     the database, so that a new link can revoke the user's earlier ones
//     and a deleted user's links go with the user;
//   - the auth.emailVerification.* points around a send and a verify;
//   - three rate-limit rules: send requests and verify attempts per client
//     address, and links sent per email.
func (p *Plugin) Declare(ic *types.PluginInitContext) error {
	if err := ic.Tokens.Declare(types.TokenKindDef{
		Kind: types.TokenKindEmailVerification, SingleUse: true, DefaultTTL: p.opts.TTL, Backend: types.TokenBackendDB,
	}); err != nil {
		return err
	}

	for _, def := range []types.HookPointDef{
		{Point: HookSendBefore, Phase: types.BeforeHookPhase},
		{Point: HookSendAfter, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookSendFailed, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookVerifyBefore, Phase: types.BeforeHookPhase},
		{Point: HookVerifyAfter, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookVerifyFailed, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
	} {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}

	byAddress := func(_ *http.Request, ip string) string { return ip }
	for _, rule := range []types.RouteRateLimitRule{
		{Name: RuleSendRoute, Method: http.MethodPost, Path: PathSend, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
		{Name: RuleVerifyRoute, Method: http.MethodPost, Path: PathVerify, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
	} {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(rule); err != nil {
			return err
		}
	}
	// Per email on the send itself, so it also bounds the automatic sends
	// and SendVerification called from code. From the route it counts
	// requests for unknown emails too, and so answers the same for both.
	if err := ic.RateLimits.DeclareHookRateLimitRule(types.HookRateLimitRule{
		Name: RuleSendEmail, Point: HookSendBefore,
		KeyFunc: types.KeyByValues(hooks.HookValueEmail), Limit: p.opts.SendLimit,
	}); err != nil {
		return err
	}
	if p.changeEnabled() {
		return p.declareChange(ic, byAddress)
	}
	return nil
}

// Register implements [types.Plugin]. This is how the plugin serves every
// way of creating a user without knowing any of them:
//   - data.user.created: a user who was created unverified is sent a link;
//   - data.user.beforeUpdate: an update that changes the address clears
//     EmailVerified, unless the update sets it itself;
//   - data.user.updated: after such an update, the new address is sent a
//     link;
//   - auth.signIn.credentialsVerified, with Options.RequireVerified: an
//     unverified user's sign-in is refused.
//
// The two sends run after the write has committed, and a failure there is
// logged by the dispatcher: the user was created either way, and asks for a
// link through the send route.
//
// The two update handlers are a fallback, for a write that changes the
// address directly. They keep EmailVerified true to its name; they do not
// keep the old address until the new one confirms. RequestChange does that,
// and its own writes pass these handlers untouched, because they set the
// address and the flag together.
func (p *Plugin) Register(reg types.HookRegistry) error {
	if err := reg.OnAfter(hooks.HookUserCreated, func(hctx *types.HookContext, result any) error {
		user, _ := result.(*models.User)
		return p.sendTo(hctx.Ctx, user)
	}, nil); err != nil {
		return err
	}

	if err := reg.OnBefore(hooks.HookUserBeforeUpdate, func(hctx *types.HookContext, changes behemoth.M) (behemoth.M, error) {
		newEmail, ok := changes[models.UserEmail].(string)
		if !ok {
			return nil, nil // the address is not being changed
		}
		id, _ := hctx.Values[hooks.HookValueUserID].(string)
		current, err := hctx.Tx.FindUserByID(hctx.Ctx, id)
		if err != nil {
			return nil, err
		}
		if store.NormalizeEmail(newEmail) == store.NormalizeEmail(current.Email) {
			return nil, nil
		}
		// An update that sets the flag itself is left alone: an admin
		// screen that changes an address it has checked, for example.
		if _, set := changes[models.UserEmailVerified]; !set {
			changes[models.UserEmailVerified] = false
		}
		hctx.Values[valueEmailChanged] = true
		return changes, nil
	}, nil); err != nil {
		return err
	}

	if err := reg.OnAfter(hooks.HookUserUpdated, func(hctx *types.HookContext, result any) error {
		if changed, _ := hctx.Values[valueEmailChanged].(bool); !changed {
			return nil
		}
		user, _ := result.(*models.User)
		return p.sendTo(hctx.Ctx, user)
	}, nil); err != nil {
		return err
	}

	if !p.opts.RequireVerified {
		return nil
	}
	return reg.OnBefore(hooks.HookSignInCredentialsVerified, func(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
		id, _ := payload[hooks.HookValueUserID].(string)
		user, err := hctx.Auth.Store.FindUserByID(hctx.Ctx, id)
		if err != nil {
			return nil, err
		}
		if !user.EmailVerified {
			return nil, &behemotherr.DomainError{
				Category: behemotherr.CategoryForbidden, Op: "emailverification.RequireVerified",
				Code: ErrorCodeEmailNotVerified, PublicMessage: "email address is not verified",
				InternalMessage: "emailverification.RequireVerified: email address is not verified",
			}
		}
		return nil, nil
	}, nil)
}

// sendTo sends a link to user from one of the plugin's data hook handlers.
// A user who needs none (no user, verified already) is not an error.
func (p *Plugin) sendTo(ctx context.Context, user *models.User) error {
	if user == nil || user.EmailVerified || user.Email == "" {
		return nil
	}
	_, err := p.sendVerification(ctx, SendRequest{user: user})
	if errors.Is(err, ErrAlreadyVerified) {
		return nil
	}
	return err
}

// Middlewares implements [types.Plugin]. The plugin has no middleware.
func (p *Plugin) Middlewares() []types.Middleware {
	return nil
}

// Init implements [types.Plugin]. It checks the options, keeps the
// AuthContext and wraps the two flows with their hook points.
func (p *Plugin) Init(ac *types.AuthContext) error {
	const op = "emailverification.Init"
	if ac.Mailer == nil || !ac.Mailer.Configured() {
		return behemotherr.NewConfigurationError(op, "no mail sender is configured; set BootConfig.Mail.Sender: the plugin does not send email itself", nil)
	}
	if p.opts.TTL < 0 {
		return behemotherr.NewConfigurationError(op, fmt.Sprintf("Options.TTL is negative: %s", p.opts.TTL), nil)
	}
	page, err := parseLinkURL(op, "LinkURL", p.opts.LinkURL)
	if err != nil {
		return err
	}
	p.linkURL = page
	p.authContext = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.send = types.WithLifecycle(ac.Dispatcher, HookSendBefore, HookSendAfter, HookSendFailed, p.sendBody)
	p.verify = types.WithLifecycle(ac.Dispatcher, HookVerifyBefore, HookVerifyAfter, HookVerifyFailed, p.verifyBody)
	if p.changeEnabled() {
		return p.initChange(ac)
	}
	return nil
}

// parseLinkURL parses one of the options that name a page of the application.
func parseLinkURL(op, option, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, behemotherr.NewConfigurationError(op,
			fmt.Sprintf("Options.%s %q is not an absolute http or https URL", option, raw), err)
	}
	return u, nil
}

// withToken returns page with rawToken added as the "token" query
// parameter, keeping any query page already has.
func withToken(page *url.URL, rawToken string) string {
	link := *page
	query := link.Query()
	query.Set(keyToken, rawToken)
	link.RawQuery = query.Encode()
	return link.String()
}

// Routes implements [types.Plugin]. The send and verify routes need no
// session: with Options.RequireVerified a user who has to verify can't sign
// in to get one. With the email change flow on, its three routes are added
// (changeRoutes).
func (p *Plugin) Routes() []types.Route {
	routes := []types.Route{
		{Method: http.MethodPost, Path: PathSend, Handler: p.handleSend},
		{Method: http.MethodPost, Path: PathVerify, Handler: p.handleVerify},
	}
	if p.changeEnabled() {
		routes = append(routes, p.changeRoutes()...)
	}
	return routes
}

// afterLookupError marks a failure of a send that happened after the user
// was found: the token could not be issued, or the message could not be
// queued. It can only happen for an email that has an account, so the route
// hides it like ErrNoAccount. A caller from code gets it, and the error it
// wraps.
type afterLookupError struct{ err error }

func (e *afterLookupError) Error() string { return e.err.Error() }
func (e *afterLookupError) Unwrap() error { return e.err }

// SendVerification sends a verification link to the user req names, by
// UserID or by Email. It replaces the user's earlier links. The message is
// handed to the mail sender in the background (Mailer.SendAsync), so the
// call does not wait for it: a send that fails later is logged by the
// mailer, and the user asks again. It fires
// auth.emailVerification.beforeSend, .afterSend and .sendFailed.
//
// It returns ErrNoAccount when no user matches and ErrAlreadyVerified when
// there is nothing to verify; neither sends anything. A redirect URL
// outside the trusted origins is a validation error.
//
// The plugin calls it itself for a new user and after a change of address.
// It is also the flow behind POST /email/send-verification, which unlike
// this method reports neither sentinel. The plugin must have been
// initialized by Boot.
func (p *Plugin) SendVerification(ctx context.Context, req SendRequest) (*SendResult, error) {
	return p.sendVerification(ctx, req)
}

func (p *Plugin) sendVerification(ctx context.Context, req SendRequest) (*SendResult, error) {
	hctx, err := p.operation(ctx, "emailverification.SendVerification")
	if err != nil {
		return nil, err
	}
	// A request by id is resolved here, before the flow: the email has to
	// be in Values when the before point's rate limit runs.
	if req.user == nil && req.UserID != "" {
		req.user, err = p.authContext.Store.FindUserByID(ctx, req.UserID)
		if err != nil {
			if behemotherr.IsNotFound(err) {
				return nil, ErrNoAccount
			}
			return nil, err
		}
	}
	if req.user != nil {
		req.UserID, req.Email = req.user.ID, req.user.Email
	}
	req.Email = store.NormalizeEmail(req.Email)
	publishEmail(hctx, req.Email)
	req.inFlow = true
	return p.send(hctx, req)
}

func (p *Plugin) sendBody(hctx *types.HookContext, req SendRequest) (*SendResult, error) {
	const op = "emailverification.SendVerification"
	ac := hctx.Auth

	// Both checks come before the lookup, so their answer does not depend
	// on whether the email has an account.
	email := req.Email
	if !utils.IsValidEmail(email) {
		return nil, behemotherr.NewInvalidInputError(op, keyEmail, "invalid email", nil)
	}
	if req.RedirectURL != "" && !types.TrustedRedirect(ac.Origins, req.RedirectURL) {
		return nil, behemotherr.NewInvalidInputError(op, "redirect_url", "redirect URL is not allowed", nil)
	}

	user := req.user
	if user == nil {
		found, err := ac.Store.FindUserByEmail(hctx.Ctx, email)
		if err != nil {
			if !behemotherr.IsNotFound(err) {
				return nil, err // infra error (DB down): not "no such user"
			}
			if failErr := ac.Dispatcher.Fail(hctx, HookSendFailed, types.FailureReason{
				Code: "userNotFound", Metadata: behemoth.M{hooks.HookValueEmail: email},
			}); failErr != nil {
				return nil, failErr
			}
			return nil, ErrNoAccount
		}
		user = found
	}
	// Sending to a verified user does nothing, which is what makes a
	// repeated request harmless.
	if user.EmailVerified {
		return nil, ErrAlreadyVerified
	}

	failed := func(code string, cause error) error {
		if failErr := ac.Dispatcher.Fail(hctx, HookSendFailed, types.FailureReason{
			Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID,
		}); failErr != nil {
			return failErr
		}
		return &afterLookupError{err: cause}
	}

	// One live link per user. The subject is the user's id, so
	// Store.DeleteUser removes the links with the user. The address the
	// link was sent to is kept next to it and checked at verify.
	if err := ac.TokenManager.RevokeAllForSubject(hctx.Ctx, types.TokenKindEmailVerification, user.ID); err != nil {
		return nil, failed("issueFailed", err)
	}
	meta := behemoth.M{keyEmail: email}
	if req.RedirectURL != "" {
		meta[keyRedirectURL] = req.RedirectURL
	}
	token, rawToken, err := ac.TokenManager.Issue(hctx.Ctx, types.TokenKindEmailVerification, user.ID, meta)
	if err != nil {
		return nil, failed("issueFailed", err)
	}

	// In the background: the request, often a sign-up, does not wait for
	// the mail provider. An error here means the message was not queued.
	err = ac.Mailer.SendAsync(hctx.Ctx, types.MailMessage{
		Kind: types.MailEmailVerification, To: email, URL: withToken(p.linkURL, rawToken), Token: rawToken,
		ExpiresAt: token.ExpiresAt, User: user, Metadata: req.Metadata,
	})
	if err != nil {
		if revokeErr := ac.TokenManager.Revoke(hctx.Ctx, token.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the link that could not be queued was not revoked", telemetry.ErrorFields(revokeErr))
		}
		return nil, failed("sendFailed", fmt.Errorf("emailverification: queue link: %w", err))
	}

	return &SendResult{UserID: user.ID, Email: email, TokenID: token.ID, ExpiresAt: token.ExpiresAt}, nil
}

// errInvalidLink is Verify's one answer to every link it refuses. It is
// typed (unauthorized, 401).
func errInvalidLink() error {
	return behemotherr.NewUnauthorized("emailverification.Verify", ErrorCodeInvalidLink, "invalid or expired link")
}

// isTokenRejection reports whether err says the token is not usable (not
// found, expired, consumed, revoked), as opposed to a failure of the system.
func isTokenRejection(err error) bool {
	return behemotherr.Is(err, behemotherr.CategoryToken) || behemotherr.IsNotFound(err)
}

// Verify marks the email of the user a link was sent to as verified.
// rawToken is the "token" query parameter of the link. A link works once.
// It fires auth.emailVerification.beforeVerify, .afterVerify and
// .verifyFailed.
//
// A link that is unknown, expired, used or replaced by a newer one gets one
// error, with the code ErrorCodeInvalidLink. So does a link of a user who
// was deleted or whose email changed after it was sent.
//
// It does not sign the user in: no session is created. It is the flow
// behind POST /email/verify.
func (p *Plugin) Verify(ctx context.Context, rawToken string) (*VerifyResult, error) {
	hctx, err := p.operation(ctx, "emailverification.Verify")
	if err != nil {
		return nil, err
	}

	// Read the token without consuming it, for the redirect URL and for
	// the email the before point gets. A token that does not check out
	// still goes through the flow, which refuses it and fires the failed
	// point.
	in := verifyInput{token: rawToken}
	var redirect string
	token, err := p.authContext.TokenManager.Verify(ctx, types.TokenKindEmailVerification, rawToken)
	switch {
	case err == nil:
		in.email, _ = token.MetadataJSON[keyEmail].(string)
		redirect, _ = token.MetadataJSON[keyRedirectURL].(string)
	case !isTokenRejection(err):
		return nil, err
	}
	publishEmail(hctx, in.email)

	user, err := p.verify(hctx, in)
	if err != nil {
		return nil, err
	}
	return &VerifyResult{User: user, RedirectURL: redirect}, nil
}

func (p *Plugin) verifyBody(hctx *types.HookContext, in verifyInput) (*models.User, error) {
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	token, err := ac.TokenManager.Consume(hctx.Ctx, types.TokenKindEmailVerification, in.token)
	if err != nil {
		if !isTokenRejection(err) {
			return nil, err // infra error: not a bad link
		}
		if failErr := dispatcher.Fail(hctx, HookVerifyFailed, types.FailureReason{Code: "invalidLink", Cause: err}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidLink()
	}

	userID := fmt.Sprint(token.Subject)
	refuse := func(code string) error {
		if failErr := dispatcher.Fail(hctx, HookVerifyFailed, types.FailureReason{
			Code: code, SubjectType: models.UserTable, SubjectID: userID,
		}); failErr != nil {
			return failErr
		}
		return errInvalidLink()
	}

	user, err := ac.Store.FindUserByID(hctx.Ctx, userID)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err
		}
		return nil, refuse("userNotFound")
	}

	// The link confirms the address it was sent to. If the user's email
	// has changed since, that address is no longer the account's.
	sentTo, _ := token.MetadataJSON[keyEmail].(string)
	if sentTo == "" || sentTo != store.NormalizeEmail(user.Email) {
		return nil, refuse("emailChanged")
	}

	if user.EmailVerified {
		return user, nil // verified some other way since the link was sent
	}
	return ac.Store.UpdateUser(hctx.Ctx, user.ID, behemoth.M{models.UserEmailVerified: true})
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

// handleSend answers every well-formed request the same: an unknown email,
// an email that is verified already, and a link that could not be issued or
// queued are all a 200, so the response does not tell which addresses have
// an account. A validation error and a rate limit are reported, since they
// do not depend on the account.
func (p *Plugin) handleSend(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("emailverification.SendVerification", "request", err)
	}
	var req SendRequest
	if err := req.FromMap(body); err != nil {
		return err
	}

	_, err := p.SendVerification(rctx.Ctx, req)
	if hidden, ok := errors.AsType[*afterLookupError](err); ok {
		// Nothing tells the client, so this line is the only report.
		p.log.Error(rctx.Ctx, "verification link was not sent", telemetry.ErrorFields(hidden.err))
		err = nil
	}
	if err != nil && !errors.Is(err, ErrNoAccount) && !errors.Is(err, ErrAlreadyVerified) {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// handleVerify returns Verify's error unchanged, and the router maps it: a
// refused link is a typed unauthorized error (401).
func (p *Plugin) handleVerify(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("emailverification.Verify", "request", err)
	}
	rawToken, _ := body[keyToken].(string)
	if rawToken == "" {
		return behemotherr.NewInvalidInputError("emailverification.Verify", keyToken, "token is required", nil)
	}

	result, err := p.Verify(rctx.Ctx, rawToken)
	if err != nil {
		return err
	}
	user, err := rctx.Auth.Public.Of(result.User) // the public columns, not the model
	if err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{types.SignInUserKey: user, keyRedirectURL: result.RedirectURL})
}

var _ types.Plugin = (*Plugin)(nil)
