package emailpassword

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

// Password reset is two flows. RequestPasswordReset issues a single-use
// token for the user and hands the link to the application's mail sender
// (AuthContext.Mailer). ResetPassword consumes the token, sets the new
// password, ends the user's sessions and sends the user a notice. The flows are off until
// Options.Reset.LinkURL is set.
//
// They follow the magic link plugin's request and verify flows. The
// difference is the second half: a magic link ends in a session, and a reset
// ends in a new password and no session.

// DefaultResetTTL is how long a reset link works when ResetOptions.TTL is
// zero.
const DefaultResetTTL = time.Hour

// The points the plugin declares and fires around a password reset, when
// reset is enabled.
const (
	// HookResetRequestBefore runs on a reset request's input: "email" and
	// "metadata". A handler may rewrite them or stop the request.
	HookResetRequestBefore types.HookPoint = "auth.passwordReset.beforeRequest"
	// HookResetRequestAfter runs once the link has been handed to the mail
	// sender, with a *ResetRequestResult.
	HookResetRequestAfter types.HookPoint = "auth.passwordReset.afterRequest"
	// HookResetRequestFailed fires for a request that sent no link: codes
	// "userNotFound", "issueFailed", "sendFailed" and "rejectedByHook".
	HookResetRequestFailed types.HookPoint = "auth.passwordReset.requestFailed"

	// HookResetBefore runs before a token is consumed, with "password" and,
	// when the token names one, "email". A handler can stop the reset. What
	// it writes to the payload is not read back.
	HookResetBefore types.HookPoint = "auth.passwordReset.before"
	// HookResetAfter runs once the password is set and the user's sessions
	// have ended, with the *models.User.
	HookResetAfter types.HookPoint = "auth.passwordReset.after"
	// HookResetFailed fires for a reset that set no password: codes
	// "invalidToken", "userNotFound", "emailChanged" and "rejectedByHook".
	HookResetFailed types.HookPoint = "auth.passwordReset.failed"
)

// Names of the rate-limit rules the plugin declares when reset is enabled.
const (
	RuleResetRequestRoute = "emailpassword.reset.request.route" // reset requests per client address
	RuleResetConfirmRoute = "emailpassword.reset.confirm.route" // reset attempts per client address
	RuleResetRequestEmail = "emailpassword.reset.request.email" // reset requests per email, from any caller
)

// Paths of the reset routes, below the router's base path.
const (
	PathResetRequest = "/password-reset/request"
	PathResetConfirm = "/password-reset/confirm"
)

// Keys of the reset flows' hook payloads and request bodies.
const (
	resetMetadataKey = "metadata"
	resetTokenKey    = "token"
)

// ErrorCodeInvalidResetToken is the code of the error ResetPassword returns
// for a link it refuses: unknown, expired, already used, replaced by a newer
// link, or for a user who is gone or has changed email since.
const ErrorCodeInvalidResetToken = "invalid_reset_token"

// SessionRevokedPasswordReset is the revoke reason of the sessions a
// password reset ends.
const SessionRevokedPasswordReset = "password_reset"

// ErrNoAccount is returned by RequestPasswordReset when no user has the
// email. The route does not report it: it answers the same for every email,
// so the response does not tell which addresses have an account.
var ErrNoAccount = errors.New("emailpassword: no account with this email")

// ResetOptions configures password reset. It is off while LinkURL is empty:
// the plugin then adds no reset routes and needs no mail sender.
type ResetOptions struct {
	// LinkURL is the page of the application the link points to, such as
	// "https://app.example.com/auth/reset". Setting it turns reset on.
	// Absolute, http or https. The plugin adds the token as the "token"
	// query parameter. The page asks for the new password and posts both
	// to the confirm route.
	LinkURL string

	// TTL is how long a link works. Zero means DefaultResetTTL.
	// TokenConfig.TTLOverrides for types.TokenKindPasswordReset takes
	// precedence.
	TTL time.Duration

	// RequestLimit bounds reset requests per email, from any caller. It
	// keeps one address from being sent link after link. Zero means 5 per
	// 15 minutes.
	RequestLimit types.Limit

	// WaitForSend chooses how the link is handed to the mail sender.
	//
	// false (the default): the request returns once the message is queued
	// (Mailer.SendAsync). A failed send is logged by the mailer and the
	// user asks again. The sender's speed then does not show in the
	// response time, which would tell a known email from an unknown one.
	//
	// true: the request waits for the sender (Mailer.Send). A failed send
	// revokes the link and fires auth.passwordReset.requestFailed.
	WaitForSend bool

	// LeaveEmailUnverified turns off marking the address as verified. By
	// default a completed reset sets EmailVerified on a user who did not
	// have it: the link was sent to the address, so following it shows the
	// user controls it. Set it when verified should only ever mean "went
	// through the application's own verification".
	LeaveEmailUnverified bool
}

// enabled reports whether the application turned reset on.
func (o ResetOptions) enabled() bool { return o.LinkURL != "" }

// ResetRequest is the input of RequestPasswordReset.
//
// It implements [behemoth.Serializable], which is how WithLifecycle turns it
// into the auth.passwordReset.beforeRequest payload and back.
type ResetRequest struct {
	// Email is the address of the account whose password to reset.
	Email string
	// Metadata is passed to the mail sender as it is, in
	// MailMessage.Metadata: a locale, a template name. Optional. The plugin
	// does not read or store it.
	Metadata behemoth.M
}

// ToMap returns the request as a hook payload.
func (r *ResetRequest) ToMap() (map[string]any, error) {
	m := map[string]any{credentialEmailKey: r.Email}
	if r.Metadata != nil {
		m[resetMetadataKey] = r.Metadata
	}
	return m, nil
}

// FromMap sets the request from a request body or a rewritten payload. A
// missing email is left empty, for the flow to refuse. A value of the wrong
// type is a validation error.
func (r *ResetRequest) FromMap(data map[string]any) error {
	const op = "emailpassword.RequestPasswordReset"
	var email string
	switch v := data[credentialEmailKey].(type) {
	case nil:
	case string:
		email = v
	default:
		return behemotherr.NewInvalidInputError(op, credentialEmailKey, "email must be a string", nil)
	}
	var metadata behemoth.M
	switch v := data[resetMetadataKey].(type) {
	case nil:
	case behemoth.M: // a payload a handler built, or a caller's request
		metadata = v
	case map[string]any: // a decoded request body
		metadata = v
	default:
		return behemotherr.NewInvalidInputError(op, resetMetadataKey, "metadata must be an object", nil)
	}
	r.Email, r.Metadata = email, metadata
	return nil
}

// ResetRequestResult is what RequestPasswordReset returns and what handlers
// on auth.passwordReset.afterRequest receive. It does not hold the token.
type ResetRequestResult struct {
	UserID    string
	Email     string
	TokenID   string
	ExpiresAt time.Time
}

// AuditSubject implements [types.AuditSubject]: a reset request is about the
// user whose password the link resets.
func (r *ResetRequestResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// resetInput is the input of the wrapped reset flow. Its payload on
// auth.passwordReset.before is "password" and, when the token names one,
// "email". The token is not in the payload, and nothing is read back from
// it: a handler can stop the reset, but it can't point it at another link
// or swap the password.
type resetInput struct {
	token    string
	email    string
	password string

	// What ResetPassword's read of the token gave: the token when it is
	// usable, and otherwise the reason it is not. The flow checks the user
	// against verified before it consumes the token.
	verified  *types.Token
	verifyErr error
}

func (in *resetInput) ToMap() (map[string]any, error) {
	m := map[string]any{credentialPasswordKey: in.password}
	if in.email != "" {
		m[credentialEmailKey] = in.email
	}
	return m, nil
}

func (in *resetInput) FromMap(map[string]any) error { return nil }

// declareReset declares what password reset adds: the token kind, the
// auth.passwordReset.* points and three rate-limit rules. Declare calls it
// when reset is enabled.
func (p *Plugin) declareReset(ic *types.PluginInitContext) error {
	// Kept in the database, so that a new link can revoke the user's
	// earlier ones and a deleted user's links go with the user.
	if err := ic.Tokens.Declare(types.TokenKindDef{
		Kind: types.TokenKindPasswordReset, SingleUse: true, DefaultTTL: p.opts.Reset.TTL, Backend: types.TokenBackendDB,
	}); err != nil {
		return err
	}

	for _, def := range []types.HookPointDef{
		{Point: HookResetRequestBefore, Phase: types.BeforeHookPhase},
		{Point: HookResetRequestAfter, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookResetRequestFailed, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookResetBefore, Phase: types.BeforeHookPhase},
		{Point: HookResetAfter, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: HookResetFailed, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
	} {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}

	// Per address on the routes, like core's sign-in rule: it slows one
	// client down and can't be used to keep another one out.
	byAddress := func(_ *http.Request, ip string) string { return ip }
	for _, rule := range []types.RouteRateLimitRule{
		{Name: RuleResetRequestRoute, Method: http.MethodPost, Path: PathResetRequest, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
		{Name: RuleResetConfirmRoute, Method: http.MethodPost, Path: PathResetConfirm, KeyFunc: byAddress, Limit: types.Limit{Max: 10, Window: time.Minute}},
	} {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(rule); err != nil {
			return err
		}
	}
	// Per email on the request itself, so it also holds for
	// RequestPasswordReset called from code. It counts requests for unknown
	// emails too, and so answers the same for both.
	return ic.RateLimits.DeclareHookRateLimitRule(types.HookRateLimitRule{
		Name: RuleResetRequestEmail, Point: HookResetRequestBefore,
		KeyFunc: types.KeyByValues(hooks.HookValueEmail), Limit: p.opts.Reset.RequestLimit,
	})
}

// initReset checks the reset options and wraps the two flows with their
// points. Init calls it when reset is enabled.
func (p *Plugin) initReset(ac *types.AuthContext) error {
	const op = "emailpassword.Init"
	if ac.Mailer == nil || !ac.Mailer.Configured() {
		return behemotherr.NewConfigurationError(op, "password reset is enabled and no mail sender is configured; set BootConfig.Mail.Sender: the plugin does not send email itself", nil)
	}
	if ac.TokenManager == nil {
		return behemotherr.NewConfigurationError(op, "password reset is enabled and AuthContext has no token manager", nil)
	}
	if p.opts.Reset.TTL < 0 {
		return behemotherr.NewConfigurationError(op, fmt.Sprintf("Options.Reset.TTL is negative: %s", p.opts.Reset.TTL), nil)
	}
	linkURL, err := url.Parse(p.opts.Reset.LinkURL)
	if err != nil || (linkURL.Scheme != "http" && linkURL.Scheme != "https") || linkURL.Host == "" {
		return behemotherr.NewConfigurationError(op,
			fmt.Sprintf("Options.Reset.LinkURL %q is not an absolute http or https URL", p.opts.Reset.LinkURL), err)
	}
	p.resetURL = linkURL
	p.resetRequest = types.WithLifecycle(ac.Dispatcher, HookResetRequestBefore, HookResetRequestAfter, HookResetRequestFailed, p.resetRequestBody)
	p.reset = types.WithLifecycle(ac.Dispatcher, HookResetBefore, HookResetAfter, HookResetFailed, p.resetBody)
	return nil
}

// resetOperation is operation for the reset flows: it also refuses when the
// application did not turn reset on.
func (p *Plugin) resetOperation(ctx context.Context, op string) (*types.HookContext, error) {
	hctx, err := p.operation(ctx, op)
	if err != nil {
		return nil, err
	}
	if !p.opts.Reset.enabled() {
		return nil, behemotherr.NewConfigurationError(op, "password reset is not enabled; set Options.Reset.LinkURL", nil)
	}
	return hctx, nil
}

// resetAfterLookupError marks a failure of a reset request that happened
// after the user was found: the token could not be issued, or the send
// failed. It can only happen for an email that has an account, so the route
// hides it like ErrNoAccount. A caller from code gets it, and the error it
// wraps.
type resetAfterLookupError struct{ err error }

func (e *resetAfterLookupError) Error() string { return e.err.Error() }
func (e *resetAfterLookupError) Unwrap() error { return e.err }

// RequestPasswordReset sends a reset link to the user with req.Email. It
// replaces the user's earlier reset links: they stop working once the new
// one is issued. The password and the user's sessions are untouched until
// the link is used. It fires auth.passwordReset.beforeRequest, .afterRequest
// and .requestFailed.
//
// A user without a password (signed up by a magic link or a provider) gets a
// link too, and using it gives the account its first password.
//
// It returns ErrNoAccount when no user has the email, and nothing is sent.
// An email of the wrong shape is a validation error.
//
// It is the flow behind POST /password-reset/request, for callers that are
// not that route. Unlike the route it reports ErrNoAccount and a failed
// send. The plugin must have been initialized by Boot, with reset enabled.
func (p *Plugin) RequestPasswordReset(ctx context.Context, req ResetRequest) (*ResetRequestResult, error) {
	hctx, err := p.resetOperation(ctx, "emailpassword.RequestPasswordReset")
	if err != nil {
		return nil, err
	}
	publishEmail(hctx, req.Email)
	return p.resetRequest(hctx, req)
}

func (p *Plugin) resetRequestBody(hctx *types.HookContext, req ResetRequest) (*ResetRequestResult, error) {
	const op = "emailpassword.RequestPasswordReset"
	ac := hctx.Auth

	// The check comes before the lookup, so its answer does not depend on
	// whether the email has an account. It is the address's shape only:
	// Options.ValidateEmail is the policy for new accounts, and an account
	// created under an older policy can still reset its password.
	email := store.NormalizeEmail(req.Email)
	if !utils.IsValidEmail(email) {
		return nil, behemotherr.NewInvalidInputError(op, credentialEmailKey, "invalid email", nil)
	}

	user, err := ac.Store.FindUserByEmail(hctx.Ctx, email)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err // infra error (DB down): not "no such user"
		}
		if failErr := ac.Dispatcher.Fail(hctx, HookResetRequestFailed, types.FailureReason{
			Code: "userNotFound", Metadata: behemoth.M{hooks.HookValueEmail: email},
		}); failErr != nil {
			return nil, failErr
		}
		return nil, ErrNoAccount
	}

	// From here on a failure is one of a known account, and its audit event
	// says which.
	failed := func(code string, cause error) error {
		if failErr := ac.Dispatcher.Fail(hctx, HookResetRequestFailed, types.FailureReason{
			Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID,
		}); failErr != nil {
			return failErr
		}
		return &resetAfterLookupError{err: cause}
	}

	// One live link per user. The subject is the user's id and not the
	// email, so Store.DeleteUser removes the links with the user. The email
	// the link was sent to is kept next to it and checked at the reset.
	if err := ac.TokenManager.RevokeAllForSubject(hctx.Ctx, types.TokenKindPasswordReset, user.ID); err != nil {
		return nil, failed("issueFailed", err)
	}
	token, rawToken, err := ac.TokenManager.Issue(hctx.Ctx, types.TokenKindPasswordReset, user.ID, behemoth.M{credentialEmailKey: email})
	if err != nil {
		return nil, failed("issueFailed", err)
	}

	link := *p.resetURL
	query := link.Query()
	query.Set(resetTokenKey, rawToken)
	link.RawQuery = query.Encode()

	msg := types.MailMessage{
		Kind: types.MailPasswordReset, To: email, URL: link.String(), Token: rawToken,
		ExpiresAt: token.ExpiresAt, User: user, Metadata: req.Metadata,
	}
	if p.opts.Reset.WaitForSend {
		err = ac.Mailer.Send(hctx.Ctx, msg)
	} else {
		err = ac.Mailer.SendAsync(hctx.Ctx, msg) // an error here means it was not queued
	}
	if err != nil {
		// A link nobody received should not stay valid.
		if revokeErr := ac.TokenManager.Revoke(hctx.Ctx, token.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the reset link that could not be sent was not revoked", telemetry.ErrorFields(revokeErr))
		}
		return nil, failed("sendFailed", fmt.Errorf("emailpassword: send reset link: %w", err))
	}

	return &ResetRequestResult{UserID: user.ID, Email: email, TokenID: token.ID, ExpiresAt: token.ExpiresAt}, nil
}

// errInvalidResetToken is ResetPassword's one answer to every link it
// refuses, so the response does not tell an expired link from one that never
// existed. It is typed (unauthorized, 401).
func errInvalidResetToken() error {
	return behemotherr.NewUnauthorized("emailpassword.ResetPassword", ErrorCodeInvalidResetToken, "invalid or expired link")
}

// isTokenRejection reports whether err says the token is not usable (not
// found, expired, consumed, revoked), as opposed to a failure of the system.
func isTokenRejection(err error) bool {
	return behemotherr.Is(err, behemotherr.CategoryToken) || behemotherr.IsNotFound(err)
}

// ResetPassword sets newPassword on the account a reset link was sent for.
// rawToken is the "token" query parameter of the link. It returns the user.
//
// The password goes through the same rules as at sign-up (Options), and is
// checked first: a password that is refused is a validation error and
// leaves the link usable. The link works once. Its token is consumed last
// before the write, after the user and the hash are in hand, so the link is
// only spent without a reset when that write itself fails.
//
// On success:
//   - the user's credential account holds the new password hash. A user who
//     had no password gets the account now;
//   - every session of the user ends (SessionRevokedPasswordReset), and no
//     new one is created: the user signs in with the new password, which
//     keeps a second factor in the path;
//   - the email is marked verified if it was not, unless
//     ResetOptions.LeaveEmailUnverified is set;
//   - the user is sent a types.MailPasswordChanged notice, in the
//     background.
//
// A link that is unknown, expired, used or replaced by a newer one gets one
// error, with the code ErrorCodeInvalidResetToken. So does a link of a user
// who was deleted or whose email changed after it was sent.
//
// It fires auth.passwordReset.before, .after and .failed. It is the flow
// behind POST /password-reset/confirm.
func (p *Plugin) ResetPassword(ctx context.Context, rawToken, newPassword string) (*models.User, error) {
	hctx, err := p.resetOperation(ctx, "emailpassword.ResetPassword")
	if err != nil {
		return nil, err
	}

	// Read the token without consuming it. The before point needs its
	// email, in the payload and published for rate-limit rules, and the
	// flow checks the user against it. A token that does not check out
	// still goes through the flow, which refuses it and fires
	// auth.passwordReset.failed.
	in := resetInput{token: rawToken, password: newPassword}
	token, err := p.authContext.TokenManager.Verify(ctx, types.TokenKindPasswordReset, rawToken)
	switch {
	case err == nil:
		in.verified = token
		in.email, _ = token.MetadataJSON[credentialEmailKey].(string)
	case !isTokenRejection(err):
		return nil, err
	default:
		in.verifyErr = err
	}
	publishEmail(hctx, in.email)
	return p.reset(hctx, in)
}

func (p *Plugin) resetBody(hctx *types.HookContext, in resetInput) (*models.User, error) {
	const op = "emailpassword.ResetPassword"
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	// Before the token, so that a typo in the new password does not cost
	// the user the link. The answer is the same for any token, so it tells
	// nothing about one.
	if err := p.validatePassword(in.password); err != nil {
		return nil, behemotherr.NewInvalidInputError(op, credentialPasswordKey, "invalid password", err)
	}

	// Every check that can refuse the reset runs on the token as
	// ResetPassword read it, before it is consumed. Only the write is left
	// after the consume, so little can still fail with the link spent.
	token := in.verified
	if token == nil {
		if failErr := dispatcher.Fail(hctx, HookResetFailed, types.FailureReason{Code: "invalidToken", Cause: in.verifyErr}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidResetToken()
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
		if failErr := dispatcher.Fail(hctx, HookResetFailed, rejected("userNotFound", nil)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidResetToken()
	}

	// The link proves control of the address it was sent to. If the user's
	// email has changed since, that is no longer the account's address.
	sentTo, _ := token.MetadataJSON[credentialEmailKey].(string)
	if sentTo == "" || sentTo != store.NormalizeEmail(user.Email) {
		if failErr := dispatcher.Fail(hctx, HookResetFailed, rejected("emailChanged", nil)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidResetToken()
	}

	// Hashed only for a token that checked out, so the route can't be used
	// to make the server hash, and before the consume, so a failed hash
	// leaves the link usable.
	passwordHash, err := hashPassword(hctx, in.password)
	if err != nil {
		return nil, err // infra error - no Fail()
	}

	// The at-most-once step. Of two resets racing with one link, both
	// passed the checks above and one loses here.
	if _, err := ac.TokenManager.Consume(hctx.Ctx, types.TokenKindPasswordReset, in.token); err != nil {
		if !isTokenRejection(err) {
			return nil, err // infra error: not a bad link
		}
		if failErr := dispatcher.Fail(hctx, HookResetFailed, rejected("invalidToken", err)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidResetToken()
	}

	// The password and the verified flag are written together or not at
	// all. The token was consumed above, outside this transaction: when
	// this write fails the link is spent and the user asks for another.
	// Consuming inside the transaction is deferred; docs/ongoing.md has
	// what it needs from the token manager.
	markVerified := !user.EmailVerified && !p.opts.Reset.LeaveEmailUnverified
	err = ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
		credential, err := tx.FindAccount(ctx, models.ProviderCredential, user.ID)
		switch {
		case err == nil:
			_, err = tx.UpdateAccount(ctx, credential.ID, behemoth.M{models.AccountPasswordHash: passwordHash})
		case behemotherr.IsNotFound(err):
			// No password yet: the account was made by a magic link or a
			// provider. The reset gives it one.
			err = tx.CreateAccount(ctx, &models.Account{
				UserID:       user.ID,
				ProviderID:   models.ProviderCredential,
				AccountID:    user.ID,
				PasswordHash: passwordHash,
			})
		}
		if err != nil || !markVerified {
			return err
		}
		updated, err := tx.UpdateUser(ctx, user.ID, behemoth.M{models.UserEmailVerified: true})
		if err != nil {
			return err
		}
		user = updated
		return nil
	})
	if err != nil {
		// A data hook's typed veto is a refusal of the reset. Anything else
		// is a failure of the system.
		if isRejection(err) {
			if failErr := dispatcher.Fail(hctx, HookResetFailed, rejected("rejectedByHook", err)); failErr != nil {
				return nil, failErr
			}
		}
		return nil, err
	}

	// Whoever knew the old password, or held a session made with it, is
	// signed out. The password is already changed when this fails, so the
	// error is a failure of the system and the caller sees it.
	if err := ac.SessionManager.RevokeAllForUser(hctx.Ctx, user.ID, SessionRevokedPasswordReset, ""); err != nil {
		return nil, fmt.Errorf("emailpassword: the password was reset, but ending the user's sessions failed: %w", err)
	}

	// Tell the owner, in case the reset was not theirs. In the background:
	// the password is set either way, and the reset should not fail or wait
	// for a notice. A message that could not be queued is logged.
	notice := types.MailMessage{Kind: types.MailPasswordChanged, To: store.NormalizeEmail(user.Email), User: user}
	if err := ac.Mailer.SendAsync(hctx.Ctx, notice); err != nil {
		p.log.Warn(hctx.Ctx, "the password changed notice was not queued", telemetry.ErrorFields(err))
	}

	return user, nil
}

// handleResetRequest answers every well-formed request the same, whether or
// not the email has an account: an unknown email, a token that could not be
// issued and a failed send are all a 200. A validation error and a rate
// limit are reported, since they do not depend on the account. Anything else
// is a failure of the system and a 500 from the router.
func (p *Plugin) handleResetRequest(rctx *types.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError("emailpassword.RequestPasswordReset", "request", err)
	}
	var req ResetRequest
	if err := req.FromMap(body); err != nil {
		return err
	}

	_, err := p.RequestPasswordReset(rctx.Ctx, req)
	if hidden, ok := errors.AsType[*resetAfterLookupError](err); ok {
		// Nothing tells the client, so this line is the only report.
		p.log.Error(rctx.Ctx, "password reset link was not sent", telemetry.ErrorFields(hidden.err))
		err = nil
	}
	if err != nil && !errors.Is(err, ErrNoAccount) {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// handleResetConfirm returns ResetPassword's error unchanged, and the router
// maps it: a refused link is a typed unauthorized error (401), a refused
// password a validation error (400). It delivers no session token: a reset
// does not sign the user in.
func (p *Plugin) handleResetConfirm(rctx *types.RequestContext) error {
	const op = "emailpassword.ResetPassword"
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError(op, "request", err)
	}
	rawToken, _ := body[resetTokenKey].(string)
	if rawToken == "" {
		return behemotherr.NewInvalidInputError(op, resetTokenKey, "token is required", nil)
	}
	password, ok := body[credentialPasswordKey].(string)
	if !ok {
		return behemotherr.NewInvalidInputError(op, credentialPasswordKey, "password is required", nil)
	}

	if _, err := p.ResetPassword(rctx.Ctx, rawToken, password); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "password_reset"})
}
