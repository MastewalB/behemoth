package emailverification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// This file is the email change flow: a user's address is replaced only
// once the new one has confirmed, and the old one is told and can undo it.
//
// It is the safe way to change an address. The handlers in Register stay as
// the fallback for a write that changes the email directly: they keep
// EmailVerified honest, and do not make such a write safe.
//
//	request   the user, signed in recently, names a new address. Nothing in
//	          users changes. The current address gets a notice with a link
//	          that undoes the change, the new one a link that confirms it.
//	confirm   the new address follows its link: email and email_verified are
//	          written together.
//	revert    the old address follows its link, before or after the confirm:
//	          a pending change is dropped, an applied one is put back, and
//	          every session of the user ends.
//
// No table or column holds the pending change. Both addresses travel in the
// metadata of the two tokens.

// The token kinds of the flow. Both are single use and kept in the
// database, with the user's id as subject, so Store.DeleteUser removes them
// with the user.
const (
	// TokenKindEmailChange is the link sent to the new address. Its
	// metadata holds the address the user had ("from") and the one asked
	// for ("to").
	TokenKindEmailChange types.TokenKind = "email_change"
	// TokenKindEmailChangeRevert is the link sent to the address the user
	// had when a change was requested. Its metadata holds that address
	// ("restore").
	TokenKindEmailChangeRevert types.TokenKind = "email_change_revert"
)

// Defaults of the flow's lifetimes.
const (
	// DefaultChangeTTL is how long the new address has to confirm.
	DefaultChangeTTL = time.Hour
	// DefaultRevertTTL is how long the old address can undo the change.
	DefaultRevertTTL = 72 * time.Hour
)

// The points of the flow. The after and failed points are audited.
const (
	// HookChangeRequestBefore runs on a change request: "userID", "email"
	// (the new address), "redirectURL" and "metadata". A handler may
	// rewrite the last two or stop the request.
	HookChangeRequestBefore types.HookPoint = "auth.emailChange.beforeRequest"
	// HookChangeRequestAfter runs once both messages are on their way,
	// with a *ChangeResult.
	HookChangeRequestAfter types.HookPoint = "auth.emailChange.afterRequest"
	// HookChangeRequestFailed fires for a request that started no change:
	// codes "issueFailed", "noticeFailed", "emailTaken", "sendFailed" and
	// "rejectedByHook".
	HookChangeRequestFailed types.HookPoint = "auth.emailChange.requestFailed"

	// HookChangeConfirmBefore runs before a change is applied. Veto only.
	HookChangeConfirmBefore types.HookPoint = "auth.emailChange.beforeConfirm"
	// HookChangeConfirmAfter runs once the address is changed, with the
	// *models.User.
	HookChangeConfirmAfter types.HookPoint = "auth.emailChange.afterConfirm"
	// HookChangeConfirmFailed fires for a confirm that was refused: codes
	// "invalidLink", "userNotFound", "emailChanged", "emailTaken" and
	// "rejectedByHook".
	HookChangeConfirmFailed types.HookPoint = "auth.emailChange.confirmFailed"

	// HookChangeRevertBefore runs before a change is undone. Veto only.
	HookChangeRevertBefore types.HookPoint = "auth.emailChange.beforeRevert"
	// HookChangeRevertAfter runs once the change is undone and the user's
	// sessions have ended, with the *models.User.
	HookChangeRevertAfter types.HookPoint = "auth.emailChange.afterRevert"
	// HookChangeRevertFailed fires for a revert that was refused: codes
	// "invalidLink", "userNotFound", "emailTaken" and "rejectedByHook".
	HookChangeRevertFailed types.HookPoint = "auth.emailChange.revertFailed"
)

// Names of the flow's rate-limit rules.
const (
	RuleChangeRoute        = "emailverification.change.route"         // change requests per client address
	RuleChangeConfirmRoute = "emailverification.change.confirm.route" // confirm attempts per client address
	RuleChangeRevertRoute  = "emailverification.change.revert.route"  // revert attempts per client address
	RuleChangeUser         = "emailverification.change.user"          // change requests per user, from any caller
)

// Paths of the flow's routes, below the router's base path.
const (
	PathChange        = "/email/change"
	PathChangeConfirm = "/email/change/confirm"
	PathChangeRevert  = "/email/change/revert"
)

// Keys of MailMessage.Data on the flow's two messages
// (types.MailEmailChange and types.MailEmailChangeNotice).
const (
	DataOldEmail = "oldEmail" // the address the account has
	DataNewEmail = "newEmail" // the address that was asked for
)

// Keys of the tokens' metadata.
const (
	keyFrom    = "from"
	keyTo      = "to"
	keyRestore = "restore"
	keyUserID  = "userID"
)

// ErrorCodeInvalidChangeLink is the code of the error ConfirmChange and
// RevertChange return for a link they refuse: unknown, expired, already
// used, or overtaken by a later request or a revert.
const ErrorCodeInvalidChangeLink = "invalid_email_change_link"

// ErrorCodeEmailTaken is the code of the conflict error ConfirmChange and
// RevertChange return when the address they would write belongs to another
// account by now.
const ErrorCodeEmailTaken = "email_taken"

// SessionRevokedEmailChangeReverted is the revoke reason of the sessions
// that end when an email change is undone.
const SessionRevokedEmailChangeReverted = "email_change_reverted"

// ErrEmailTaken is returned by RequestChange when another account has the
// address asked for. The current address has been sent its notice by then,
// and nothing goes to the new one. The route does not report it: it answers
// the same whether or not the address is registered.
var ErrEmailTaken = errors.New("emailverification: the new email belongs to another account")

// ChangeRequest is the input of RequestChange.
//
// It implements [behemoth.Serializable], which is how WithLifecycle turns it
// into the auth.emailChange.beforeRequest payload and back.
type ChangeRequest struct {
	// UserID is the user whose address changes. The route takes it from
	// the session.
	UserID string
	// NewEmail is the address to change to.
	NewEmail string
	// RedirectURL is where the application should send the user after the
	// new address has confirmed. Optional, and checked like
	// SendRequest.RedirectURL. ConfirmChange returns it.
	RedirectURL string
	// Metadata is passed to the mail sender as it is, on both messages.
	// Optional.
	Metadata behemoth.M

	// inFlow is set once the request has entered the flow. FromMap then
	// reads a rewritten payload and not a request body.
	inFlow bool
}

// ToMap returns the request as a hook payload.
func (r *ChangeRequest) ToMap() (map[string]any, error) {
	m := map[string]any{keyUserID: r.UserID, keyEmail: r.NewEmail, keyRedirectURL: r.RedirectURL}
	if r.Metadata != nil {
		m[keyMetadata] = r.Metadata
	}
	return m, nil
}

// FromMap sets the request from a request body or a rewritten payload. From
// a payload only the redirect URL and the metadata are taken: whose address
// changes, and to what, is not a handler's to decide. From a body the user
// is not read either; the route takes it from the session.
func (r *ChangeRequest) FromMap(data map[string]any) error {
	email, redirect, metadata, err := requestFields("emailverification.RequestChange", data)
	if err != nil {
		return err
	}
	if !r.inFlow {
		r.NewEmail = email
	}
	r.RedirectURL, r.Metadata = redirect, metadata
	return nil
}

// ChangeResult is what RequestChange returns and what handlers on
// auth.emailChange.afterRequest receive. It does not hold a token.
type ChangeResult struct {
	UserID    string
	OldEmail  string
	NewEmail  string
	TokenID   string    // the confirmation token's id
	ExpiresAt time.Time // when the confirmation link stops working
}

// AuditSubject implements [types.AuditSubject]: a change is about its user.
func (r *ChangeResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// changeTokenInput is the input of the wrapped confirm and revert flows.
// Its payload is "email", the address the token would write, when the token
// names one. The token is not in the payload and nothing is read back.
type changeTokenInput struct {
	token string
	email string
}

func (v *changeTokenInput) ToMap() (map[string]any, error) {
	m := map[string]any{}
	if v.email != "" {
		m[keyEmail] = v.email
	}
	return m, nil
}

func (v *changeTokenInput) FromMap(map[string]any) error { return nil }

// changeEnabled reports whether the application turned the flow on.
func (p *Plugin) changeEnabled() bool {
	return p.opts.ChangeLinkURL != "" || p.opts.RevertLinkURL != ""
}

// declareChange declares what the flow needs: its two token kinds, nine
// points and four rate-limit rules.
func (p *Plugin) declareChange(ic *types.PluginInitContext, byAddress func(*http.Request, string) string) error {
	for _, def := range []types.TokenKindDef{
		{Kind: TokenKindEmailChange, SingleUse: true, DefaultTTL: p.opts.ChangeTTL, Backend: types.TokenBackendDB},
		{Kind: TokenKindEmailChangeRevert, SingleUse: true, DefaultTTL: p.opts.RevertTTL, Backend: types.TokenBackendDB},
	} {
		if err := ic.Tokens.Declare(def); err != nil {
			return err
		}
	}

	for _, flow := range [][3]types.HookPoint{
		{HookChangeRequestBefore, HookChangeRequestAfter, HookChangeRequestFailed},
		{HookChangeConfirmBefore, HookChangeConfirmAfter, HookChangeConfirmFailed},
		{HookChangeRevertBefore, HookChangeRevertAfter, HookChangeRevertFailed},
	} {
		for _, def := range []types.HookPointDef{
			{Point: flow[0], Phase: types.BeforeHookPhase},
			{Point: flow[1], Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
			{Point: flow[2], Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},
		} {
			if err := ic.Hooks.Declare(def); err != nil {
				return err
			}
		}
	}

	perMinute := types.Limit{Max: 10, Window: time.Minute}
	for _, rule := range []types.RouteRateLimitRule{
		{Name: RuleChangeRoute, Method: http.MethodPost, Path: PathChange, KeyFunc: byAddress, Limit: perMinute},
		{Name: RuleChangeConfirmRoute, Method: http.MethodPost, Path: PathChangeConfirm, KeyFunc: byAddress, Limit: perMinute},
		{Name: RuleChangeRevertRoute, Method: http.MethodPost, Path: PathChangeRevert, KeyFunc: byAddress, Limit: perMinute},
	} {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(rule); err != nil {
			return err
		}
	}
	// Per user on the request itself: every request mails the current
	// address, whoever makes it.
	return ic.RateLimits.DeclareHookRateLimitRule(types.HookRateLimitRule{
		Name: RuleChangeUser, Point: HookChangeRequestBefore,
		KeyFunc: types.KeyByValues(hooks.HookValueUserID), Limit: p.opts.ChangeLimit,
	})
}

// initChange checks the flow's options and wraps its three flows.
func (p *Plugin) initChange(ac *types.AuthContext) error {
	const op = "emailverification.Init"
	if p.opts.ChangeLinkURL == "" || p.opts.RevertLinkURL == "" {
		return behemotherr.NewConfigurationError(op,
			"Options.ChangeLinkURL and Options.RevertLinkURL go together: the email change flow needs both pages", nil)
	}
	if p.opts.ChangeTTL < 0 || p.opts.RevertTTL < 0 {
		return behemotherr.NewConfigurationError(op,
			fmt.Sprintf("Options.ChangeTTL (%s) and Options.RevertTTL (%s) can't be negative", p.opts.ChangeTTL, p.opts.RevertTTL), nil)
	}
	var err error
	if p.changeURL, err = parseLinkURL(op, "ChangeLinkURL", p.opts.ChangeLinkURL); err != nil {
		return err
	}
	if p.revertURL, err = parseLinkURL(op, "RevertLinkURL", p.opts.RevertLinkURL); err != nil {
		return err
	}
	p.changeRequest = types.WithLifecycle(ac.Dispatcher, HookChangeRequestBefore, HookChangeRequestAfter, HookChangeRequestFailed, p.changeRequestBody)
	p.changeConfirm = types.WithLifecycle(ac.Dispatcher, HookChangeConfirmBefore, HookChangeConfirmAfter, HookChangeConfirmFailed, p.changeConfirmBody)
	p.changeRevert = types.WithLifecycle(ac.Dispatcher, HookChangeRevertBefore, HookChangeRevertAfter, HookChangeRevertFailed, p.changeRevertBody)
	return nil
}

// changeRoutes returns the flow's routes. A request needs a fresh session:
// a stolen session that is hours old can't start a change. The other two
// are opened from a mailbox, by whoever holds the link, and need none.
func (p *Plugin) changeRoutes() []types.Route {
	return []types.Route{
		{Method: http.MethodPost, Path: PathChange, Handler: p.handleChange,
			Middlewares: []types.Middleware{types.RequireFreshSession(p.authContext.SessionManager)}},
		{Method: http.MethodPost, Path: PathChangeConfirm, Handler: p.handleChangeConfirm},
		{Method: http.MethodPost, Path: PathChangeRevert, Handler: p.handleChangeRevert},
	}
}

// changeOperation is operation for the change flow: it also refuses when
// the flow is off.
func (p *Plugin) changeOperation(ctx context.Context, op string) (*types.HookContext, error) {
	hctx, err := p.operation(ctx, op)
	if err != nil {
		return nil, err
	}
	if p.changeURL == nil {
		return nil, behemotherr.NewConfigurationError(op,
			"the email change flow is off; set Options.ChangeLinkURL and Options.RevertLinkURL", nil)
	}
	return hctx, nil
}

// RequestChange starts a change of req.UserID's email to req.NewEmail. The
// user's address does not change yet. Two messages go out:
//
//   - to the current address, a notice (types.MailEmailChangeNotice) with a
//     link that undoes the change for Options.RevertTTL. The call waits for
//     the mail sender to take it: without the notice there is no change.
//   - to the new address, a link that confirms it (types.MailEmailChange),
//     in the background.
//
// A new request replaces the user's pending one. It fires
// auth.emailChange.beforeRequest, .afterRequest and .requestFailed.
//
// It returns ErrNoAccount for an unknown user and ErrEmailTaken when the
// address belongs to another account. An address of the wrong shape, the
// address the account already has, and a redirect URL outside the trusted
// origins are validation errors.
//
// It is the flow behind POST /email/change, which requires a fresh session.
// A caller from code vouches for the request itself: nothing here checks
// who is asking.
func (p *Plugin) RequestChange(ctx context.Context, req ChangeRequest) (*ChangeResult, error) {
	const op = "emailverification.RequestChange"
	hctx, err := p.changeOperation(ctx, op)
	if err != nil {
		return nil, err
	}
	if req.UserID == "" {
		return nil, behemotherr.NewInvalidInputError(op, "user", "a user is required", nil)
	}
	// Published for the rule per user, and for the audit events' subject.
	hctx.Values[hooks.HookValueUserID] = req.UserID
	req.NewEmail = store.NormalizeEmail(req.NewEmail)
	req.inFlow = true
	return p.changeRequest(hctx, req)
}

func (p *Plugin) changeRequestBody(hctx *types.HookContext, req ChangeRequest) (*ChangeResult, error) {
	const op = "emailverification.RequestChange"
	ac := hctx.Auth

	newEmail := req.NewEmail
	if !utils.IsValidEmail(newEmail) {
		return nil, behemotherr.NewInvalidInputError(op, keyEmail, "invalid email", nil)
	}
	if req.RedirectURL != "" && !types.TrustedRedirect(ac.Origins, req.RedirectURL) {
		return nil, behemotherr.NewInvalidInputError(op, "redirect_url", "redirect URL is not allowed", nil)
	}
	user, err := ac.Store.FindUserByID(hctx.Ctx, req.UserID)
	if err != nil {
		if behemotherr.IsNotFound(err) {
			return nil, ErrNoAccount
		}
		return nil, err
	}
	current := store.NormalizeEmail(user.Email)
	if newEmail == current {
		return nil, behemotherr.NewInvalidInputError(op, keyEmail, "this is already the account's email", nil)
	}

	failed := func(code string, cause error) error {
		if failErr := ac.Dispatcher.Fail(hctx, HookChangeRequestFailed, types.FailureReason{
			Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID,
		}); failErr != nil {
			return failErr
		}
		return cause
	}
	revoke := func(token *types.Token) {
		if err := ac.TokenManager.Revoke(hctx.Ctx, token.ID); err != nil {
			p.log.Warn(hctx.Ctx, "a link of a failed email change request was not revoked", telemetry.ErrorFields(err))
		}
	}
	data := behemoth.M{DataOldEmail: current, DataNewEmail: newEmail}

	// One pending change per user: a new request replaces the earlier one.
	// Revert links are never replaced. Each belongs to the request that
	// issued it, and an older one has to outlive every newer request (see
	// changeRevertBody).
	if err := ac.TokenManager.RevokeAllForSubject(hctx.Ctx, TokenKindEmailChange, user.ID); err != nil {
		return nil, failed("issueFailed", err)
	}

	// The notice comes first, and the request waits for it. It is what
	// lets the owner of the account stop a change they did not ask for, so
	// a change whose notice could not be handed over does not start.
	revert, rawRevert, err := ac.TokenManager.Issue(hctx.Ctx, TokenKindEmailChangeRevert, user.ID, behemoth.M{keyRestore: current})
	if err != nil {
		return nil, failed("issueFailed", err)
	}
	err = ac.Mailer.Send(hctx.Ctx, types.MailMessage{
		Kind: types.MailEmailChangeNotice, To: current, URL: withToken(p.revertURL, rawRevert), Token: rawRevert,
		ExpiresAt: revert.ExpiresAt, User: user, Data: data, Metadata: req.Metadata,
	})
	if err != nil {
		revoke(revert)
		return nil, failed("noticeFailed", fmt.Errorf("emailverification: send change notice: %w", err))
	}

	// Checked after the notice, so that a request for an address that is
	// taken does the same work as one for a free address up to here. The
	// address is not reserved: the confirm checks again, by writing it.
	if _, err := ac.Store.FindUserByEmail(hctx.Ctx, newEmail); err == nil {
		return nil, failed("emailTaken", ErrEmailTaken)
	} else if !behemotherr.IsNotFound(err) {
		return nil, err
	}

	meta := behemoth.M{keyFrom: current, keyTo: newEmail}
	if req.RedirectURL != "" {
		meta[keyRedirectURL] = req.RedirectURL
	}
	token, rawToken, err := ac.TokenManager.Issue(hctx.Ctx, TokenKindEmailChange, user.ID, meta)
	if err != nil {
		return nil, failed("issueFailed", err)
	}
	// In the background, like a verification link: if it is lost, the user
	// asks again. An error here means the message was not queued.
	err = ac.Mailer.SendAsync(hctx.Ctx, types.MailMessage{
		Kind: types.MailEmailChange, To: newEmail, URL: withToken(p.changeURL, rawToken), Token: rawToken,
		ExpiresAt: token.ExpiresAt, User: user, Data: data, Metadata: req.Metadata,
	})
	if err != nil {
		revoke(token)
		return nil, failed("sendFailed", fmt.Errorf("emailverification: queue change link: %w", err))
	}

	return &ChangeResult{UserID: user.ID, OldEmail: current, NewEmail: newEmail, TokenID: token.ID, ExpiresAt: token.ExpiresAt}, nil
}

// errInvalidChangeLink is the one answer to every confirm or revert link
// that is refused. It is typed (unauthorized, 401).
func errInvalidChangeLink(op string) error {
	return behemotherr.NewUnauthorized(op, ErrorCodeInvalidChangeLink, "invalid or expired link")
}

// errEmailTaken is the typed conflict (409) of a confirm or a revert whose
// address another account holds by now. Whoever sees it holds a link that
// was mailed to that address, so it tells them nothing new about it.
func errEmailTaken(op string) error {
	return &behemotherr.DomainError{
		Category: behemotherr.CategoryConflict, Op: op, Code: ErrorCodeEmailTaken,
		PublicMessage:   "this email address is not available",
		InternalMessage: op + ": the address belongs to another account",
	}
}

// readChangeToken reads a confirm or revert token without consuming it, for
// what the before point needs: the user in Values (the audit events'
// subject), and the address the token would write in the payload. A token
// that does not check out still goes through the flow, which refuses it and
// fires the failed point.
func (p *Plugin) readChangeToken(hctx *types.HookContext, kind types.TokenKind, rawToken, emailKey string) (*types.Token, changeTokenInput, error) {
	in := changeTokenInput{token: rawToken}
	token, err := p.authContext.TokenManager.Verify(hctx.Ctx, kind, rawToken)
	if err != nil {
		if !isTokenRejection(err) {
			return nil, in, err
		}
		return nil, in, nil
	}
	in.email, _ = token.MetadataJSON[emailKey].(string)
	hctx.Values[hooks.HookValueUserID] = fmt.Sprint(token.Subject)
	return token, in, nil
}

// ConfirmChange applies the change a link sent to the new address stands
// for. rawToken is the "token" query parameter of that link. The user's
// email becomes the new address, marked verified: following the link shows
// who controls it. It fires auth.emailChange.beforeConfirm, .afterConfirm
// and .confirmFailed.
//
// A link that is unknown, expired, used, or replaced by a later request
// gets one error, with the code ErrorCodeInvalidChangeLink. So does one
// whose user is gone or no longer has the address the request started from
// (a revert, or another change, came first). When another account took the
// new address in the meantime, the error is a conflict with the code
// ErrorCodeEmailTaken.
//
// The user's sessions are left as they are. It is the flow behind
// POST /email/change/confirm.
func (p *Plugin) ConfirmChange(ctx context.Context, rawToken string) (*VerifyResult, error) {
	hctx, err := p.changeOperation(ctx, "emailverification.ConfirmChange")
	if err != nil {
		return nil, err
	}
	token, in, err := p.readChangeToken(hctx, TokenKindEmailChange, rawToken, keyTo)
	if err != nil {
		return nil, err
	}
	var redirect string
	if token != nil {
		redirect, _ = token.MetadataJSON[keyRedirectURL].(string)
	}
	user, err := p.changeConfirm(hctx, in)
	if err != nil {
		return nil, err
	}
	return &VerifyResult{User: user, RedirectURL: redirect}, nil
}

// refuseChange fires point for a confirm or a revert that is refused, and
// returns result, the error the caller is given. userID is the audit
// event's subject, when the token named a user.
func refuseChange(hctx *types.HookContext, point types.HookPoint, code string, cause error, userID string, result error) error {
	reason := types.FailureReason{Code: code, Cause: cause}
	if userID != "" {
		reason.SubjectType, reason.SubjectID = models.UserTable, userID
	}
	if failErr := hctx.Auth.Dispatcher.Fail(hctx, point, reason); failErr != nil {
		return failErr
	}
	return result
}

func (p *Plugin) changeConfirmBody(hctx *types.HookContext, in changeTokenInput) (*models.User, error) {
	const op = "emailverification.ConfirmChange"
	ac := hctx.Auth
	refuse := func(code string, cause error, userID string, result error) error {
		return refuseChange(hctx, HookChangeConfirmFailed, code, cause, userID, result)
	}

	token, err := ac.TokenManager.Consume(hctx.Ctx, TokenKindEmailChange, in.token)
	if err != nil {
		if !isTokenRejection(err) {
			return nil, err // infra error: not a bad link
		}
		return nil, refuse("invalidLink", err, "", errInvalidChangeLink(op))
	}
	userID := fmt.Sprint(token.Subject)
	user, err := ac.Store.FindUserByID(hctx.Ctx, userID)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err
		}
		return nil, refuse("userNotFound", nil, userID, errInvalidChangeLink(op))
	}

	// The request was made for the address the user had then. If the
	// account has another one by now, a revert or another change came
	// first, and this link no longer says what the user wants.
	from, _ := token.MetadataJSON[keyFrom].(string)
	to, _ := token.MetadataJSON[keyTo].(string)
	if to == "" || from != store.NormalizeEmail(user.Email) {
		return nil, refuse("emailChanged", nil, userID, errInvalidChangeLink(op))
	}

	// Both columns in one write. The plugin's own data.user.beforeUpdate
	// handler leaves an update that sets the flag alone, and its
	// data.user.updated handler sends nothing to a verified user.
	updated, err := ac.Store.UpdateUser(hctx.Ctx, user.ID, behemoth.M{models.UserEmail: to, models.UserEmailVerified: true})
	if err != nil {
		if behemotherr.IsDuplicateKey(err) {
			return nil, refuse("emailTaken", err, userID, errEmailTaken(op))
		}
		return nil, err
	}
	return updated, nil
}

// RevertChange undoes an email change. rawToken is the "token" query
// parameter of the link in the notice the old address got. It works before
// the new address has confirmed and after, for Options.RevertTTL:
//
//   - the user's pending change is dropped;
//   - if the address was changed, the old one is put back, marked verified:
//     following the link shows who controls it;
//   - revert links issued after this one stop working, so that whoever made
//     the later requests can't undo this;
//   - every session of the user ends (SessionRevokedEmailChangeReverted).
//     The change was asked for from one of them.
//
// It fires auth.emailChange.beforeRevert, .afterRevert and .revertFailed.
// A link that is unknown, expired or used gets the error with the code
// ErrorCodeInvalidChangeLink. When another account has taken the old
// address since, it can't be put back: the sessions still end, and the error
// is a conflict with the code ErrorCodeEmailTaken.
//
// It is the flow behind POST /email/change/revert.
func (p *Plugin) RevertChange(ctx context.Context, rawToken string) (*models.User, error) {
	hctx, err := p.changeOperation(ctx, "emailverification.RevertChange")
	if err != nil {
		return nil, err
	}
	_, in, err := p.readChangeToken(hctx, TokenKindEmailChangeRevert, rawToken, keyRestore)
	if err != nil {
		return nil, err
	}
	return p.changeRevert(hctx, in)
}

func (p *Plugin) changeRevertBody(hctx *types.HookContext, in changeTokenInput) (*models.User, error) {
	const op = "emailverification.RevertChange"
	ac := hctx.Auth
	refuse := func(code string, cause error, userID string, result error) error {
		return refuseChange(hctx, HookChangeRevertFailed, code, cause, userID, result)
	}

	token, err := ac.TokenManager.Consume(hctx.Ctx, TokenKindEmailChangeRevert, in.token)
	if err != nil {
		if !isTokenRejection(err) {
			return nil, err // infra error: not a bad link
		}
		return nil, refuse("invalidLink", err, "", errInvalidChangeLink(op))
	}
	userID := fmt.Sprint(token.Subject)
	restore, _ := token.MetadataJSON[keyRestore].(string)
	user, err := ac.Store.FindUserByID(hctx.Ctx, userID)
	if err != nil {
		if !behemotherr.IsNotFound(err) {
			return nil, err
		}
		return nil, refuse("userNotFound", nil, userID, errInvalidChangeLink(op))
	}
	if restore == "" {
		return nil, refuse("invalidLink", nil, userID, errInvalidChangeLink(op))
	}

	// A change that has not been confirmed yet is dropped.
	if err := ac.TokenManager.RevokeAllForSubject(hctx.Ctx, TokenKindEmailChange, user.ID); err != nil {
		return nil, err
	}

	// Revert links issued after this one belong to later requests. Left
	// alive, the one sent to the address this revert removes would put
	// that address back. Older links are kept: their addresses held the
	// account before this one did, and a later link must not be able to
	// cancel them. "Not before" and not "after", because some databases
	// keep the creation time to the second.
	links, err := ac.TokenManager.ListForSubject(hctx.Ctx, TokenKindEmailChangeRevert, user.ID)
	if err != nil {
		return nil, err
	}
	for _, later := range links {
		if later.ID == token.ID || later.CreatedAt.Before(token.CreatedAt) {
			continue
		}
		if err := ac.TokenManager.Revoke(hctx.Ctx, later.ID); err != nil {
			return nil, err
		}
	}

	taken := false
	if store.NormalizeEmail(user.Email) != restore {
		updated, err := ac.Store.UpdateUser(hctx.Ctx, user.ID, behemoth.M{models.UserEmail: restore, models.UserEmailVerified: true})
		switch {
		case err == nil:
			user = updated
		case behemotherr.IsDuplicateKey(err):
			taken = true // nothing reserves the old address; see docs/ongoing.md
		default:
			return nil, err
		}
	}

	// Whoever asked for the change had a session. All of them end, also
	// when the address could not be put back.
	if err := ac.SessionManager.RevokeAllForUser(hctx.Ctx, user.ID, SessionRevokedEmailChangeReverted, ""); err != nil {
		return nil, err
	}
	if taken {
		return nil, refuse("emailTaken", nil, userID, errEmailTaken(op))
	}
	return user, nil
}

// handleChange takes the user from the session RequireFreshSession checked.
// It answers a request for an address that is taken like one that was sent
// its links, so a signed-in user can't use it to learn which addresses have
// an account.
func (p *Plugin) handleChange(rctx *types.RequestContext) error {
	const op = "emailverification.RequestChange"
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return behemotherr.NewValidationError(op, "request", err)
	}
	var req ChangeRequest
	if err := req.FromMap(body); err != nil {
		return err
	}
	session, _ := rctx.Values["session"].(*models.Session)
	if session == nil {
		return behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionNotFresh, nil)
	}
	req.UserID = session.UserID

	if _, err := p.RequestChange(rctx.Ctx, req); err != nil && !errors.Is(err, ErrEmailTaken) {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// changeToken reads the token from the body of a confirm or revert request.
func changeToken(rctx *types.RequestContext, op string) (string, error) {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return "", behemotherr.NewValidationError(op, "request", err)
	}
	rawToken, _ := body[keyToken].(string)
	if rawToken == "" {
		return "", behemotherr.NewInvalidInputError(op, keyToken, "token is required", nil)
	}
	return rawToken, nil
}

func (p *Plugin) handleChangeConfirm(rctx *types.RequestContext) error {
	rawToken, err := changeToken(rctx, "emailverification.ConfirmChange")
	if err != nil {
		return err
	}
	result, err := p.ConfirmChange(rctx.Ctx, rawToken)
	if err != nil {
		return err
	}
	user, err := rctx.Auth.Public.Of(result.User) // the public columns, not the model
	if err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{types.SignInUserKey: user, keyRedirectURL: result.RedirectURL})
}

// handleChangeRevert answers without the user: the caller holds a link from
// a mailbox and no session, and every session has just ended.
func (p *Plugin) handleChangeRevert(rctx *types.RequestContext) error {
	rawToken, err := changeToken(rctx, "emailverification.RevertChange")
	if err != nil {
		return err
	}
	if _, err := p.RevertChange(rctx.Ctx, rawToken); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "reverted"})
}
