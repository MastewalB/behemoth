package twofactor

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/twofactor/totp"
	"github.com/MastewalB/behemoth/store"
)

// onCredentialsVerified handles auth.signIn.credentialsVerified, the
// checkpoint every sign-in passes once its first factor checked out. The
// session of a user with a method that is on is made pending. A method on
// the channel the first factor used does not count, and a sign-in that
// leaves the user no method is refused with ErrorCodeSameChannel. See
// ADR-0009.
func (p *Plugin) onCredentialsVerified(hctx *core.HookContext, payload behemoth.M) (behemoth.M, error) {
	const op = "twofactor.SignIn"
	userID, _ := payload[hooks.HookValueUserID].(string)
	factor, _ := payload[hooks.HookValueFactor].(string)
	rows, err := methodsOf(hctx.Ctx, p.ac.Store.DB(), userID)
	if err != nil {
		return nil, err
	}
	on := confirmedOf(rows)
	if len(on) == 0 {
		return nil, nil // the plugin is off for the user
	}
	usable, err := p.usable(hctx.Ctx, userID, on, []string{factor})
	if err != nil {
		return nil, err
	}
	if len(usable) == 0 {
		return nil, errSameChannel(op)
	}
	payload[hooks.HookValueRequireStepUp] = true
	return payload, nil
}

// usable returns the methods a sign-in whose session proved factors may
// pass its second factor with, in the order TOTP, email, SMS: the methods
// that are on, that Options.Methods offers, and that are not on a channel
// among factors. Recovery codes follow when the user has one left: they
// count after any first factor.
func (p *Plugin) usable(ctx context.Context, userID string, on []*methodRow, factors []string) ([]Method, error) {
	var methods []Method
	for _, m := range []Method{MethodTOTP, MethodEmail, MethodSMS} {
		turnedOn := slices.ContainsFunc(on, func(r *methodRow) bool { return r.Method == m })
		if turnedOn && p.offers(m) && !slices.Contains(factors, string(m)) {
			methods = append(methods, m)
		}
	}
	left, err := p.ac.Store.DB().Count(ctx, &recoveryCodeRow{}, unusedCodes(userID))
	if err != nil {
		return nil, err
	}
	if left > 0 {
		methods = append(methods, MethodRecoveryCode)
	}
	return methods, nil
}

// pending returns the session of a caller whose sign-in waits for a second
// factor: the caller of a call that presented the pending session's token,
// anonymous with errs.CodeSessionPending. It is the one caller the
// challenge flows accept. A caller whose token failed otherwise gets the
// reason, one that presented none errs.CodeSessionMissing, and one whose
// session is active ErrorCodeNotPending.
func pending(ctx context.Context, op string) (identity.SessionRef, error) {
	caller := identity.CallerFrom(ctx)
	session, ok := caller.Session()
	switch {
	case ok && session.State == string(models.SessionPending):
		return session, nil
	case ok:
		return identity.SessionRef{}, errNotPending(op)
	case caller.AuthError() != nil:
		return identity.SessionRef{}, caller.AuthError()
	}
	return identity.SessionRef{}, errs.NewSessionError(op, errs.CodeSessionMissing, nil)
}

// ChallengeMethod is one way a pending sign-in may pass its second factor.
type ChallengeMethod struct {
	Method Method
	// Destination is where a sent code goes, partly hidden, such as
	// "a***@example.com" or "+1******0123". It is empty for TOTP and for
	// recovery codes.
	Destination string
}

// Challenge is what Challenge returns.
type Challenge struct {
	// Methods are the ways the sign-in may pass its second factor, in the
	// order TOTP, email, SMS, and recovery codes.
	Methods []ChallengeMethod
	// Locked says that too many second factors failed in a row. Methods
	// then holds recovery codes only, if the user has any left.
	Locked bool
}

// Challenge returns the methods the caller's pending sign-in may pass its
// second factor with. A method on the channel of the sign-in's first factor
// is left out: an email code after a magic link would prove the same
// mailbox twice. The caller is the pending session, as for Verify.
func (p *Plugin) Challenge(ctx context.Context) (*Challenge, error) {
	const op = "twofactor.Challenge"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	session, err := pending(ctx, op)
	if err != nil {
		return nil, err
	}
	rows, err := methodsOf(ctx, p.ac.Store.DB(), session.UserID)
	if err != nil {
		return nil, err
	}
	usable, err := p.usable(ctx, session.UserID, confirmedOf(rows), session.Factors)
	if err != nil {
		return nil, err
	}
	locked, err := p.locked(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	destinations := map[Method]string{}
	for _, r := range rows {
		destinations[r.Method] = r.Destination
	}
	challenge := &Challenge{Locked: locked}
	for _, m := range usable {
		if locked && m != MethodRecoveryCode {
			continue
		}
		challenge.Methods = append(challenge.Methods, ChallengeMethod{Method: m, Destination: masked(m, destinations[m])})
	}
	return challenge, nil
}

// masked returns destination partly hidden: the first character of an
// address's local part and its domain, and the first two and last four
// characters of a number.
func masked(method Method, destination string) string {
	switch method {
	case MethodEmail:
		local, domain, ok := strings.Cut(destination, "@")
		if !ok || local == "" {
			return "***"
		}
		return string([]rune(local)[:1]) + "***@" + domain
	case MethodSMS:
		if len(destination) <= 6 {
			return strings.Repeat("*", len(destination))
		}
		return destination[:2] + strings.Repeat("*", len(destination)-6) + destination[len(destination)-4:]
	}
	return ""
}

// SendCodeRequest is the input of SendCode.
type SendCodeRequest struct {
	// Method is MethodEmail or MethodSMS.
	Method Method
	// Metadata is passed to the sender as it is, such as a locale. The
	// plugin does not read or store it.
	Metadata behemoth.M
}

// SendCode sends a code that completes the caller's pending sign-in, by
// email or text message, to the destination of the caller's method. The
// code works for that pending session only, and a new code replaces the
// user's earlier one for the channel.
//
// A method the sign-in may not use (see Challenge), TOTP included, gets
// ErrorCodeMethodUnavailable, and nothing is sent under the lock
// (ErrorCodeLocked). The caller is the pending session, as for Verify. It
// fires auth.twoFactor.beforeSend, where the rate limits per user and per
// address run, and .afterSend or .sendFailed.
func (p *Plugin) SendCode(ctx context.Context, req SendCodeRequest) (*SendResult, error) {
	const op = "twofactor.SendCode"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	session, err := pending(ctx, op)
	if err != nil {
		return nil, err
	}
	method, err := parseMethod(op, string(req.Method))
	if err != nil {
		return nil, err
	}
	userID := session.UserID
	hctx, err := p.operation(ctx, op, userID)
	if err != nil {
		return nil, err
	}
	refuse := func(code string, answer error) (*SendResult, error) {
		if err := p.failed(hctx, HookSendFailed, code, nil, userID); err != nil {
			return nil, err
		}
		return nil, answer
	}
	rows, err := methodsOf(ctx, p.ac.Store.DB(), userID)
	if err != nil {
		return nil, err
	}
	usable, err := p.usable(ctx, userID, confirmedOf(rows), session.Factors)
	if err != nil {
		return nil, err
	}
	if method == MethodTOTP || !slices.Contains(usable, method) {
		return refuse("method_unavailable", errMethodUnavailable(op))
	}
	locked, err := p.locked(ctx, userID)
	if err != nil {
		return nil, err
	}
	if locked {
		return refuse("locked", errLocked(op))
	}
	user, err := p.ac.Store.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(rows, func(r *methodRow) bool { return r.Method == method })
	return p.send(ctx, op, PurposeSignIn, method, user, rows[i].Destination, req.Metadata, behemoth.M{keySessionID: session.ID})
}

// VerifyRequest is the input of Verify.
type VerifyRequest struct {
	// Method is what Code is: a code for MethodTOTP, MethodEmail, or
	// MethodSMS, or a recovery code for MethodRecoveryCode.
	Method Method
	Code   string
}

// Verify finishes the caller's pending sign-in with its second factor. It
// checks code for method, spends it, and promotes the session
// (SessionManager.Promote), which gets a new token: the result is a
// finished sign-in, as a sign-in flow returns one, and the pending token
// stops working. The session records the method as its second factor
// (models.Session.Factors). The raw session token is in the result and is
// the caller's to deliver.
//
// A code that is wrong, expired, used, or was sent for another sign-in is
// refused with ErrorCodeInvalidCode, and counts as a failure of the user,
// across pending sessions. After Options.MaxFailures failures in a row,
// only a recovery code passes, and the other methods get ErrorCodeLocked; a
// second factor that passes clears the count. A method the sign-in may not
// use gets ErrorCodeMethodUnavailable.
//
// The caller is the pending session: the caller of a call that presented
// its token, which is anonymous with errs.CodeSessionPending. A caller
// without one gets the reason its token failed, or errs.CodeSessionMissing,
// and a caller with an active session gets ErrorCodeNotPending. It fires
// auth.twoFactor.beforeVerify, where the rate limits per user and per
// address run, and .afterVerify or .verifyFailed.
func (p *Plugin) Verify(ctx context.Context, req VerifyRequest) (*core.SignInResult, error) {
	const op = "twofactor.Verify"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	session, err := pending(ctx, op)
	if err != nil {
		return nil, err
	}
	method, err := parseVerifyMethod(op, string(req.Method))
	if err != nil {
		return nil, err
	}
	userID := session.UserID
	hctx, err := p.operation(ctx, op, userID)
	if err != nil {
		return nil, err
	}
	d := p.ac.Dispatcher
	if _, err := d.RunBefore(hctx, HookVerifyBefore, behemoth.M{
		hooks.HookValueUserID: userID, keyMethod: string(method), hooks.HookValueSessionID: session.ID,
	}); err != nil {
		return nil, core.FailIfRejected(d, hctx, HookVerifyFailed, err, core.FailureReason{SubjectType: models.UserTable, SubjectID: userID})
	}
	refuse := func(code string, answer error) (*core.SignInResult, error) {
		if err := p.failed(hctx, HookVerifyFailed, code, nil, userID); err != nil {
			return nil, err
		}
		return nil, answer
	}

	rows, err := methodsOf(hctx.Ctx, p.ac.Store.DB(), userID)
	if err != nil {
		return nil, err
	}
	usable, err := p.usable(hctx.Ctx, userID, confirmedOf(rows), session.Factors)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(usable, method) {
		return refuse("method_unavailable", errMethodUnavailable(op))
	}
	if method != MethodRecoveryCode {
		locked, err := p.locked(hctx.Ctx, userID)
		if err != nil {
			return nil, err
		}
		if locked {
			return refuse("locked", errLocked(op))
		}
	}
	passed, err := p.spend(hctx.Ctx, session, method, req.Code)
	if err != nil {
		return nil, err
	}
	if !passed {
		if err := p.countFailure(hctx.Ctx, userID); err != nil {
			return nil, err
		}
		return refuse("invalid_code", errInvalidCode(op))
	}

	promoted, rawToken, err := p.ac.SessionManager.Promote(hctx.Ctx, session.ID, string(method))
	if err != nil {
		return nil, err
	}
	if err := p.resetFailures(hctx.Ctx, userID); err != nil {
		return nil, err
	}
	user, err := p.ac.Store.FindUserByID(hctx.Ctx, userID)
	if err != nil {
		return nil, err
	}
	result := &core.SignInResult{User: user, Session: promoted, RawToken: rawToken, Method: PluginName}
	if err := d.RunAfter(hctx, HookVerifyAfter, result); err != nil {
		return nil, err
	}
	return result, nil
}

// spend checks code for method and, when it passes, spends it, so that it
// finishes one sign-in at most. It reports false for a code that does not
// pass.
func (p *Plugin) spend(ctx context.Context, session identity.SessionRef, method Method, code string) (bool, error) {
	db := p.ac.Store.DB()
	now := p.ac.Store.Now()
	switch method {
	case MethodTOTP:
		row, err := methodOf(ctx, db, session.UserID, MethodTOTP)
		if err != nil {
			return false, err
		}
		secret, err := p.openSecret(row.Secret)
		if err != nil {
			return false, err
		}
		step, ok := totp.Check(secret, code, now)
		if !ok {
			return false, nil
		}
		// The step is recorded only while it is later than the last one that
		// passed, in the write itself: a code works once, and of two
		// requests with one code, one passes.
		err = db.UpdateOne(ctx, &methodRow{}, clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
			{Field: colID, Operator: clause.OpEqual, Value: row.ID},
			{Field: colLastStep, Operator: clause.OpLessThan, Value: step},
		}}, behemoth.M{colLastStep: step, colUpdatedAt: now})
		if errs.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err

	case MethodRecoveryCode:
		found, err := db.FindMany(ctx, &recoveryCodeRow{}, unusedCodes(session.UserID), nil)
		if err != nil {
			return false, err
		}
		var match *recoveryCodeRow
		for _, f := range found {
			row := f.(*recoveryCodeRow)
			ok, err := p.ac.Crypto.Secrets.Verify(recoveryHashed(session.UserID, code), row.CodeHash, row.KeyVersion)
			if err != nil {
				return false, err
			}
			if ok && match == nil {
				match = row // the rest are compared too, so the time does not tell which one matched
			}
		}
		if match == nil {
			return false, nil
		}
		// Used up at most once: the write requires the code to be unused.
		err = db.UpdateOne(ctx, &recoveryCodeRow{}, clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
			{Field: colID, Operator: clause.OpEqual, Value: match.ID},
			{Field: colUsedAt, Operator: clause.OpIsNull},
		}}, behemoth.M{colUsedAt: now})
		if errs.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err

	default: // a code sent by email or text message
		consumed, err := p.ac.Codes.Consume(ctx, codeKind(PurposeSignIn, method), session.UserID, code)
		if errs.IsCodeRejection(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// The code was sent for one pending sign-in. The consume comes
		// first, so a code presented by another session is spent.
		sentFor, _ := consumed.Metadata[keySessionID].(string)
		return sentFor == session.ID, nil
	}
}

// countFailure adds a failed second factor to userID's count. The write is
// guarded on the count that was read, as the code manager's attempts are,
// so that failures arriving together each count.
func (p *Plugin) countFailure(ctx context.Context, userID string) error {
	db := p.ac.Store.DB()
	for range 8 {
		now := p.ac.Store.Now()
		found, err := db.FindOne(ctx, &failureRow{}, byUser(userID))
		if errs.IsNotFound(err) {
			err = db.Create(ctx, &failureRow{UserID: userID, Failures: 1, UpdatedAt: now})
			if !errs.IsDuplicateKey(err) {
				return err
			}
			continue // another failure created the row first
		}
		if err != nil {
			return err
		}
		row := found.(*failureRow)
		err = db.UpdateOne(ctx, &failureRow{}, clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
			{Field: colUserID, Operator: clause.OpEqual, Value: userID},
			{Field: colFailures, Operator: clause.OpEqual, Value: row.Failures},
		}}, behemoth.M{colFailures: row.Failures + 1, colUpdatedAt: now})
		if !errs.IsNotFound(err) {
			return err
		}
	}
	return fmt.Errorf("twofactor: the failure count of user %s is still contended", userID)
}

// resetFailures clears userID's count of failed second factors.
func (p *Plugin) resetFailures(ctx context.Context, userID string) error {
	return p.ac.Store.DB().DeleteMany(ctx, &failureRow{}, byUser(userID))
}

// locked reports whether userID has failed Options.MaxFailures second
// factors in a row.
func (p *Plugin) locked(ctx context.Context, userID string) (bool, error) {
	found, err := p.ac.Store.DB().FindOne(ctx, &failureRow{}, byUser(userID))
	if errs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return found.(*failureRow).Failures >= p.opts.MaxFailures, nil
}

// ResetRequest is the input of Reset.
type ResetRequest struct {
	UserID string
}

// Reset turns every method of the user named in req off, for a user who
// lost every method and every recovery code. It deletes the methods, a
// setup in progress included, the recovery codes, the failure count, and
// the codes sent and not used. It fires the disable points with
// ReasonAdminReset and no method.
//
// It is an admin operation: the caller needs PermissionReset
// (Access.RequireAdmin), which only a system caller holds today. A user
// without a method gets a conflict with ErrorCodeNotEnabled.
func (p *Plugin) Reset(ctx context.Context, req ResetRequest) (*DisableResult, error) {
	const op = "twofactor.Reset"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	if err := p.ac.Access.RequireAdmin(ctx, PermissionReset); err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, req.UserID)
	if err != nil {
		return nil, err
	}
	return p.reset(hctx, disableInput{userID: req.UserID, reason: ReasonAdminReset})
}

func (p *Plugin) resetBody(hctx *core.HookContext, in disableInput) (*DisableResult, error) {
	const op = "twofactor.Reset"
	err := p.ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
		db := tx.DB()
		rows, err := methodsOf(ctx, db, in.userID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return errs.NewNotFound(op, MethodTable, nil)
		}
		for _, model := range []behemoth.Model{&methodRow{}, &recoveryCodeRow{}, &failureRow{}} {
			if err := db.DeleteMany(ctx, model, byUser(in.userID)); err != nil {
				return err
			}
		}
		return nil
	})
	if errs.IsNotFound(err) {
		if failErr := p.failed(hctx, HookDisableFailed, "not_enabled", nil, in.userID); failErr != nil {
			return nil, failErr
		}
		return nil, errNotEnabled(op)
	}
	if err != nil {
		return nil, err
	}
	for _, purpose := range []Purpose{PurposeSetup, PurposeSignIn} {
		for _, method := range []Method{MethodEmail, MethodSMS} {
			if p.ac.Codes == nil {
				break
			}
			if err := p.ac.Codes.Revoke(hctx.Ctx, codeKind(purpose, method), in.userID); err != nil {
				return nil, err
			}
		}
	}
	return &DisableResult{UserID: in.userID, Reason: in.reason, Off: true}, nil
}
