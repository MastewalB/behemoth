package twofactor

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/plugins/phonenumber"
	"github.com/MastewalB/behemoth/plugins/twofactor/totp"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/utils"
)

// SessionRevokedEnabled is the revoke reason of the sessions that end when a
// user's first method is turned on: they were opened without a second
// factor.
const SessionRevokedEnabled = "two_factor_enabled"

// MethodStatus is one method that is on, as Status reports it.
type MethodStatus struct {
	Method Method
	// Destination is the address or number the method's codes go to. It is
	// empty for TOTP.
	Destination string
	// ConfirmedAt is when the method was turned on.
	ConfirmedAt time.Time
}

// Status is what Status returns.
type Status struct {
	// Methods are the methods that are on, by name. The plugin is on for the
	// user when there is at least one.
	Methods []MethodStatus
	// RecoveryCodesLeft is the number of recovery codes not used yet.
	RecoveryCodesLeft int
}

// Status returns the methods that are on for the caller's account, and how
// many recovery codes are left. The caller needs PermissionRead
// (Access.RequireUser).
func (p *Plugin) Status(ctx context.Context) (*Status, error) {
	const op = "twofactor.Status"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	userID, err := p.ac.Access.RequireUser(ctx, PermissionRead)
	if err != nil {
		return nil, err
	}
	db := p.ac.Store.DB()
	rows, err := methodsOf(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	status := &Status{}
	for _, r := range confirmedOf(rows) {
		status.Methods = append(status.Methods, MethodStatus{Method: r.Method, Destination: r.Destination, ConfirmedAt: *r.ConfirmedAt})
	}
	slices.SortFunc(status.Methods, func(a, b MethodStatus) int { return strings.Compare(string(a.Method), string(b.Method)) })
	left, err := db.Count(ctx, &recoveryCodeRow{}, unusedCodes(userID))
	if err != nil {
		return nil, err
	}
	status.RecoveryCodesLeft = int(left)
	return status, nil
}

// EnrollRequest is the input of Enroll.
type EnrollRequest struct {
	Method Method
	// PhoneNumber is the number to send codes to, for MethodSMS, in E.164
	// form ("+14155550123").
	PhoneNumber string
	// Metadata is passed to the mail or SMS sender as it is, such as a
	// locale. The plugin does not read or store it.
	Metadata behemoth.M
}

// Enrollment is what Enroll returns.
type Enrollment struct {
	Method Method
	// Secret and URI are set for TOTP: the secret in base32, for typing into
	// an app, and the otpauth link a QR code carries. They are credentials:
	// show them to the user and keep them nowhere else.
	Secret string
	URI    string
	// Destination and ExpiresAt are set for email and SMS: where the setup
	// code went, and when it stops working.
	Destination string
	ExpiresAt   time.Time
}

// Enroll starts turning a method on for the caller's account. The method is
// on once Confirm gets a code that shows the user holds it.
//
// For TOTP it generates a secret, stores it sealed, and returns it with the
// link a QR code carries; the code to confirm is one an authenticator app
// computes from it. A user who has TOTP on keeps the old secret until the
// new one is confirmed. For email it sends a setup code to the account's
// address, and for SMS to req.PhoneNumber. Once confirmed, the method's
// codes go to that address or number, whatever the account's email or phone
// number becomes.
//
// The caller needs PermissionManage and a fresh session
// (Access.RequireFreshUser). A method Options.Methods does not offer gets a
// forbidden error with ErrorCodeMethodUnavailable, and a malformed number a
// validation error. Sending a code fires auth.twoFactor.beforeSend, and
// .afterSend or .sendFailed.
func (p *Plugin) Enroll(ctx context.Context, req EnrollRequest) (*Enrollment, error) {
	const op = "twofactor.Enroll"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	userID, err := p.ac.Access.RequireFreshUser(ctx, PermissionManage)
	if err != nil {
		return nil, err
	}
	method, err := p.method(op, string(req.Method))
	if err != nil {
		return nil, err
	}
	user, err := p.ac.Store.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	switch method {
	case MethodTOTP:
		return p.enrollTOTP(ctx, op, user)
	case MethodEmail:
		return p.enrollDestination(ctx, op, user, method, user.Email, req.Metadata)
	default:
		number, err := phonenumber.Parse(req.PhoneNumber)
		if err != nil {
			return nil, err
		}
		return p.enrollDestination(ctx, op, user, method, number, req.Metadata)
	}
}

// enrollTOTP stores a new secret, sealed, as the pending secret of the
// user's TOTP row.
func (p *Plugin) enrollTOTP(ctx context.Context, op string, user *models.User) (*Enrollment, error) {
	secret, err := p.ac.Crypto.Random.SecureRandomBytes(totp.SecretSize)
	if err != nil {
		return nil, errs.NewSecurityError(op, "random_generation_failed", err)
	}
	encoded := totp.EncodeSecret(secret)
	sealed, err := p.ac.Store.Seal(encoded)
	if err != nil {
		return nil, err
	}
	if err := p.upsertMethod(ctx, p.ac.Store.DB(), user.ID, MethodTOTP, behemoth.M{colPendingSecret: sealed}); err != nil {
		return nil, err
	}
	return &Enrollment{Method: MethodTOTP, Secret: encoded, URI: totp.URI(p.opts.Issuer, user.Email, secret)}, nil
}

// enrollDestination sends a setup code to destination. The destination
// travels in the code's metadata, so that Confirm stores the one the code
// went to.
func (p *Plugin) enrollDestination(ctx context.Context, op string, user *models.User, method Method, destination string, metadata behemoth.M) (*Enrollment, error) {
	sent, err := p.send(ctx, op, PurposeSetup, method, user, destination, metadata, behemoth.M{keyDestination: destination})
	if err != nil {
		return nil, err
	}
	return &Enrollment{Method: method, Destination: destination, ExpiresAt: sent.ExpiresAt}, nil
}

// SendResult is what a send hands to auth.twoFactor.afterSend. It does not
// hold the code.
type SendResult struct {
	UserID      string
	Method      Method
	Purpose     Purpose
	Destination string
	ExpiresAt   time.Time
}

// AuditSubject implements [core.AuditSubject]: a code is about the user it
// was sent to.
func (r *SendResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.UserID == "" {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// send issues a code for purpose and sends it to destination by method. It
// fires its points itself, as the phone number plugin's send does: the after
// point is for a code that went out. A code that was not handed to the
// sender is revoked, and the error is returned.
func (p *Plugin) send(ctx context.Context, op string, purpose Purpose, method Method, user *models.User, destination string, metadata, codeMetadata behemoth.M) (*SendResult, error) {
	hctx, err := p.operation(ctx, op, user.ID)
	if err != nil {
		return nil, err
	}
	d := p.ac.Dispatcher
	if _, err := d.RunBefore(hctx, HookSendBefore, behemoth.M{
		hooks.HookValueUserID: user.ID, keyMethod: string(method), keyPurpose: string(purpose),
	}); err != nil {
		return nil, core.FailIfRejected(d, hctx, HookSendFailed, err, core.FailureReason{SubjectType: models.UserTable, SubjectID: user.ID})
	}

	kind := codeKind(purpose, method)
	code, issued, err := p.ac.Codes.Issue(hctx.Ctx, kind, user.ID, core.CodeOptions{
		Length: p.opts.CodeLength, TTL: p.opts.CodeTTL, MaxAttempts: p.opts.MaxAttempts, Metadata: codeMetadata,
	})
	if err != nil {
		return nil, err
	}
	if err := p.deliver(hctx.Ctx, purpose, method, user, destination, code, issued.ExpiresAt, metadata); err != nil {
		// Nobody received the code, so it should not stay usable.
		p.log.Error(hctx.Ctx, "a two-factor code was not handed to the sender", telemetry.ErrorFields(err, behemoth.M{keyMethod: string(method), keyPurpose: string(purpose)}))
		if revokeErr := p.ac.Codes.Revoke(hctx.Ctx, kind, user.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the unsent code was not revoked", telemetry.ErrorFields(revokeErr))
		}
		if failErr := p.failed(hctx, HookSendFailed, "send_failed", err, user.ID); failErr != nil {
			return nil, failErr
		}
		return nil, err
	}

	result := &SendResult{UserID: user.ID, Method: method, Purpose: purpose, Destination: destination, ExpiresAt: issued.ExpiresAt}
	if err := d.RunAfter(hctx, HookSendAfter, result); err != nil {
		return nil, err
	}
	return result, nil
}

// deliver hands code to the mail or SMS sender, and waits for it with
// Options.WaitForSend.
func (p *Plugin) deliver(ctx context.Context, purpose Purpose, method Method, user *models.User, destination, code string, expiresAt time.Time, metadata behemoth.M) error {
	if method == MethodEmail {
		kind := core.MailTwoFactorSetup
		if purpose != PurposeSetup {
			kind = core.MailTwoFactorCode
		}
		msg := core.MailMessage{Kind: kind, To: destination, Code: code, ExpiresAt: expiresAt, User: user, Metadata: metadata}
		if p.opts.WaitForSend {
			return p.ac.Mailer.Send(ctx, msg)
		}
		return p.ac.Mailer.SendAsync(ctx, msg)
	}
	kind := core.SMSTwoFactorSetup
	if purpose != PurposeSetup {
		kind = core.SMSTwoFactorCode
	}
	msg := core.SMSMessage{Kind: kind, To: destination, Code: code, ExpiresAt: expiresAt, User: user, Metadata: metadata}
	if p.opts.WaitForSend {
		return p.ac.SMS.Send(ctx, msg)
	}
	return p.ac.SMS.SendAsync(ctx, msg)
}

// ConfirmRequest is the input of Confirm.
type ConfirmRequest struct {
	Method Method
	Code   string
}

// EnableResult is what auth.twoFactor.afterEnable receives: the method that
// is on. It holds no secret and no recovery code.
type EnableResult struct {
	UserID      string
	Method      Method
	Destination string // the address or number the method's codes go to; empty for TOTP
	// First says that no method was on before: the plugin is now on for the
	// user, the user got recovery codes, and their other sessions ended.
	First bool
}

// AuditSubject implements [core.AuditSubject]: the method is the user's.
func (r *EnableResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.UserID == "" {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// ConfirmResult is what Confirm returns.
type ConfirmResult struct {
	EnableResult
	// RecoveryCodes are set with the user's first method, and only then.
	// Show them to the user once: only their hashes are stored. They are
	// credentials.
	RecoveryCodes []string
}

// Confirm turns on the method Enroll set up, once code shows that the user
// holds it: for TOTP, a code an authenticator app computed from the new
// secret, and for email and SMS, the code Enroll sent. A TOTP code that
// confirms can't sign in afterwards.
//
// With the user's first method, Confirm also creates the recovery codes and
// returns them, the only time they are shown, and ends the user's other
// sessions with the reason SessionRevokedEnabled: they were opened without a
// second factor. The session that confirms stays. If ending them fails, the
// error is returned and the method stays on.
//
// The caller needs PermissionManage and a fresh session. A wrong, expired,
// or used code, and one with no setup in progress, get one error with
// ErrorCodeInvalidCode. It fires auth.twoFactor.beforeEnable, and
// .afterEnable or .enableFailed.
func (p *Plugin) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResult, error) {
	const op = "twofactor.Confirm"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	userID, err := p.ac.Access.RequireFreshUser(ctx, PermissionManage)
	if err != nil {
		return nil, err
	}
	method, err := p.method(op, string(req.Method))
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, userID)
	if err != nil {
		return nil, err
	}
	// The points are fired here and not by WithLifecycle: the caller gets
	// the recovery codes, and the after point's result must not hold them.
	d := p.ac.Dispatcher
	if _, err := d.RunBefore(hctx, HookEnableBefore, behemoth.M{hooks.HookValueUserID: userID, keyMethod: string(method)}); err != nil {
		return nil, core.FailIfRejected(d, hctx, HookEnableFailed, err, core.FailureReason{SubjectType: models.UserTable, SubjectID: userID})
	}
	changes, err := p.proven(hctx, op, userID, method, req.Code)
	if err != nil {
		return nil, err
	}
	result, codes, err := p.enable(hctx.Ctx, userID, method, changes)
	if err != nil {
		return nil, err
	}
	if result.First {
		except := ""
		if session, ok := identity.CallerFrom(ctx).Session(); ok {
			except = session.ID
		}
		if err := p.ac.SessionManager.RevokeAllForUser(hctx.Ctx, userID, SessionRevokedEnabled, except); err != nil {
			return nil, err
		}
	}
	if err := d.RunAfter(hctx, HookEnableAfter, result); err != nil {
		return nil, err
	}
	return &ConfirmResult{EnableResult: *result, RecoveryCodes: codes}, nil
}

// proven checks code for method and returns the changes that turn the
// method on: the confirmed secret and the step that passed for TOTP, the
// destination the code was sent to for email and SMS. A refusal fires
// auth.twoFactor.enableFailed with the code "invalid_code".
func (p *Plugin) proven(hctx *core.HookContext, op, userID string, method Method, code string) (behemoth.M, error) {
	refuse := func(cause error) (behemoth.M, error) {
		if err := p.failed(hctx, HookEnableFailed, "invalid_code", cause, userID); err != nil {
			return nil, err
		}
		return nil, errInvalidCode(op)
	}
	if method != MethodTOTP {
		consumed, err := p.ac.Codes.Consume(hctx.Ctx, codeKind(PurposeSetup, method), userID, code)
		if err != nil {
			if !errs.IsCodeRejection(err) {
				return nil, err
			}
			return refuse(err)
		}
		destination, _ := consumed.Metadata[keyDestination].(string)
		return behemoth.M{colDestination: destination}, nil
	}

	row, err := methodOf(hctx.Ctx, p.ac.Store.DB(), userID, MethodTOTP)
	if err != nil && !errs.IsNotFound(err) {
		return nil, err
	}
	if row == nil || row.PendingSecret == "" {
		return refuse(nil) // no setup in progress
	}
	secret, err := p.openSecret(row.PendingSecret)
	if err != nil {
		return nil, err
	}
	step, ok := totp.Check(secret, code, p.ac.Store.Now())
	if !ok {
		return refuse(nil)
	}
	// The step that confirmed is recorded as passed, so the same code can't
	// sign in.
	return behemoth.M{colSecret: row.PendingSecret, colPendingSecret: nil, colLastStep: step}, nil
}

// openSecret returns the TOTP secret a sealed value holds.
func (p *Plugin) openSecret(sealed string) ([]byte, error) {
	encoded, err := p.ac.Store.Open(sealed)
	if err != nil {
		return nil, err
	}
	return totp.DecodeSecret(encoded)
}

// enable writes changes to the user's row for method and marks it
// confirmed, in one transaction with the recovery codes of a first method.
// It returns the codes, which only a first method gets.
func (p *Plugin) enable(ctx context.Context, userID string, method Method, changes behemoth.M) (*EnableResult, []string, error) {
	result := &EnableResult{UserID: userID, Method: method}
	result.Destination, _ = changes[colDestination].(string)
	var codes []string
	err := p.ac.Store.Transaction(ctx, func(ctx context.Context, tx *store.Store) error {
		db := tx.DB()
		rows, err := methodsOf(ctx, db, userID)
		if err != nil {
			return err
		}
		result.First = len(confirmedOf(rows)) == 0
		confirmed := false
		for _, r := range rows {
			confirmed = confirmed || (r.Method == method && r.ConfirmedAt != nil)
		}
		if !confirmed {
			changes[colConfirmedAt] = p.ac.Store.Now()
		}
		if err := p.upsertMethod(ctx, db, userID, method, changes); err != nil {
			return err
		}
		if result.First {
			codes, err = p.replaceRecoveryCodes(ctx, db, userID)
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return result, codes, nil
}

// upsertMethod applies changes to userID's row for method, and creates the
// row when there is none. Of two calls that create it at once, the second
// finds the unique index taken and updates the first's row.
func (p *Plugin) upsertMethod(ctx context.Context, db behemoth.Database, userID string, method Method, changes behemoth.M) error {
	now := p.ac.Store.Now()
	for range 2 {
		row, err := methodOf(ctx, db, userID, method)
		if err == nil {
			update := maps.Clone(changes)
			update[colUpdatedAt] = now
			return db.UpdateOne(ctx, &methodRow{}, byID(row.ID), update)
		}
		if !errs.IsNotFound(err) {
			return err
		}
		created := &methodRow{ID: utils.GenerateUUID(), UserID: userID, Method: method, CreatedAt: now, UpdatedAt: now}
		fields, err := created.ToMap()
		if err != nil {
			return err
		}
		maps.Copy(fields, changes)
		if err := created.FromMap(fields); err != nil {
			return err
		}
		if err := db.Create(ctx, created); !errs.IsDuplicateKey(err) {
			return err
		}
	}
	return fmt.Errorf("twofactor: the %s method of user %s is still contended", method, userID)
}

// DisableRequest is the input of Disable.
type DisableRequest struct {
	Method Method
}

// DisableResult is what Disable returns and auth.twoFactor.afterDisable
// receives.
type DisableResult struct {
	UserID string
	Method Method
	Reason string // why the method went: ReasonUserDisabled
	// Off says that no method is left on: the plugin is off for the user,
	// and the recovery codes are gone.
	Off bool
}

// AuditSubject implements [core.AuditSubject]: the method was the user's.
func (r *DisableResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.UserID == "" {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// disableInput is the input of the wrapped flow behind Disable. Its payload
// on auth.twoFactor.beforeDisable is "userID", "method", and "reason", and
// nothing is read back: a handler can stop the change, but it can't point
// it at another method.
type disableInput struct {
	userID string
	method Method
	reason string
}

func (in *disableInput) ToMap() (map[string]any, error) {
	return map[string]any{hooks.HookValueUserID: in.userID, keyMethod: string(in.method), keyReason: in.reason}, nil
}

func (in *disableInput) FromMap(map[string]any) error { return nil }

// Disable turns a method of the caller's account off, a setup in progress
// included. When no method is left on, the recovery codes go too, and a
// sign-in of the user no longer waits for a second factor. A method that
// Options.Methods no longer offers can still be turned off.
//
// The caller needs PermissionManage and a fresh session. A method that is
// not on gets a conflict with ErrorCodeNotEnabled. It fires
// auth.twoFactor.beforeDisable, and .afterDisable or .disableFailed.
func (p *Plugin) Disable(ctx context.Context, req DisableRequest) (*DisableResult, error) {
	const op = "twofactor.Disable"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	userID, err := p.ac.Access.RequireFreshUser(ctx, PermissionManage)
	if err != nil {
		return nil, err
	}
	method, err := parseMethod(op, string(req.Method))
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, userID)
	if err != nil {
		return nil, err
	}
	return p.disable(hctx, disableInput{userID: userID, method: method, reason: ReasonUserDisabled})
}

func (p *Plugin) disableBody(hctx *core.HookContext, in disableInput) (*DisableResult, error) {
	const op = "twofactor.Disable"
	result := &DisableResult{UserID: in.userID, Method: in.method, Reason: in.reason}
	err := p.ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
		db := tx.DB()
		row, err := methodOf(ctx, db, in.userID, in.method)
		if err != nil {
			return err
		}
		if err := db.Delete(ctx, row); err != nil {
			return err
		}
		rows, err := methodsOf(ctx, db, in.userID)
		if err != nil {
			return err
		}
		if len(confirmedOf(rows)) > 0 {
			return nil
		}
		result.Off = true
		return db.DeleteMany(ctx, &recoveryCodeRow{}, byUser(in.userID))
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
	if in.method != MethodTOTP && p.ac.Codes != nil {
		// A setup code sent for the method stops working with it.
		if err := p.ac.Codes.Revoke(hctx.Ctx, codeKind(PurposeSetup, in.method), in.userID); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// RegenerateResult is what auth.twoFactor.afterRegenerate receives. It holds
// no code.
type RegenerateResult struct {
	UserID string
	Count  int // the number of codes in the new set
}

// AuditSubject implements [core.AuditSubject]: the codes are the user's.
func (r *RegenerateResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.UserID == "" {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// RegenerateRecoveryCodes replaces the recovery codes of the caller's
// account with a new set, and returns it: the only time the codes are
// shown. The codes of the old set stop working.
//
// The caller needs PermissionManage and a fresh session. A user without a
// method that is on gets a conflict with ErrorCodeNotEnabled. It fires
// auth.twoFactor.beforeRegenerate and .afterRegenerate.
func (p *Plugin) RegenerateRecoveryCodes(ctx context.Context) ([]string, error) {
	const op = "twofactor.RegenerateRecoveryCodes"
	if err := p.ready(op); err != nil {
		return nil, err
	}
	userID, err := p.ac.Access.RequireFreshUser(ctx, PermissionManage)
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, userID)
	if err != nil {
		return nil, err
	}
	d := p.ac.Dispatcher
	if _, err := d.RunBefore(hctx, HookRegenerateBefore, behemoth.M{hooks.HookValueUserID: userID}); err != nil {
		return nil, err
	}
	var codes []string
	err = p.ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
		rows, err := methodsOf(ctx, tx.DB(), userID)
		if err != nil {
			return err
		}
		if len(confirmedOf(rows)) == 0 {
			return errNotEnabled(op)
		}
		codes, err = p.replaceRecoveryCodes(ctx, tx.DB(), userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := d.RunAfter(hctx, HookRegenerateAfter, &RegenerateResult{UserID: userID, Count: len(codes)}); err != nil {
		return nil, err
	}
	return codes, nil
}

// recoveryAlphabet is Crockford's base32: no I, L, O, or U, so that a code
// read off paper is not misread. A random byte modulo 32 picks each symbol
// uniformly, since 256 is a multiple of 32.
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// recoveryCodeLength is the number of symbols in a recovery code: 50 bits,
// which puts guessing one out of reach without a limit of its own.
const recoveryCodeLength = 10

// newRecoveryCode returns a code in the form a user sees: "XXXXX-XXXXX".
func (p *Plugin) newRecoveryCode() (string, error) {
	raw, err := p.ac.Crypto.Random.SecureRandomBytes(recoveryCodeLength)
	if err != nil {
		return "", err
	}
	code := make([]byte, recoveryCodeLength)
	for i, b := range raw {
		code[i] = recoveryAlphabet[b%32]
	}
	return string(code[:5]) + "-" + string(code[5:]), nil
}

// normalizeRecoveryCode returns code in the form that is hashed: uppercase,
// without dashes or spaces, and with the letters Crockford's base32 reads as
// digits replaced: O by 0, I and L by 1.
func normalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch r = unicode.ToUpper(r); r {
		case '-', ' ':
			return -1
		case 'O':
			return '0'
		case 'I', 'L':
			return '1'
		}
		return r
	}, code)
}

// recoveryHashed is what is hashed for a recovery code: the user's id with
// the code, so that a hash copied to another user's row matches nothing
// there.
func recoveryHashed(userID, code string) string {
	return userID + "\x00" + normalizeRecoveryCode(code)
}

// replaceRecoveryCodes deletes userID's recovery codes and stores a new set
// through db, the transaction the caller runs in, and returns the codes in
// the form a user sees. Only keyed hashes are stored (Crypto.Secrets), so a
// copy of the table does not give the codes away.
func (p *Plugin) replaceRecoveryCodes(ctx context.Context, db behemoth.Database, userID string) ([]string, error) {
	const op = "twofactor.replaceRecoveryCodes"
	if err := db.DeleteMany(ctx, &recoveryCodeRow{}, byUser(userID)); err != nil {
		return nil, err
	}
	now := p.ac.Store.Now()
	codes := make([]string, 0, p.opts.RecoveryCodes)
	for range p.opts.RecoveryCodes {
		code, err := p.newRecoveryCode()
		if err != nil {
			return nil, errs.NewSecurityError(op, "random_generation_failed", err)
		}
		hash, keyVersion, err := p.ac.Crypto.Secrets.Hash(recoveryHashed(userID, code))
		if err != nil {
			return nil, err
		}
		if err := db.Create(ctx, &recoveryCodeRow{ID: utils.GenerateUUID(), UserID: userID, CodeHash: hash, KeyVersion: keyVersion, CreatedAt: now}); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// byID selects the row whose id is id.
func byID(id string) clause.Expression {
	return clause.Expression{Conditions: []clause.Condition{{Field: colID, Operator: clause.OpEqual, Value: id}}}
}
