// Package phonenumber is the phone number plugin: a user confirms a phone
// number with a one-time code sent by text message, and can then sign in
// with the number and a code, or with the number and their password.
//
// It builds on the email/password plugin (plugins/emailpassword) and depends
// on it: the password belongs to that plugin, and sign-in by number and
// password runs through emailpassword.Plugin.SignInWith, as the username
// plugin's sign-in does. Codes come from the code manager
// (AuthContext.Codes) and are delivered by the application's SMS sender
// (AuthContext.SMS).
//
// A number is written to a user only after a code sent to it was confirmed,
// so every stored number is a verified one. A user signs up by email and
// adds a number afterwards; sign-up with a number alone is not built,
// because users.email is required.
package phonenumber

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
	"github.com/MastewalB/behemoth/telemetry"
)

// PluginName is the name the plugin registers under (PluginMeta.Name). It
// owns the plugin's routes, column, hook points, handlers and rate-limit
// rules, and is the Method of the sign-ins it makes.
const PluginName = "phonenumber"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// Column is the phone number column the plugin contributes to users: unique,
// nullable and public. It holds the number in E.164 form ("+14155550123"),
// and no value for a user without one. A number in it was confirmed with a
// code, or set by the application through Plugin.SetPhoneNumber.
var Column = schema.Field[string]{Table: models.UserTable, Name: "phone_number"}

// columnLength holds an E.164 number: "+" and up to 15 digits.
const columnLength = 16

// Paths of the plugin's routes, below the router's base path. The two reset
// routes are mounted only with Options.PasswordReset.
const (
	PathSendOTP      = "/phone-number/send-otp"
	PathVerify       = "/phone-number/verify"
	PathSignIn       = "/sign-in/phone-number"
	PathResetRequest = "/phone-number/request-password-reset"
	PathReset        = "/phone-number/reset-password"
)

// The points the plugin declares and fires. Signing in, by code or by
// password, fires core's auth.signIn.* points instead.
const (
	// HookSendBefore runs before a code is sent, on "phone_number",
	// "purpose" and, for a signed-in caller, "userID". Veto only.
	HookSendBefore core.HookPoint = "auth.phoneNumber.beforeSend"
	// HookSendAfter runs once the message has been handed to the SMS
	// sender, with a *SendResult.
	HookSendAfter core.HookPoint = "auth.phoneNumber.afterSend"
	// HookSendFailed fires for a request that sent no code: codes
	// "no_account", "number_taken", "already_set", "send_failed" and
	// "rejected_by_hook".
	HookSendFailed core.HookPoint = "auth.phoneNumber.sendFailed"

	// HookVerifyBefore runs before a number is added to a user, on
	// "phone_number" and "userID". Veto only.
	HookVerifyBefore core.HookPoint = "auth.phoneNumber.beforeVerify"
	// HookVerifyAfter runs once the user holds the number, with the
	// *models.User.
	HookVerifyAfter core.HookPoint = "auth.phoneNumber.afterVerify"
	// HookVerifyFailed fires for a number that was not added: codes
	// "invalid_code", "number_mismatch", "number_taken" and "rejected_by_hook".
	HookVerifyFailed core.HookPoint = "auth.phoneNumber.verifyFailed"

	// HookResetBefore runs before a password is reset with a code, on
	// "phone_number" and "password". Veto only.
	HookResetBefore core.HookPoint = "auth.phoneNumber.beforePasswordReset"
	// HookResetAfter runs once the password is set, with the *models.User.
	HookResetAfter core.HookPoint = "auth.phoneNumber.afterPasswordReset"
	// HookResetFailed fires for a reset that was refused: codes
	// "no_account", "invalid_code" and "rejected_by_hook".
	HookResetFailed core.HookPoint = "auth.phoneNumber.passwordResetFailed"
)

// The permissions the plugin declares.
const (
	// PermissionPhoneChange is the permission SendCode and Verify require
	// of a caller that acts for a user: adding a phone number to the
	// caller's own account. A caller signing in by code needs none.
	PermissionPhoneChange core.Permission = "phone:change"
	// PermissionSetPhone is the admin permission SetPhoneNumber requires:
	// setting the number of an account named in the input, without a code.
	PermissionSetPhone core.Permission = "user:set_phone"
	// PermissionAddPhone is the admin permission AddNumber requires: adding
	// a number, with its code, to an account named in the input.
	PermissionAddPhone core.Permission = "user:add_phone"
)

// Names of the rate-limit rules the plugin declares. The rules that end in
// .address count per client address. RuleSendAddress counts the codes asked
// for with SendCode, and RuleResetRequestAddress those for a password reset.
// RuleSendNumber counts the codes asked for per number, from any caller and
// for any purpose: each one is a text message somebody pays for and somebody
// receives. A sign-in, with a code or a password, is counted by core's
// core.signin.address, per client address and method.
const (
	RuleSendAddress         = "phonenumber.send.address"
	RuleVerifyAddress       = "phonenumber.verify.address"
	RuleResetRequestAddress = "phonenumber.reset_request.address"
	RuleResetAddress        = "phonenumber.reset.address"
	RuleSendNumber          = "phonenumber.send.number"
)

// sendByAddress returns the KeyFunc of a send rule per client address: the
// caller's address, for the sends of a password reset when reset is true and
// for the other sends when it is false. The send publishes its purpose in
// Values under keyPurpose.
func sendByAddress(reset bool) func(hctx *core.HookContext) (string, bool) {
	byAddress := core.KeyByClientIP()
	return func(hctx *core.HookContext) (string, bool) {
		if (hctx.Values[keyPurpose] == string(PurposePasswordReset)) != reset {
			return "", false
		}
		return byAddress(hctx)
	}
}

// HookValuePhoneNumber is the key a flow's number is published under in
// HookContext.Values, in E.164 form, for rate-limit rules:
// core.KeyByValues(phonenumber.HookValuePhoneNumber). It is also the key of
// the number in the hook payloads and the request bodies.
const HookValuePhoneNumber = "phone_number"

// Keys of the request bodies and hook payloads.
const (
	keyCode     = "code"
	keyPassword = "password"
	keyMetadata = "metadata"
	keyPurpose  = "purpose"
	keyMethod   = "method"
)

// Purpose says what a code is for. It is the "purpose" of the
// auth.phoneNumber.beforeSend payload and of a SendResult.
type Purpose string

const (
	// PurposeVerify adds or changes the number of a signed-in user.
	PurposeVerify Purpose = "verify"
	// PurposeSignIn signs in the user who holds the number.
	PurposeSignIn Purpose = "sign_in"
	// PurposePasswordReset lets the user who holds the number set a new
	// password.
	PurposePasswordReset Purpose = "password_reset"
)

// The kinds of the codes the plugin issues, one per purpose, so that a code
// sent for one can't be used for another. The subject of each is a user id.
const (
	codeVerify models.CodeKind = PluginName + ".verify"
	codeSignIn models.CodeKind = PluginName + ".sign_in"
	codeReset  models.CodeKind = PluginName + ".password_reset"
)

// valueConfirmed is the note the plugin's flows leave in the operation's
// Values for its data handlers: the number this write may set, because a
// code sent to it was confirmed or the application vouches for it.
const valueConfirmed = PluginName + ".confirmed"

// Codes of the errors the plugin returns for its own rejections.
const (
	// ErrorCodeInvalidPhoneNumber is the code of the validation error (400)
	// for a number that is not a string or not in E.164 form.
	ErrorCodeInvalidPhoneNumber = "phone_number_invalid_input"
	// ErrorCodeInvalidCode is the code of the unauthorized error (401) for
	// a code that is not accepted: wrong, expired, used, out of attempts,
	// or for a number nobody holds.
	ErrorCodeInvalidCode = "invalid_phone_code"
	// ErrorCodePhoneNumberTaken is the code of the conflict error (409) for
	// a number another user holds.
	ErrorCodePhoneNumberTaken = "phone_number_taken"
	// ErrorCodeUnconfirmedChange is the code of the forbidden error (403)
	// for a write that sets a number without going through the plugin: a
	// Store.UpdateUser or Store.CreateUser that names phone_number.
	ErrorCodeUnconfirmedChange = "phone_number_unconfirmed_change"
)

// Reasons a SendResult gives for a code that was not sent.
const (
	ReasonNoAccount   = "no_account"   // nobody holds the number
	ReasonNumberTaken = "number_taken" // another user holds the number
	ReasonAlreadySet  = "already_set"  // the user holds the number already
	ReasonSendFailed  = "send_failed"  // the SMS sender refused the message
)

// Options configures the plugin. The zero value is usable. An SMS sender in
// BootConfig.SMS is required: the plugin sends nothing itself.
type Options struct {
	// CodeLength is the number of digits of a code. Zero means 6.
	CodeLength int
	// CodeTTL is how long a code works. Zero means 5 minutes.
	CodeTTL time.Duration
	// MaxAttempts is how many times one code may be tried. Zero means 5.
	MaxAttempts int

	// SendLimit bounds the codes sent per number, for every purpose and
	// from any caller. Zero means 3 per 15 minutes.
	SendLimit core.Limit

	// WaitForSend chooses how a code is handed to the SMS sender.
	//
	// false (the default): the request returns once the message is queued
	// (SMS.SendAsync). A failed send is logged. The provider's speed then
	// does not show in the response time, which would tell a number with an
	// account from one without.
	//
	// true: the request waits for the sender (SMS.Send), and a failed send
	// revokes the code. Choose it when the sender only enqueues.
	WaitForSend bool

	// PasswordReset turns on resetting a password with a code sent to the
	// user's number, and mounts its two routes. It is off by default: a
	// text message is a weaker proof than a link in a mailbox, since a
	// number can be moved to another SIM.
	PasswordReset bool
}

// Plugin is the phone number plugin. It contributes the phone_number column
// to users, registers handlers that keep the column to confirmed numbers,
// adds its routes, and declares its hook points and rate-limit rules.
type Plugin struct {
	opts        Options
	passwords   *emailpassword.Plugin
	authContext *core.AuthContext
	log         telemetry.Logger

	verify func(hctx *core.HookContext, in verifyInput) (*models.User, error)
	signIn func(hctx *core.HookContext, in signInInput) (*core.SignInResult, error)
	reset  func(hctx *core.HookContext, in resetInput) (*models.User, error)
}

// New returns the plugin configured with opts. passwords is the
// email/password plugin of the same application, the one passed to Prepare.
// Values left at zero take their defaults. A missing plugin and values that
// can't work are reported by Init, as a configuration error from Boot.
func New(passwords *emailpassword.Plugin, opts Options) *Plugin {
	if opts.CodeLength == 0 {
		opts.CodeLength = core.DefaultCodeLength
	}
	if opts.CodeTTL == 0 {
		opts.CodeTTL = core.DefaultCodeTTL
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = core.DefaultCodeMaxAttempts
	}
	if opts.SendLimit == (core.Limit{}) {
		opts.SendLimit = core.Limit{Max: 3, Window: 15 * time.Minute}
	}
	return &Plugin{opts: opts, passwords: passwords}
}

// Meta implements [core.Plugin]. The plugin depends on the email/password
// plugin, so that plugin is initialized first. It has no mount path.
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
//   - the phone_number column on users (Column), nullable so that a user
//     without a number holds no value and a version of the application
//     without the plugin can still insert users;
//   - the auth.phoneNumber.* points around sending a code, adding a number
//     and, with Options.PasswordReset, resetting a password;
//   - a rate-limit rule per client address on each flow, and one per number
//     on sending;
//   - the permission PermissionPhoneChange, and the admin permissions
//     PermissionSetPhone and PermissionAddPhone.
//
// It declares no table and no token kind: codes are rows of core's
// verification_codes table, issued by the code manager.
func (p *Plugin) Declare(ic *core.PluginInitContext) error {
	for _, def := range []core.PermissionDef{
		{Name: PermissionPhoneChange, Kind: core.PermissionSelf, Description: "Add or change the phone number of your account"},
		{Name: PermissionSetPhone, Kind: core.PermissionAdmin, Description: "Set the phone number of any account without a code"},
		{Name: PermissionAddPhone, Kind: core.PermissionAdmin, Description: "Add a confirmed phone number to any account"},
	} {
		if err := ic.Permissions.Declare(def); err != nil {
			return err
		}
	}
	if err := ic.Schemas.ExtendColumn(Column.Contribution(schema.Column{
		Type: schema.ColTypeString, Length: columnLength, Nullable: true, Unique: true, Public: true,
	})); err != nil {
		return err
	}

	points := []core.HookPointDef{
		{Point: HookSendBefore, Phase: core.BeforeHookPhase},
		{Point: HookSendAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookSendFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookVerifyBefore, Phase: core.BeforeHookPhase},
		{Point: HookVerifyAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookVerifyFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
	}
	// Per client address on the flows' before points, so they hold for
	// every transport. Per number on the send itself, so it holds for every
	// purpose; it counts requests for numbers nobody holds too, and so
	// answers the same for both.
	perAddress := core.Limit{Max: 10, Window: time.Minute}
	rules := []core.HookRateLimitRule{
		{Name: RuleSendAddress, Point: HookSendBefore, KeyFunc: sendByAddress(false), Limit: perAddress},
		{Name: RuleVerifyAddress, Point: HookVerifyBefore, KeyFunc: core.KeyByClientIP(), Limit: perAddress},
		{Name: RuleSendNumber, Point: HookSendBefore, KeyFunc: core.KeyByValues(HookValuePhoneNumber), Limit: p.opts.SendLimit},
	}
	if p.opts.PasswordReset {
		points = append(points,
			core.HookPointDef{Point: HookResetBefore, Phase: core.BeforeHookPhase},
			core.HookPointDef{Point: HookResetAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
			core.HookPointDef{Point: HookResetFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
		)
		rules = append(rules,
			core.HookRateLimitRule{Name: RuleResetRequestAddress, Point: HookSendBefore, KeyFunc: sendByAddress(true), Limit: perAddress},
			core.HookRateLimitRule{Name: RuleResetAddress, Point: HookResetBefore, KeyFunc: core.KeyByClientIP(), Limit: perAddress},
		)
	}
	for _, def := range points {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		if err := ic.RateLimits.DeclareHookRateLimitRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// Register implements [core.Plugin]. Two handlers keep the column to
// confirmed numbers, for every way of writing a user:
//   - data.user.beforeCreate: a row that carries a number is refused;
//   - data.user.beforeUpdate: an update that sets a number is refused,
//     unless it comes from one of the plugin's flows. One that removes the
//     number passes.
func (p *Plugin) Register(reg core.HookRegistry) error {
	if err := reg.OnBefore(hooks.HookUserBeforeCreate, p.onUserCreate, nil); err != nil {
		return err
	}
	return reg.OnBefore(hooks.HookUserBeforeUpdate, p.onUserUpdate, nil)
}

// Middlewares implements [core.Plugin]. The plugin has no middleware that
// runs on every route. The session read its send and verify routes need is
// attached to those two (see Routes).
func (p *Plugin) Middlewares() []core.Middleware {
	return nil
}

// Init implements [core.Plugin]. It checks the options and the SMS sender,
// keeps the AuthContext and wraps the flows with their hook points.
func (p *Plugin) Init(ac *core.AuthContext) error {
	const op = "phonenumber.Init"
	if p.passwords == nil {
		return errs.NewConfigurationError(op, "no email/password plugin was given to New; sign-in by password and password reset run through it", nil)
	}
	if ac.SMS == nil || !ac.SMS.Configured() {
		return errs.NewConfigurationError(op, "no SMS sender is configured; set BootConfig.SMS.Sender: the plugin does not send text messages itself", nil)
	}
	if ac.Codes == nil {
		return errs.NewConfigurationError(op, "AuthContext has no code manager", nil)
	}
	if p.opts.CodeLength < 4 || p.opts.CodeLength > 12 || p.opts.CodeTTL < 0 || p.opts.MaxAttempts < 1 {
		return errs.NewConfigurationError(op,
			fmt.Sprintf("code options are invalid: length %d (4 to 12), TTL %s, attempts %d", p.opts.CodeLength, p.opts.CodeTTL, p.opts.MaxAttempts), nil)
	}
	p.authContext = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.verify = core.WithLifecycle(ac.Dispatcher, HookVerifyBefore, HookVerifyAfter, HookVerifyFailed, p.verifyBody)
	p.signIn = core.WithLifecycle(ac.Dispatcher, hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed, p.signInBody)
	if p.opts.PasswordReset {
		p.reset = core.WithLifecycle(ac.Dispatcher, HookResetBefore, HookResetAfter, HookResetFailed, p.resetBody)
	}
	return nil
}

// Routes implements [core.Plugin]. The send and verify flows read the
// caller: for a signed-in user they add a number, for a visitor they sign
// in. The two reset routes are added only with Options.PasswordReset.
func (p *Plugin) Routes() []core.Route {
	routes := []core.Route{
		{Method: http.MethodPost, Path: PathSendOTP, Handler: p.handleSend},
		{Method: http.MethodPost, Path: PathVerify, Handler: p.handleVerify},
		{Method: http.MethodPost, Path: PathSignIn, Handler: p.handleSignIn},
	}
	if p.opts.PasswordReset {
		routes = append(routes,
			core.Route{Method: http.MethodPost, Path: PathResetRequest, Handler: p.handleResetRequest},
			core.Route{Method: http.MethodPost, Path: PathReset, Handler: p.handleReset},
		)
	}
	return routes
}

// Parse returns number in the form it is stored and compared in, E.164: a
// "+", a country code and the rest, 8 to 15 digits in all and no leading
// zero, such as "+14155550123". Surrounding space is dropped. Nothing else
// is: a national number ("0911 234567") or one with separators is refused,
// because turning it into E.164 needs the caller's country. The error is a
// validation error with ErrorCodeInvalidPhoneNumber.
func Parse(number string) (string, error) {
	number = strings.TrimSpace(number)
	digits, plus := strings.CutPrefix(number, "+")
	valid := plus && len(digits) >= 8 && len(digits) <= 15 && digits[0] != '0'
	for i := 0; valid && i < len(digits); i++ {
		valid = digits[i] >= '0' && digits[i] <= '9'
	}
	if !valid {
		return "", errInvalidNumber(`phone number must be in international form, such as "+14155550123"`)
	}
	return number, nil
}

func errInvalidNumber(message string) error {
	return errs.NewInvalidInputError("phonenumber.Parse", HookValuePhoneNumber, message, nil)
}

// errInvalidCode is the one answer to every code the plugin refuses, and to
// a number nobody holds, so that the response does not tell them apart.
func errInvalidCode(op string) error {
	return errs.NewUnauthorized(op, ErrorCodeInvalidCode, "invalid or expired code")
}

func errNumberTaken(op string) error {
	const message = "this phone number is already in use"
	return &errs.DomainError{
		Category: errs.CategoryConflict, Op: op, Code: ErrorCodePhoneNumberTaken,
		PublicMessage: message, InternalMessage: op + ": " + message,
	}
}

func errUnconfirmedChange() error {
	const op, message = "phonenumber.write", "a phone number is set by confirming a code sent to it"
	return &errs.DomainError{
		Category: errs.CategoryForbidden, Op: op, Code: ErrorCodeUnconfirmedChange,
		PublicMessage: message, InternalMessage: op + ": " + message,
	}
}

// onUserCreate handles data.user.beforeCreate. A user is created without a
// number: one on the row is refused, since nothing confirmed it. A user gets
// a number afterwards, by a code or through SetPhoneNumber.
func (p *Plugin) onUserCreate(_ *core.HookContext, row behemoth.M) (behemoth.M, error) {
	if raw, ok := row[Column.Name]; ok && raw != nil && raw != "" {
		return nil, errUnconfirmedChange()
	}
	delete(row, Column.Name) // no value, not an empty string: the column is unique
	return row, nil
}

// onUserUpdate handles data.user.beforeUpdate. An update that does not name
// the number is left alone, and one that empties it removes it. One that
// sets a number passes only when one of the plugin's flows left that number
// in Values (write); it is then checked against the other users. Two writes
// racing for one number can both pass that check, and the column's unique
// constraint refuses the second.
func (p *Plugin) onUserUpdate(hctx *core.HookContext, changes behemoth.M) (behemoth.M, error) {
	raw, changing := changes[Column.Name]
	if !changing {
		return nil, nil
	}
	if raw == nil || raw == "" {
		changes[Column.Name] = nil
		return changes, nil
	}
	text, ok := raw.(string)
	if !ok {
		return nil, errInvalidNumber("phone_number must be a string")
	}
	number, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if confirmed, _ := hctx.Values[valueConfirmed].(string); confirmed != number {
		return nil, errUnconfirmedChange()
	}
	id, _ := hctx.Values[hooks.HookValueUserID].(string)
	holder, err := hctx.Tx.FindUserBy(hctx.Ctx, Column.Name, number)
	switch {
	case err == nil:
		if holder.ID != id {
			return nil, errNumberTaken("phonenumber.write")
		}
	case !errs.IsNotFound(err):
		return nil, err
	}
	changes[Column.Name] = number
	return changes, nil
}

// write sets number on the user with userID, or removes the user's number
// when number is empty. It is the one place a number is written: it leaves
// the number in the Values the update's data handlers start from, which is
// what onUserUpdate lets through.
func (p *Plugin) write(ctx context.Context, userID, number string) (*models.User, error) {
	ctx = core.BeginOperation(ctx)
	var value any
	if number != "" {
		core.HookValuesFrom(ctx)[valueConfirmed] = number
		value = number
	}
	return p.authContext.Store.UpdateUser(ctx, userID, behemoth.M{Column.Name: value})
}

// operation builds the HookContext one flow call runs with, as the
// email/password plugin's does, and publishes number for rate-limit rules.
func (p *Plugin) operation(ctx context.Context, op, number string) (*core.HookContext, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	hctx := &core.HookContext{
		Ctx:    ctx,
		Auth:   p.authContext,
		Values: core.NestedHookValues(ctx),
	}
	delete(hctx.Values, hooks.HookValueEmail) // an enclosing operation's, not this one's
	hctx.Values[HookValuePhoneNumber] = number
	return hctx, nil
}

// findHolder returns the user who holds number, or a NotFound error.
func (p *Plugin) findHolder(ctx context.Context, number string) (*models.User, error) {
	return p.authContext.Store.FindUserBy(ctx, Column.Name, number)
}

// SendRequest is the input of SendCode.
type SendRequest struct {
	// PhoneNumber is the number to send the code to, in E.164 form.
	PhoneNumber string
	// Metadata is passed to the SMS sender as it is, in
	// SMSMessage.Metadata: a locale. The plugin does not read or store it.
	Metadata behemoth.M

	// userID is the user who is adding the number: the one the caller acts
	// for, set by SendCode. Empty means the code is for signing in with a
	// number somebody already holds.
	userID string
}

// SendResult is what SendCode and RequestPasswordReset return, and what
// handlers on auth.phoneNumber.afterSend receive. It does not hold the code.
type SendResult struct {
	// Sent says whether a code was handed to the SMS sender. When it is
	// false, Reason says why (the Reason constants) and the other fields
	// are empty. A route does not pass either on: it answers the same for
	// every well-formed request.
	Sent   bool
	Reason string

	Purpose     Purpose
	UserID      string
	PhoneNumber string
	ExpiresAt   time.Time
}

// AuditSubject implements [core.AuditSubject]: a code is about the user it
// was issued for.
func (r *SendResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.UserID == "" {
		return "", ""
	}
	return models.UserTable, r.UserID
}

// SendCode sends a one-time code to a phone number.
//
// For a caller that acts for a user, it is the first step of adding the
// number to that user, who may hold another number already: the code is
// confirmed with Verify, and only then is the number written. The caller
// needs PermissionPhoneChange (Access.OptionalUser). For an anonymous caller
// the code signs in the user who holds the number. A caller whose
// credential failed gets the reason as a session error, so a user whose
// session has ended is not taken for a visitor who wants to sign in.
//
// A number that is not in E.164 form is a validation error, and too many
// codes for one number a rate-limit error. Every other outcome is a result
// and no error: Sent says whether a code went out, and Reason why not (no
// user holds the number, another user does, the user has it already, the
// sender failed). A caller in code can act on the reason. A client is not
// told, which is why the route answers the same either way.
//
// A new code replaces the user's earlier one for the same purpose. It fires
// auth.phoneNumber.beforeSend, and .afterSend or .sendFailed. It is the flow
// behind POST /phone-number/send-otp.
func (p *Plugin) SendCode(ctx context.Context, req SendRequest) (*SendResult, error) {
	const op = "phonenumber.SendCode"
	if p.authContext == nil {
		return nil, errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	userID, forUser, err := p.authContext.Access.OptionalUser(ctx, PermissionPhoneChange)
	if err != nil {
		return nil, err
	}
	purpose := PurposeSignIn
	req.userID = ""
	if forUser {
		purpose, req.userID = PurposeVerify, userID
	}
	return p.send(ctx, op, purpose, req)
}

// send is the flow behind SendCode and RequestPasswordReset. It fires its
// points itself and not through WithLifecycle: the after point is for a
// code that went out, and a request that sent none still returns a result.
func (p *Plugin) send(ctx context.Context, op string, purpose Purpose, req SendRequest) (*SendResult, error) {
	number, err := Parse(req.PhoneNumber)
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, number)
	if err != nil {
		return nil, err
	}
	hctx = core.AsOperation(hctx)
	ac := p.authContext
	dispatcher := ac.Dispatcher

	notSent := func(reason, code string, cause error, userID string) (*SendResult, error) {
		failure := core.FailureReason{Code: code, Cause: cause, Metadata: behemoth.M{HookValuePhoneNumber: number, keyPurpose: string(purpose)}}
		if userID != "" {
			failure.SubjectType, failure.SubjectID = models.UserTable, userID
		}
		if err := dispatcher.Fail(hctx, HookSendFailed, failure); err != nil {
			return nil, err
		}
		return &SendResult{Reason: reason}, nil
	}

	payload := behemoth.M{HookValuePhoneNumber: number, keyPurpose: string(purpose)}
	hctx.Values[keyPurpose] = string(purpose) // the rules per address count a reset's sends apart
	if req.userID != "" {
		payload[hooks.HookValueUserID] = req.userID
	}
	if _, err := dispatcher.RunBefore(hctx, HookSendBefore, payload); err != nil {
		return nil, core.FailIfRejected(dispatcher, hctx, HookSendFailed, err, core.FailureReason{})
	}

	// Who the code is for. Its subject is always a user id, so that the
	// code goes when the user is deleted.
	var user *models.User
	var kind models.CodeKind
	var message core.SMSKind
	holder, err := p.findHolder(hctx.Ctx, number)
	if err != nil && !errs.IsNotFound(err) {
		return nil, err
	}
	switch purpose {
	case PurposeVerify:
		kind, message = codeVerify, core.SMSPhoneVerification
		if user, err = ac.Store.FindUserByID(hctx.Ctx, req.userID); err != nil {
			return nil, err
		}
		if holder != nil && holder.ID == user.ID {
			return notSent(ReasonAlreadySet, "already_set", nil, user.ID)
		}
		if holder != nil {
			return notSent(ReasonNumberTaken, "number_taken", nil, user.ID)
		}
	default:
		kind, message = codeSignIn, core.SMSSignIn
		if purpose == PurposePasswordReset {
			kind, message = codeReset, core.SMSPasswordReset
		}
		if holder == nil {
			return notSent(ReasonNoAccount, "no_account", nil, "")
		}
		user = holder
	}

	code, issued, err := ac.Codes.Issue(hctx.Ctx, kind, user.ID, core.CodeOptions{
		Length: p.opts.CodeLength, TTL: p.opts.CodeTTL, MaxAttempts: p.opts.MaxAttempts,
		Metadata: behemoth.M{HookValuePhoneNumber: number},
	})
	if err != nil {
		return nil, err
	}

	sms := core.SMSMessage{Kind: message, To: number, Code: code, ExpiresAt: issued.ExpiresAt, User: user, Metadata: req.Metadata}
	if p.opts.WaitForSend {
		err = ac.SMS.Send(hctx.Ctx, sms)
	} else {
		err = ac.SMS.SendAsync(hctx.Ctx, sms)
	}
	if err != nil {
		// Nobody received the code, so it should not stay usable. The
		// result does not carry the error, so this line is its report.
		p.log.Error(hctx.Ctx, "the code was not handed to the SMS sender", telemetry.ErrorFields(err, behemoth.M{keyPurpose: string(purpose)}))
		if revokeErr := ac.Codes.Revoke(hctx.Ctx, kind, user.ID); revokeErr != nil {
			p.log.Warn(hctx.Ctx, "the unsent code was not revoked", telemetry.ErrorFields(revokeErr))
		}
		return notSent(ReasonSendFailed, "send_failed", err, user.ID)
	}

	result := &SendResult{Sent: true, Purpose: purpose, UserID: user.ID, PhoneNumber: number, ExpiresAt: issued.ExpiresAt}
	if err := dispatcher.RunAfter(hctx, HookSendAfter, result); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyRequest is the input of Verify.
type VerifyRequest struct {
	PhoneNumber string
	Code        string
}

// VerifyResult is what Verify returns. One of its two fields is set.
type VerifyResult struct {
	// User is the user who now holds the number, when a number was added.
	User *models.User
	// SignIn is the sign-in, when the code signed a user in.
	SignIn *core.SignInResult
}

// Verify confirms the code SendCode sent to req.PhoneNumber. For a caller
// that acts for a user it adds the number to that user, as AddNumber does,
// and needs PermissionPhoneChange (Access.OptionalUser); for an anonymous
// caller it is SignInWithCode. A caller whose credential failed gets the
// reason. It exists so that the verify route calls one flow.
func (p *Plugin) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	const op = "phonenumber.Verify"
	if p.authContext == nil {
		return nil, errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	userID, forUser, err := p.authContext.Access.OptionalUser(ctx, PermissionPhoneChange)
	if err != nil {
		return nil, err
	}
	if forUser {
		user, err := p.addNumber(ctx, userID, req.PhoneNumber, req.Code)
		if err != nil {
			return nil, err
		}
		return &VerifyResult{User: user}, nil
	}
	result, err := p.SignInWithCode(ctx, req.PhoneNumber, req.Code)
	if err != nil {
		return nil, err
	}
	return &VerifyResult{SignIn: result}, nil
}

// verifyInput is the input of the wrapped flow behind AddNumber. Its payload
// on auth.phoneNumber.beforeVerify is "phone_number" and "userID". The code
// is not in it and nothing is read back.
type verifyInput struct {
	userID, number, code string
}

func (v *verifyInput) ToMap() (map[string]any, error) {
	return map[string]any{HookValuePhoneNumber: v.number, hooks.HookValueUserID: v.userID}, nil
}

func (v *verifyInput) FromMap(map[string]any) error { return nil }

// AddNumber gives the user with userID the phone number, once code is the
// one SendCode sent to it for that user. A number the user held before is
// replaced. It returns the stored user.
//
// A code that is wrong, expired, used or out of attempts, and a code that
// was sent to another number, get one error with ErrorCodeInvalidCode. A
// number that another user took in the meantime is a conflict with
// ErrorCodePhoneNumberTaken. Each attempt costs the code one of its tries.
//
// It fires auth.phoneNumber.beforeVerify, .afterVerify and .verifyFailed.
//
// It is an admin operation: the caller needs PermissionAddPhone
// (Access.RequireAdmin), which only a system caller holds today. A user
// adds a number to their own account with Verify.
func (p *Plugin) AddNumber(ctx context.Context, userID, phoneNumber, code string) (*models.User, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError("phonenumber.AddNumber", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	if err := p.authContext.Access.RequireAdmin(ctx, PermissionAddPhone); err != nil {
		return nil, err
	}
	return p.addNumber(ctx, userID, phoneNumber, code)
}

// addNumber is AddNumber, and what Verify runs for the user its caller acts
// for.
func (p *Plugin) addNumber(ctx context.Context, userID, phoneNumber, code string) (*models.User, error) {
	const op = "phonenumber.AddNumber"
	number, err := Parse(phoneNumber)
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, number)
	if err != nil {
		return nil, err
	}
	hctx.Values[hooks.HookValueUserID] = userID
	return p.verify(hctx, verifyInput{userID: userID, number: number, code: code})
}

func (p *Plugin) verifyBody(hctx *core.HookContext, in verifyInput) (*models.User, error) {
	const op = "phonenumber.AddNumber"
	ac := hctx.Auth
	refuse := func(code string, cause error, answer error) (*models.User, error) {
		if err := ac.Dispatcher.Fail(hctx, HookVerifyFailed, core.FailureReason{
			Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: in.userID,
		}); err != nil {
			return nil, err
		}
		return nil, answer
	}

	consumed, err := ac.Codes.Consume(hctx.Ctx, codeVerify, in.userID, in.code)
	if err != nil {
		if !errs.IsCodeRejection(err) {
			return nil, err
		}
		return refuse("invalid_code", err, errInvalidCode(op))
	}
	// The code proves control of the number it was sent to, and of no
	// other.
	if sentTo, _ := consumed.Metadata[HookValuePhoneNumber].(string); sentTo != in.number {
		return refuse("number_mismatch", nil, errInvalidCode(op))
	}

	user, err := p.write(hctx.Ctx, in.userID, in.number)
	if err != nil {
		if errs.IsCode(err, ErrorCodePhoneNumberTaken) || errs.IsDuplicateKey(err) {
			return refuse("number_taken", err, errNumberTaken(op))
		}
		return nil, core.FailIfRejected(ac.Dispatcher, hctx, HookVerifyFailed, err,
			core.FailureReason{SubjectType: models.UserTable, SubjectID: in.userID})
	}
	return user, nil
}

// signInInput is the input of the wrapped flow behind SignInWithCode. Its
// payload on auth.signIn.before is "method" and "phone_number". The code is
// not in it, and nothing is read back: a handler can stop the sign-in, but
// it can't point it at another number.
type signInInput struct {
	number, code string
}

func (v *signInInput) ToMap() (map[string]any, error) {
	return map[string]any{keyMethod: PluginName, HookValuePhoneNumber: v.number}, nil
}

func (v *signInInput) FromMap(map[string]any) error { return nil }

// SignInWithCode signs in the user who holds phoneNumber, once code is the
// one SendCode sent to it. The session is pending instead of active when a
// handler on auth.signIn.credentialsVerified asked for a second factor.
//
// A number nobody holds and a code that is wrong, expired, used or out of
// attempts get one error with ErrorCodeInvalidCode. It fires core's
// auth.signIn.before, .after and .failed, like every sign-in; the result's
// Method is "phonenumber". The raw session token is in the result and is the
// caller's to deliver.
func (p *Plugin) SignInWithCode(ctx context.Context, phoneNumber, code string) (*core.SignInResult, error) {
	number, err := Parse(phoneNumber)
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, "phonenumber.SignInWithCode", number)
	if err != nil {
		return nil, err
	}
	hctx.Values[hooks.HookValueMethod] = PluginName // core's per-address limit counts each method apart
	return p.signIn(hctx, signInInput{number: number, code: code})
}

func (p *Plugin) signInBody(hctx *core.HookContext, in signInInput) (*core.SignInResult, error) {
	const op = "phonenumber.SignInWithCode"
	ac := hctx.Auth
	dispatcher := ac.Dispatcher

	user, err := p.findHolder(hctx.Ctx, in.number)
	if err != nil {
		if !errs.IsNotFound(err) {
			return nil, err
		}
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, core.FailureReason{
			Code: "user_not_found", Metadata: behemoth.M{HookValuePhoneNumber: in.number},
		}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidCode(op)
	}
	rejected := func(code string, cause error) core.FailureReason {
		return core.FailureReason{Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: user.ID}
	}

	if _, err := ac.Codes.Consume(hctx.Ctx, codeSignIn, user.ID, in.code); err != nil {
		if !errs.IsCodeRejection(err) {
			return nil, err
		}
		if failErr := dispatcher.Fail(hctx, hooks.HookSignInFailed, rejected("invalid_code", err)); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidCode(op)
	}

	// The seam a 2FA plugin hooks, as in the email/password sign-in.
	checkpoint, err := dispatcher.RunBefore(hctx, hooks.HookSignInCredentialsVerified,
		behemoth.M{hooks.HookValueUserID: user.ID})
	if err != nil {
		return nil, core.FailIfRejected(dispatcher, hctx, hooks.HookSignInFailed, err,
			core.FailureReason{SubjectType: models.UserTable, SubjectID: user.ID})
	}
	state := models.SessionActive
	if requireStepUp, _ := checkpoint["requireStepUp"].(bool); requireStepUp {
		state = models.SessionPending
	}

	session, rawToken, err := ac.SessionManager.Create(hctx.Ctx, user.ID, core.SessionMeta{State: state})
	if err != nil {
		return nil, err
	}
	return &core.SignInResult{User: user, Session: session, RawToken: rawToken, Method: PluginName}, nil
}

// Credentials is the input of SignIn: a phone number and a password.
type Credentials struct {
	PhoneNumber string
	Password    string

	// Extra holds input the flow does not read but a handler on
	// auth.signIn.before may, such as a captcha token. The route fills it
	// with the request fields other than the number and the password.
	Extra behemoth.M
}

// FromMap sets the credentials from a request body. "phone_number" and
// "password" fill the fields and every other key goes to Extra. A missing or
// null value is left empty, for sign-in to refuse; one that is not a string
// is a validation error.
func (c *Credentials) FromMap(data map[string]any) error {
	number, err := stringField("phonenumber.SignIn", data, HookValuePhoneNumber)
	if err != nil {
		return err
	}
	password, err := stringField("phonenumber.SignIn", data, keyPassword)
	if err != nil {
		return err
	}
	extra := behemoth.M{}
	maps.Copy(extra, data)
	delete(extra, HookValuePhoneNumber)
	delete(extra, keyPassword)
	if len(extra) == 0 {
		extra = nil
	}
	c.PhoneNumber, c.Password, c.Extra = number, password, extra
	return nil
}

// stringField reads a string from a request body. A missing or null key is
// empty; a value of another type is a validation error named after the key.
func stringField(op string, data map[string]any, key string) (string, error) {
	switch v := data[key].(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		return "", errs.NewInvalidInputError(op, key, key+" must be a string", nil)
	}
}

// SignIn verifies a phone number and a password and creates a session for
// the user who holds the number. It is the email/password plugin's sign-in
// with another lookup (emailpassword.Plugin.SignInWith), as the username
// plugin's is: the same password check, second-factor checkpoint, session
// and auth.signIn.* points, and one typed error for a number nobody holds, a
// user without a password and a wrong password, with the code
// emailpassword.ErrorCodeInvalidCredentials. The result's Method is
// "phonenumber".
//
// Unlike SendCode it does not refuse a number that is not in E.164 form: it
// finds no user for it and answers like a wrong password. It is the flow
// behind POST /sign-in/phone-number.
func (p *Plugin) SignIn(ctx context.Context, creds Credentials) (*core.SignInResult, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError("phonenumber.SignIn", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	return p.passwords.SignInWith(ctx, emailpassword.IdentifierCredentials{
		Key:      HookValuePhoneNumber,
		Value:    strings.TrimSpace(creds.PhoneNumber),
		Password: creds.Password,
		Extra:    creds.Extra,
		Method:   PluginName,
		Find: func(ctx context.Context, s *store.Store, value string) (*models.User, error) {
			number, err := Parse(value)
			if err != nil {
				return nil, errs.NewNotFound("phonenumber.SignIn", models.UserTable, err)
			}
			return s.FindUserBy(ctx, Column.Name, number)
		},
	})
}

// ResetRequest is the input of RequestPasswordReset.
type ResetRequest struct {
	PhoneNumber string
	// Metadata is passed to the SMS sender, as in SendRequest.
	Metadata behemoth.M
}

// RequestPasswordReset sends a code to the user who holds the number, with
// which ResetPassword sets a new password. Its errors and its result are
// SendCode's: a number nobody holds is a result with Sent false, not an
// error. It needs Options.PasswordReset and returns a configuration error
// without it. It is the flow behind POST
// /phone-number/request-password-reset.
func (p *Plugin) RequestPasswordReset(ctx context.Context, req ResetRequest) (*SendResult, error) {
	const op = "phonenumber.RequestPasswordReset"
	if !p.opts.PasswordReset {
		return nil, errResetOff(op)
	}
	return p.send(ctx, op, PurposePasswordReset, SendRequest{PhoneNumber: req.PhoneNumber, Metadata: req.Metadata})
}

func errResetOff(op string) error {
	return errs.NewConfigurationError(op, "password reset by phone is off; set Options.PasswordReset", nil)
}

// resetInput is the input of the wrapped flow behind ResetPassword. Its
// payload on auth.phoneNumber.beforePasswordReset is "phone_number" and
// "password". The code is not in it and nothing is read back.
type resetInput struct {
	number, code, password string
}

func (v *resetInput) ToMap() (map[string]any, error) {
	return map[string]any{HookValuePhoneNumber: v.number, keyPassword: v.password}, nil
}

func (v *resetInput) FromMap(map[string]any) error { return nil }

// ResetPassword sets newPassword on the user who holds phoneNumber, once
// code is the one RequestPasswordReset sent to it. It returns the user.
//
// The password is the email/password plugin's to set
// (emailpassword.Plugin.SetPassword): its rules apply, every session of the
// user ends and none is created, and the user is told by mail when a mail
// sender is configured. The password is checked first, so one that is
// refused is a validation error and costs the code no attempt. A number
// nobody holds and a code that is wrong, expired, used or out of attempts
// get one error with ErrorCodeInvalidCode.
//
// It fires auth.phoneNumber.beforePasswordReset, .afterPasswordReset and
// .passwordResetFailed. It is the flow behind POST
// /phone-number/reset-password.
func (p *Plugin) ResetPassword(ctx context.Context, phoneNumber, code, newPassword string) (*models.User, error) {
	const op = "phonenumber.ResetPassword"
	if !p.opts.PasswordReset {
		return nil, errResetOff(op)
	}
	number, err := Parse(phoneNumber)
	if err != nil {
		return nil, err
	}
	hctx, err := p.operation(ctx, op, number)
	if err != nil {
		return nil, err
	}
	if err := p.passwords.ValidatePassword(newPassword); err != nil {
		return nil, err
	}
	return p.reset(hctx, resetInput{number: number, code: code, password: newPassword})
}

func (p *Plugin) resetBody(hctx *core.HookContext, in resetInput) (*models.User, error) {
	const op = "phonenumber.ResetPassword"
	ac := hctx.Auth
	user, err := p.findHolder(hctx.Ctx, in.number)
	if err != nil {
		if !errs.IsNotFound(err) {
			return nil, err
		}
		if failErr := ac.Dispatcher.Fail(hctx, HookResetFailed, core.FailureReason{
			Code: "no_account", Metadata: behemoth.M{HookValuePhoneNumber: in.number},
		}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidCode(op)
	}
	if _, err := ac.Codes.Consume(hctx.Ctx, codeReset, user.ID, in.code); err != nil {
		if !errs.IsCodeRejection(err) {
			return nil, err
		}
		if failErr := ac.Dispatcher.Fail(hctx, HookResetFailed, core.FailureReason{
			Code: "invalid_code", Cause: err, SubjectType: models.UserTable, SubjectID: user.ID,
		}); failErr != nil {
			return nil, failErr
		}
		return nil, errInvalidCode(op)
	}
	// The code is spent from here on. The password passed the rules before
	// the flow began, so what can still fail is the write itself.
	// The code is the proof, so the password plugin's admin check does not
	// apply: the caller is anonymous, and stays the caller of what follows.
	return p.passwords.SetPasswordUnchecked(hctx.Ctx, user.ID, in.password)
}

// SetPhoneNumber gives the user with userID the phone number without a
// code, or removes the user's number when phoneNumber is empty, and returns
// the stored user. It is for the application's own code, which vouches for
// the number: an admin screen, an import of users whose numbers were
// confirmed elsewhere. A number that is not in E.164 form is a validation
// error, and one another user holds a conflict with
// ErrorCodePhoneNumberTaken.
//
// It is an admin operation: the caller needs PermissionSetPhone
// (Access.RequireAdmin), which only a system caller holds today. It fires no
// points of the plugin.
func (p *Plugin) SetPhoneNumber(ctx context.Context, userID, phoneNumber string) (*models.User, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError("phonenumber.SetPhoneNumber", "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	if err := p.authContext.Access.RequireAdmin(ctx, PermissionSetPhone); err != nil {
		return nil, err
	}
	number := strings.TrimSpace(phoneNumber)
	if number != "" {
		var err error
		if number, err = Parse(number); err != nil {
			return nil, err
		}
	}
	return p.write(ctx, userID, number)
}

// body decodes a request body as a map.
func body(rctx *core.RequestContext, op string) (behemoth.M, error) {
	var data behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&data); err != nil {
		return nil, errs.NewValidationError(op, "request", err)
	}
	return data, nil
}

// metadataField reads the optional "metadata" object of a request body.
func metadataField(op string, data behemoth.M) (behemoth.M, error) {
	switch v := data[keyMetadata].(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return v, nil
	default:
		return nil, errs.NewInvalidInputError(op, keyMetadata, keyMetadata+" must be an object", nil)
	}
}

// handleSend answers every well-formed request the same: the flow's result
// says whether a code went out and why not, and none of it is passed on. A
// validation error and a rate limit are the flow's errors and are reported,
// since they do not depend on who holds the number.
func (p *Plugin) handleSend(rctx *core.RequestContext) error {
	const op = "phonenumber.SendCode"
	data, err := body(rctx, op)
	if err != nil {
		return err
	}
	number, err := stringField(op, data, HookValuePhoneNumber)
	if err != nil {
		return err
	}
	metadata, err := metadataField(op, data)
	if err != nil {
		return err
	}
	if _, err := p.SendCode(rctx.Ctx, SendRequest{PhoneNumber: number, Metadata: metadata}); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// handleVerify answers with the user for a caller who added a number, and
// the way every sign-in route does (core.WriteSignIn) for one who signed
// in.
func (p *Plugin) handleVerify(rctx *core.RequestContext) error {
	const op = "phonenumber.Verify"
	data, err := body(rctx, op)
	if err != nil {
		return err
	}
	number, err := stringField(op, data, HookValuePhoneNumber)
	if err != nil {
		return err
	}
	code, err := stringField(op, data, keyCode)
	if err != nil {
		return err
	}
	result, err := p.Verify(rctx.Ctx, VerifyRequest{PhoneNumber: number, Code: code})
	if err != nil {
		return err
	}
	if result.SignIn != nil {
		return core.WriteSignIn(rctx, result.SignIn, nil)
	}
	view, err := rctx.Auth.Public.Of(result.User)
	if err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{core.SignInUserKey: view})
}

// handleSignIn decodes the body, calls SignIn and answers with
// core.WriteSignIn. It returns the flow's error unchanged.
func (p *Plugin) handleSignIn(rctx *core.RequestContext) error {
	data, err := body(rctx, "phonenumber.SignIn")
	if err != nil {
		return err
	}
	var creds Credentials
	if err := creds.FromMap(data); err != nil {
		return err
	}
	result, err := p.SignIn(rctx.Ctx, creds)
	if err != nil {
		return err
	}
	return core.WriteSignIn(rctx, result, nil)
}

// handleResetRequest answers every well-formed request the same, like
// handleSend.
func (p *Plugin) handleResetRequest(rctx *core.RequestContext) error {
	const op = "phonenumber.RequestPasswordReset"
	data, err := body(rctx, op)
	if err != nil {
		return err
	}
	number, err := stringField(op, data, HookValuePhoneNumber)
	if err != nil {
		return err
	}
	metadata, err := metadataField(op, data)
	if err != nil {
		return err
	}
	if _, err := p.RequestPasswordReset(rctx.Ctx, ResetRequest{PhoneNumber: number, Metadata: metadata}); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "ok"})
}

// handleReset returns ResetPassword's error unchanged. It delivers no
// session token: a reset does not sign the user in.
func (p *Plugin) handleReset(rctx *core.RequestContext) error {
	const op = "phonenumber.ResetPassword"
	data, err := body(rctx, op)
	if err != nil {
		return err
	}
	number, err := stringField(op, data, HookValuePhoneNumber)
	if err != nil {
		return err
	}
	code, err := stringField(op, data, keyCode)
	if err != nil {
		return err
	}
	password, err := stringField(op, data, keyPassword)
	if err != nil {
		return err
	}
	if _, err := p.ResetPassword(rctx.Ctx, number, code, password); err != nil {
		return err
	}
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "password_reset"})
}

var _ core.Plugin = (*Plugin)(nil)
