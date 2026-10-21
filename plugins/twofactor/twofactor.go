// Package twofactor is the two-factor plugin: a user turns on a second
// factor, and a sign-in of that user then waits for it, whichever plugin
// checked the first factor. The methods are a code from an authenticator app
// (TOTP), and a code sent by email or by text message. A user gets recovery
// codes with the first method.
//
// It builds on core's pending sessions: a sign-in that needs a second factor
// creates a session that authenticates nobody until the second factor passes
// and the session is promoted (core.SessionManager.Promote).
//
// Experimental: setting methods up, turning them off, and replacing the
// recovery codes work. A sign-in does not ask for the second factor yet.
package twofactor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
)

// PluginName is the name the plugin registers under (PluginMeta.Name). It
// owns the plugin's tables, hook points, rate-limit rules, and permissions.
const PluginName = "twofactor"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// Method is a second factor a user turns on. Each method's name is the
// factor a session records when it passes the method (core.FactorTOTP and
// the others).
type Method string

const (
	MethodTOTP  Method = core.FactorTOTP  // a code from an authenticator app
	MethodEmail Method = core.FactorEmail // a code sent by email
	MethodSMS   Method = core.FactorSMS   // a code sent by text message
)

// parseMethod returns the method named s, or a validation error.
func parseMethod(op, s string) (Method, error) {
	switch m := Method(s); m {
	case MethodTOTP, MethodEmail, MethodSMS:
		return m, nil
	}
	return "", errs.NewInvalidInputError(op, keyMethod, "method must be one of totp, email, or sms", nil)
}

// Purpose says what a sent code is for. It is the "purpose" of the
// auth.twoFactor.beforeSend payload and of a SendResult.
type Purpose string

// PurposeSetup is a code that confirms an address or a number a user sets
// up as a method.
const PurposeSetup Purpose = "setup"

// codeKind is the kind of the codes sent for purpose by method, such as
// "twofactor.setup_email": a kind per purpose and channel keeps a setup code
// from serving another purpose.
func codeKind(purpose Purpose, method Method) models.CodeKind {
	return models.CodeKind(PluginName + "." + string(purpose) + "_" + string(method))
}

// The points the plugin declares and fires.
const (
	// HookEnableBefore runs before a method is turned on, on "userID" and
	// "method". Veto only.
	HookEnableBefore core.HookPoint = "auth.twoFactor.beforeEnable"
	// HookEnableAfter runs once the method is on, with an *EnableResult.
	HookEnableAfter core.HookPoint = "auth.twoFactor.afterEnable"
	// HookEnableFailed fires for a confirmation that was refused: codes
	// "invalid_code" and "rejected_by_hook".
	HookEnableFailed core.HookPoint = "auth.twoFactor.enableFailed"

	// HookDisableBefore runs before a method is turned off, on "userID",
	// "method", and "reason". Veto only.
	HookDisableBefore core.HookPoint = "auth.twoFactor.beforeDisable"
	// HookDisableAfter runs once the method is off, with a *DisableResult.
	HookDisableAfter core.HookPoint = "auth.twoFactor.afterDisable"
	// HookDisableFailed fires for a method that was not turned off: codes
	// "not_enabled" and "rejected_by_hook".
	HookDisableFailed core.HookPoint = "auth.twoFactor.disableFailed"

	// HookSendBefore runs before a code is sent by email or text message,
	// on "userID", "method", and "purpose". Veto only.
	HookSendBefore core.HookPoint = "auth.twoFactor.beforeSend"
	// HookSendAfter runs once the message is handed to the sender, with a
	// *SendResult, which holds no code.
	HookSendAfter core.HookPoint = "auth.twoFactor.afterSend"
	// HookSendFailed fires for a code that was not sent: codes
	// "send_failed" and "rejected_by_hook".
	HookSendFailed core.HookPoint = "auth.twoFactor.sendFailed"

	// HookRegenerateBefore runs before a user's recovery codes are
	// replaced, on "userID". Veto only.
	HookRegenerateBefore core.HookPoint = "auth.twoFactor.beforeRegenerate"
	// HookRegenerateAfter runs once they are replaced, with a
	// *RegenerateResult, which holds no code.
	HookRegenerateAfter core.HookPoint = "auth.twoFactor.afterRegenerate"
)

// The permissions the plugin declares.
const (
	// PermissionRead is the permission Status requires: reading the methods
	// of the caller's own account.
	PermissionRead core.Permission = "two_factor:read"
	// PermissionManage is the permission the setup flows require, with a
	// fresh session: turning methods on and off, and replacing the recovery
	// codes, on the caller's own account.
	PermissionManage core.Permission = "two_factor:manage"
)

// Names of the rate-limit rules the plugin declares. RuleSendUser counts the
// codes sent per user, for every purpose: each one is a message somebody
// pays for and somebody receives.
const (
	RuleSendUser      = "twofactor.send.user"
	RuleSendAddress   = "twofactor.send.address"
	RuleEnableAddress = "twofactor.enable.address"
)

// Keys of the hook payloads, the code metadata, and the request bodies.
const (
	keyMethod      = "method"
	keyPurpose     = "purpose"
	keyReason      = "reason"
	keyDestination = "destination"
)

// The reasons in the payload of auth.twoFactor.beforeDisable and in a
// DisableResult.
const (
	// ReasonUserDisabled is a method the user turned off (Disable).
	ReasonUserDisabled = "user_disabled"
)

// Codes of the errors the plugin returns for its own rejections.
const (
	// ErrorCodeInvalidCode is the code of the unauthorized error (401) for
	// a code that is not accepted: wrong, expired, used, or out of
	// attempts.
	ErrorCodeInvalidCode = "invalid_two_factor_code"
	// ErrorCodeMethodUnavailable is the code of the forbidden error (403)
	// for a method that Options.Methods does not offer.
	ErrorCodeMethodUnavailable = "two_factor_method_unavailable"
	// ErrorCodeNotEnabled is the code of the conflict error (409) for
	// turning off a method that is not on, and for replacing the recovery
	// codes of a user without a method.
	ErrorCodeNotEnabled = "two_factor_not_enabled"
)

// Defaults of Options, applied by New to the fields left at zero.
const (
	// DefaultRecoveryCodes is the number of codes in a set.
	DefaultRecoveryCodes = 10
	// maxRecoveryCodes bounds Options.RecoveryCodes.
	maxRecoveryCodes = 20
)

// Options configures the plugin. Every field left at zero takes its default,
// except Issuer, which TOTP requires. A sender in BootConfig.Mail is required
// for MethodEmail, and one in BootConfig.SMS for MethodSMS.
type Options struct {
	// Issuer is the name an authenticator app shows next to the account,
	// such as the application's name. It is required when Methods offers
	// MethodTOTP.
	Issuer string
	// Methods are the methods a user may turn on. Empty means TOTP only.
	Methods []Method

	// CodeLength, CodeTTL, and MaxAttempts shape the codes sent by email
	// and text message, as core.CodeOptions does. Zero means 6 digits, 5
	// minutes, and 5 attempts.
	CodeLength  int
	CodeTTL     time.Duration
	MaxAttempts int
	// SendLimit bounds the codes sent per user, for every purpose. Zero
	// means 3 per 15 minutes.
	SendLimit core.Limit
	// WaitForSend chooses how a code is handed to the sender. False, the
	// default, queues it (SendAsync) and logs a failed send. True waits
	// (Send), and a failed send revokes the code and is returned.
	WaitForSend bool

	// RecoveryCodes is the number of codes in a set of recovery codes,
	// 1 to 20. Zero means DefaultRecoveryCodes.
	RecoveryCodes int
}

// Plugin is the two-factor plugin. It declares its tables, hook points,
// rate-limit rules, and permissions, and removes a user's rows when the user
// is deleted.
type Plugin struct {
	opts Options
	ac   *core.AuthContext
	log  telemetry.Logger

	disable func(hctx *core.HookContext, in disableInput) (*DisableResult, error)
}

// New returns the plugin configured with opts. Values left at zero take
// their defaults. Values that can't work are reported by Init, as a
// configuration error from Boot.
func New(opts Options) *Plugin {
	opts.Methods = slices.Clone(opts.Methods)
	if len(opts.Methods) == 0 {
		opts.Methods = []Method{MethodTOTP}
	}
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
	if opts.RecoveryCodes == 0 {
		opts.RecoveryCodes = DefaultRecoveryCodes
	}
	return &Plugin{opts: opts}
}

// Meta implements [core.Plugin]. The plugin depends on no other plugin: it
// applies to every sign-in, whichever plugin runs it. It has no mount path.
func (p *Plugin) Meta() core.PluginMeta {
	return core.PluginMeta{Name: PluginName}
}

// Version implements [core.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [core.Plugin]. The plugin declares:
//   - its tables: two_factor_methods and two_factor_recovery_codes;
//   - the auth.twoFactor.* points around turning a method on and off,
//     sending a code, and replacing the recovery codes;
//   - a rate-limit rule per user and one per client address on sending, and
//     one per client address on turning a method on;
//   - the permissions PermissionRead and PermissionManage.
func (p *Plugin) Declare(ic *core.PluginInitContext) error {
	for _, def := range []core.PermissionDef{
		{Name: PermissionRead, Kind: core.PermissionSelf, Description: "See the two-factor methods of your account"},
		{Name: PermissionManage, Kind: core.PermissionSelf, Description: "Turn two-factor methods of your account on or off, and replace its recovery codes"},
	} {
		if err := ic.Permissions.Declare(def); err != nil {
			return err
		}
	}
	for _, t := range tables() {
		if err := ic.Schemas.Declare(t.model, t.table); err != nil {
			return err
		}
	}
	for _, def := range []core.HookPointDef{
		{Point: HookEnableBefore, Phase: core.BeforeHookPhase},
		{Point: HookEnableAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookEnableFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookDisableBefore, Phase: core.BeforeHookPhase},
		{Point: HookDisableAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookDisableFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookSendBefore, Phase: core.BeforeHookPhase},
		{Point: HookSendAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookSendFailed, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},
		{Point: HookRegenerateBefore, Phase: core.BeforeHookPhase},
		{Point: HookRegenerateAfter, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
	} {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}
	// Hook rules, so that they hold however a flow is reached. Each flow
	// publishes its user in Values before its before point.
	perAddress := core.Limit{Max: 10, Window: time.Minute}
	for _, rule := range []core.HookRateLimitRule{
		{Name: RuleSendUser, Point: HookSendBefore, KeyFunc: core.KeyByValues(hooks.HookValueUserID), Limit: p.opts.SendLimit},
		{Name: RuleSendAddress, Point: HookSendBefore, KeyFunc: core.KeyByClientIP(), Limit: perAddress},
		{Name: RuleEnableAddress, Point: HookEnableBefore, KeyFunc: core.KeyByClientIP(), Limit: perAddress},
	} {
		if err := ic.RateLimits.DeclareHookRateLimitRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// Register implements [core.Plugin]. A handler on data.user.beforeDelete
// deletes the user's rows of the plugin's tables, in the delete's
// transaction, so that they go on every database, MongoDB and SQLite without
// foreign keys included.
func (p *Plugin) Register(reg core.HookRegistry) error {
	return reg.OnBefore(hooks.HookUserBeforeDelete, p.onUserDelete, nil)
}

// onUserDelete handles data.user.beforeDelete.
func (p *Plugin) onUserDelete(hctx *core.HookContext, _ behemoth.M) (behemoth.M, error) {
	userID, _ := hctx.Values[hooks.HookValueUserID].(string)
	db := hctx.Tx.DB()
	for _, model := range []behemoth.Model{&methodRow{}, &recoveryCodeRow{}} {
		if err := db.DeleteMany(hctx.Ctx, model, byUser(userID)); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Init implements [core.Plugin]. It checks the options against what the
// methods need, keeps the AuthContext, and wraps Disable with its points.
func (p *Plugin) Init(ac *core.AuthContext) error {
	const op = "twofactor.Init"
	sends := false
	for _, m := range p.opts.Methods {
		switch m {
		case MethodTOTP:
			if strings.TrimSpace(p.opts.Issuer) == "" {
				return errs.NewConfigurationError(op, "Options.Issuer is empty; TOTP needs it: an authenticator app shows it next to the account", nil)
			}
		case MethodEmail:
			sends = true
			if ac.Mailer == nil || !ac.Mailer.Configured() {
				return errs.NewConfigurationError(op, "no mail sender is configured; set BootConfig.Mail.Sender: the email method sends its codes through it", nil)
			}
		case MethodSMS:
			sends = true
			if ac.SMS == nil || !ac.SMS.Configured() {
				return errs.NewConfigurationError(op, "no SMS sender is configured; set BootConfig.SMS.Sender: the SMS method sends its codes through it", nil)
			}
		default:
			return errs.NewConfigurationError(op, fmt.Sprintf("Options.Methods names %q, which is not a method: totp, email, or sms", m), nil)
		}
	}
	if sends {
		if ac.Codes == nil {
			return errs.NewConfigurationError(op, "AuthContext has no code manager", nil)
		}
		if p.opts.CodeLength < 4 || p.opts.CodeLength > 12 || p.opts.CodeTTL < 0 || p.opts.MaxAttempts < 1 {
			return errs.NewConfigurationError(op,
				fmt.Sprintf("code options are invalid: length %d (4 to 12), TTL %s, attempts %d", p.opts.CodeLength, p.opts.CodeTTL, p.opts.MaxAttempts), nil)
		}
	}
	if p.opts.RecoveryCodes < 1 || p.opts.RecoveryCodes > maxRecoveryCodes {
		return errs.NewConfigurationError(op, fmt.Sprintf("Options.RecoveryCodes is %d: a set has 1 to %d codes", p.opts.RecoveryCodes, maxRecoveryCodes), nil)
	}
	p.ac = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.disable = core.WithLifecycle(ac.Dispatcher, HookDisableBefore, HookDisableAfter, HookDisableFailed, p.disableBody)
	return nil
}

// offers reports whether Options.Methods offers method.
func (p *Plugin) offers(method Method) bool {
	return slices.Contains(p.opts.Methods, method)
}

// method checks that s names a method Options.Methods offers, and returns it.
func (p *Plugin) method(op, s string) (Method, error) {
	method, err := parseMethod(op, s)
	if err != nil {
		return "", err
	}
	if !p.offers(method) {
		return "", errs.NewForbidden(op, ErrorCodeMethodUnavailable, "this two-factor method is not available")
	}
	return method, nil
}

// operation builds the HookContext one flow call runs with, as the other
// plugins' flows do, and publishes the user the flow acts for. Its Values
// start as a copy of the operation ctx belongs to, if any.
func (p *Plugin) operation(ctx context.Context, op, userID string) (*core.HookContext, error) {
	if p.ac == nil {
		return nil, errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	hctx := core.AsOperation(&core.HookContext{Ctx: ctx, Auth: p.ac, Values: core.NestedHookValues(ctx)})
	hctx.Values[hooks.HookValueUserID] = userID
	return hctx, nil
}

// ready reports a configuration error when Boot has not initialized the
// plugin. A flow calls it before it asks Access about the caller.
func (p *Plugin) ready(op string) error {
	if p.ac == nil {
		return errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	return nil
}

// failed fires point with code for the user of a refused operation.
func (p *Plugin) failed(hctx *core.HookContext, point core.HookPoint, code string, cause error, userID string) error {
	return p.ac.Dispatcher.Fail(hctx, point, core.FailureReason{
		Code: code, Cause: cause, SubjectType: models.UserTable, SubjectID: userID,
	})
}

// errInvalidCode is the one answer to every code the plugin refuses, so that
// the response does not tell a wrong code from an expired or a used one.
func errInvalidCode(op string) error {
	return errs.NewUnauthorized(op, ErrorCodeInvalidCode, "invalid or expired code")
}

func errNotEnabled(op string) error {
	const message = "this two-factor method is not on"
	return &errs.DomainError{
		Category: errs.CategoryConflict, Op: op, Code: ErrorCodeNotEnabled,
		PublicMessage: message, InternalMessage: op + ": " + message,
	}
}
