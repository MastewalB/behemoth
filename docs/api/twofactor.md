# Two-factor authentication

The `twofactor` plugin lets a user turn on a second factor: a code from an authenticator app (TOTP), or a code sent by email or by text message. A user gets recovery codes with the first method.

`Experimental:` turning methods on and off and replacing the recovery codes work. A sign-in does not ask for the second factor yet, and the plugin has no routes yet: call its flows from your own code. Its API can still change.

## Setup

```go
import (
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/plugins/twofactor"
)

passwords := emailpassword.New(emailpassword.Options{})
second := twofactor.New(twofactor.Options{
	Issuer:  "Example",
	Methods: []twofactor.Method{twofactor.MethodTOTP, twofactor.MethodEmail},
})

app, err := engine.Prepare([]core.Plugin{passwords, second}, engine.PrepareConfig{})
// ...
ac, err := engine.Boot(ctx, app, db, engine.BootConfig{
	Mail: core.MailConfig{Sender: mailSender}, // for the email method
	// ...
})
```

`mailSender` is your `core.MailSender`; see [Mail](mail.md). The plugin is set up as follows:

- The plugin's name is `twofactor` (`twofactor.PluginName`). It depends on no other plugin.
- It adds two tables, `two_factor_methods` and `two_factor_recovery_codes`, and uses the core `verification_codes` table. Generate and apply a migration after adding the plugin. On MongoDB, run `EnsureIndexes`.
- `Boot` fails without `Issuer` when TOTP is offered, without a mail sender when email is, and without an SMS sender when SMS is.
- On SQLite, open the database with `_txlock=immediate`. See [Username](username.md#setup) for the reason.

Your senders get a setup code in a message of these kinds, with the code in `Code` and no link:

| Kind | When |
| --- | --- |
| `core.MailTwoFactorSetup` | a user sets up the email method |
| `core.SMSTwoFactorSetup` | a user sets up the SMS method |

## Options

| Field | Default | Meaning |
| --- | --- | --- |
| `Issuer` | none | The name an authenticator app shows next to the account, such as your application's. Required when `Methods` offers TOTP. |
| `Methods` | TOTP only | The methods a user may turn on: `twofactor.MethodTOTP`, `MethodEmail`, `MethodSMS`. |
| `CodeLength` | 6 | Digits of a code sent by email or SMS, 4 to 12. |
| `CodeTTL` | 5 minutes | How long a sent code works. |
| `MaxAttempts` | 5 | How many times one sent code may be tried, the right guess included. |
| `SendLimit` | 3 per 15 minutes | Codes sent per user, for every purpose together. |
| `WaitForSend` | false | false: the call returns once the message is queued, and a failed send is logged. true: the call waits for your sender, and a failed send revokes the code and is returned. |
| `RecoveryCodes` | 10 | Codes in a set of recovery codes, 1 to 20. |

TOTP codes are fixed at SHA-1, six digits, and 30 seconds, the parameters every authenticator app supports.

## Turn a method on

A method is on once the user proves they hold it, in two calls:

1. `Enroll` starts the setup. For TOTP it returns a secret and an `otpauth://` link: show the link as a QR code, and the secret for typing in. For email it sends a setup code to the account's address, and for SMS to the number the user gives.
2. `Confirm` takes a code: one the authenticator app shows, or the one that was sent. The method is then on.

The setup follows these rules:

- **The first method brings the recovery codes.** `Confirm` returns them in `RecoveryCodes`, the only time they are shown: only keyed hashes are stored. Each is ten characters, such as `7K3QX-M9P2D`. `RegenerateRecoveryCodes` replaces the set.
- **The first method ends the user's other sessions**, with the revoke reason `two_factor_enabled` (`twofactor.SessionRevokedEnabled`): they were opened without a second factor. The session that confirms stays.
- **A method keeps the destination it was confirmed with.** Codes go to that address or number, whatever the account's email or phone number becomes. Set the method up again to change it.
- **A new TOTP setup keeps the old secret working** until the new one is confirmed.
- **The TOTP secret is stored sealed,** like an OAuth token: the store encrypts it with your secrets.
- **Turning the last method off** deletes the recovery codes too.

A number is accepted in E.164 form only, as for the phone number plugin. See [Phone number](phonenumber.md#phone-numbers).

## Call the flows from code

Each flow acts on the caller's own account, which it reads from `ctx`. The setup flows need a fresh session: a session signed in within `SessionConfig.FreshAge`, 15 minutes by default.

```go
enrollment, err := second.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
// show enrollment.URI as a QR code, and enrollment.Secret
confirmed, err := second.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: code})
// confirmed.First, confirmed.RecoveryCodes (with the first method only)

status, err := second.Status(ctx) // status.Methods, status.RecoveryCodesLeft
codes, err := second.RegenerateRecoveryCodes(ctx)
result, err := second.Disable(ctx, twofactor.DisableRequest{Method: twofactor.MethodTOTP}) // result.Off
```

The flows behave as follows:

- `Status` requires `twofactor.PermissionRead` (`two_factor:read`). The other flows require `twofactor.PermissionManage` (`two_factor:manage`) and a fresh session; an older one gets `401` with `session_not_fresh`, and the user signs in again. A signed-in user holds both permissions.
- A system caller that acts for a user (`identity.System("support-tool").For(userID)`) passes without a session.
- Before `Boot`, the flows return a configuration error.

## Errors

| Code | Status | When |
| --- | --- | --- |
| `invalid_two_factor_code` | `401` | `Confirm` with a code that is wrong, expired, used, out of attempts, or without a setup in progress |
| `two_factor_method_unavailable` | `403` | a method `Options.Methods` does not offer |
| `two_factor_not_enabled` | `409` | `Disable` of a method that is not on, `RegenerateRecoveryCodes` without a method |
| `method_invalid_input` | `400` | a name that is not a method |
| `phone_number_invalid_input` | `400` | a number that is not in E.164 form |

## Hooks

| Point | Phase | Payload or result |
| --- | --- | --- |
| `auth.twoFactor.beforeEnable` (`twofactor.HookEnableBefore`) | before | `userID`, `method`. Veto only. |
| `auth.twoFactor.afterEnable` (`twofactor.HookEnableAfter`) | after | a `*twofactor.EnableResult`. No secret and no recovery code. |
| `auth.twoFactor.enableFailed` (`twofactor.HookEnableFailed`) | failed | codes `invalid_code`, `rejected_by_hook` |
| `auth.twoFactor.beforeDisable` (`twofactor.HookDisableBefore`) | before | `userID`, `method`, `reason`. Veto only. |
| `auth.twoFactor.afterDisable` (`twofactor.HookDisableAfter`) | after | a `*twofactor.DisableResult` |
| `auth.twoFactor.disableFailed` (`twofactor.HookDisableFailed`) | failed | codes `not_enabled`, `rejected_by_hook` |
| `auth.twoFactor.beforeSend` (`twofactor.HookSendBefore`) | before | `userID`, `method`, `purpose` (`setup`). Veto only. |
| `auth.twoFactor.afterSend` (`twofactor.HookSendAfter`) | after | a `*twofactor.SendResult`. Not the code. |
| `auth.twoFactor.sendFailed` (`twofactor.HookSendFailed`) | failed | codes `send_failed`, `rejected_by_hook` |
| `auth.twoFactor.beforeRegenerate` (`twofactor.HookRegenerateBefore`) | before | `userID`. Veto only. |
| `auth.twoFactor.afterRegenerate` (`twofactor.HookRegenerateAfter`) | after | a `*twofactor.RegenerateResult`: the number of codes, not the codes |

The after and failed points are audited. Every flow publishes the user under `hooks.HookValueUserID` in `Values`, for rate-limit rules.

## Rate limits

| Rule | Limits | Default |
| --- | --- | --- |
| `twofactor.RuleSendUser` | codes sent per user, for every purpose | `SendLimit`, 3 per 15 minutes |
| `twofactor.RuleSendAddress` | codes sent per client address | 10 a minute |
| `twofactor.RuleEnableAddress` | confirmations per client address | 10 a minute |

The rules are on the flows' before points, so they hold for the flows called from your own code. Change a limit, or turn a rule off, by its name with `RateLimitConfig`; see [Hooks](hooks.md#change-a-rule-by-its-name).

## Limits

The plugin has these limits:

- A sign-in does not ask for the second factor yet.
- The plugin mounts no routes yet.
- A recovery code can't be used yet. Keep the set: it is what a user will sign in with when no method is at hand.
