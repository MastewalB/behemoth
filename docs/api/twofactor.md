# Two-factor authentication

The `twofactor` plugin lets a user turn on a second factor: a code from an authenticator app (TOTP), or a code sent by email or by text message. A user gets recovery codes with the first method. A sign-in of that user then waits for the second factor, whichever plugin checked the first: a password, a magic link, a phone code, or an OAuth provider.

`Experimental:` the plugin is new, and its API can still change.

## Setup

```go
import (
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	"github.com/go-behemoth/behemoth/plugins/twofactor"
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

Your senders get a code in a message of these kinds, with the code in `Code` and no link:

| Kind | When |
| --- | --- |
| `core.MailTwoFactorSetup`, `core.SMSTwoFactorSetup` | a user sets up the email or SMS method |
| `core.MailTwoFactorCode`, `core.SMSTwoFactorCode` | a user signs in and asked for a code |

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
| `VerifyLimit` | 5 per 15 minutes | Second factors tried per user, across sign-ins. |
| `MaxFailures` | 100 | Failed second factors in a row after which only a recovery code passes. At most 100, the most NIST SP 800-63B allows. |

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
- **The TOTP secret is stored sealed,** like an OAuth token: the store encrypts it with your secrets, for its user. A secret copied into another user's row does not work there.
- **Turning the last method off** deletes the recovery codes too.

A number is accepted in E.164 form only, as for the phone number plugin. See [Phone number](phonenumber.md#phone-numbers).

## Sign in with a second factor

A sign-in of a user with a method that is on creates a pending session, and its route answers `{"status": "requires_second_factor"}` with the session's token. See [Sessions](sessions.md#the-sign-in-response). The sign-in then goes on with the pending session as the caller:

1. `Challenge` returns the methods this sign-in may use, with destinations partly hidden (`a***@example.com`, `+1******0123`).
2. For email or SMS, `SendCode` sends a sign-in code. It works for this sign-in only.
3. `Verify` takes the method and the code. It returns a finished sign-in, a `*core.SignInResult`, with a new session token: hand it to `httpapi.WriteSignIn` as any sign-in does. The pending token stops working.

The sign-in follows these rules:

- **A channel counts once.** After a magic link, which proves the mailbox, an email code doesn't count, and after a sign-in by phone code an SMS code doesn't. When none of a user's methods counts and no recovery code is left, the sign-in itself is refused with `403` and `two_factor_same_channel`: the user signs in another way, with a password for example.
- **A recovery code counts after any sign-in**, under the method `twofactor.MethodRecoveryCode`. It works once, typed in any case and with or without its dash.
- **A TOTP code works once.** A code that signed in, or confirmed the method, is refused when it comes again.
- **Failures count per user**, whichever pending session they come from. After `MaxFailures` in a row, only a recovery code passes: the other methods get `403` with `two_factor_locked`, and `Challenge` reports `Locked`. A recovery code that passes lifts the lock. The user should then change their password, which someone else knows.
- **The session records both factors** in `Session.Factors`, such as `password` and `totp`.

An admin turns every method of a user off with `Reset`, for a user who lost every method and every recovery code. It requires `twofactor.PermissionReset` (`user:reset_two_factor`), which only a system caller holds.

## Routes

The routes sit directly under the router's base path, and each path is a constant of the package (`twofactor.PathEnroll` and the others). Request bodies are JSON objects, and every answer is marked `Cache-Control: no-store`.

| Route | Caller | Body | Answer |
| --- | --- | --- | --- |
| `GET /two-factor` | signed in | | `{"methods": [{"method": "totp", "confirmed_at": "..."}, {"method": "email", "destination": "ada@example.com", "confirmed_at": "..."}], "recovery_codes_left": 8, "locked": false}` |
| `POST /two-factor/enroll` | a fresh session | `method`; `phone_number` for `sms`; `metadata` for your sender | for `totp`: `{"secret": "...", "uri": "otpauth://..."}`. For `email` and `sms`: `{"status": "code_sent"}` |
| `POST /two-factor/confirm` | a fresh session | `method`, `code` | `{"status": "enabled"}`, with `recovery_codes` when it is the user's first method |
| `POST /two-factor/disable` | a fresh session | `method` | `{"status": "disabled"}` |
| `POST /two-factor/recovery-codes` | a fresh session | none | `{"recovery_codes": [...]}` |
| `GET /two-factor/challenge` | the pending session | | `{"methods": [{"method": "sms", "destination": "+1******0123"}, {"method": "recovery_code"}], "locked": false}` |
| `POST /two-factor/send-otp` | the pending session | `method`: `email` or `sms`; `metadata` | `{"status": "code_sent"}` |
| `POST /two-factor/verify` | the pending session | `method`, `code` | the body of a finished sign-in, `{"user": {...}}`, and the new session token by the configured delivery |

The pending session is the one a sign-in route answered `requires_second_factor` for: send its token the way the session token travels. A client then:

1. calls `GET /two-factor/challenge` and shows the methods;
2. calls `POST /two-factor/send-otp` for `email` or `sms`;
3. posts the code to `POST /two-factor/verify`, and keeps the new token from its answer.

A field of the wrong type is a `400` named after the field, such as `method_invalid_input`, and a body that is not JSON a `400` with `request_validation_error`. The plugin's other rejections are under [Errors](#errors).

## Call the flows from code

Each flow acts on the caller's own account, which it reads from `ctx`. The setup flows need a fresh session: a session signed in within `SessionConfig.FreshAge`, 15 minutes by default.

```go
enrollment, err := second.Enroll(ctx, twofactor.EnrollRequest{Method: twofactor.MethodTOTP})
// show enrollment.URI as a QR code, and enrollment.Secret
confirmed, err := second.Confirm(ctx, twofactor.ConfirmRequest{Method: twofactor.MethodTOTP, Code: code})
// confirmed.First, confirmed.RecoveryCodes (with the first method only)

status, err := second.Status(ctx) // status.Methods, status.RecoveryCodesLeft, status.Locked
codes, err := second.RegenerateRecoveryCodes(ctx)
result, err := second.Disable(ctx, twofactor.DisableRequest{Method: twofactor.MethodTOTP}) // result.Off

// With the pending session as the caller:
challenge, err := second.Challenge(ctx) // challenge.Methods, challenge.Locked
sent, err := second.SendCode(ctx, twofactor.SendCodeRequest{Method: twofactor.MethodEmail})
signIn, err := second.Verify(ctx, twofactor.VerifyRequest{Method: twofactor.MethodTOTP, Code: code})

admin := identity.WithCaller(ctx, identity.System("support-tool"))
reset, err := second.Reset(admin, twofactor.ResetRequest{UserID: userID})
```

The flows behave as follows:

- `Status` requires `twofactor.PermissionRead` (`two_factor:read`). The setup flows require `twofactor.PermissionManage` (`two_factor:manage`) and a fresh session; an older one gets `401` with `session_not_fresh`, and the user signs in again. A signed-in user holds both permissions.
- `Challenge`, `SendCode`, and `Verify` take the pending session from the caller: the caller of a call that presented its token. A caller without one gets its session error, such as `session_missing`, and one with an active session `409` with `two_factor_not_pending`.
- `Verify` returns the raw session token in its result, and delivers nothing.
- A system caller that acts for a user (`identity.System("support-tool").For(userID)`) passes without a session.
- Before `Boot`, the flows return a configuration error.

## Errors

| Code | Status | When |
| --- | --- | --- |
| `invalid_two_factor_code` | `401` | a code that is wrong, expired, used, out of attempts, or sent for another sign-in; a recovery code that is not one; `Confirm` without a setup in progress |
| `two_factor_method_unavailable` | `403` | a method `Options.Methods` does not offer, the user has not turned on, or this sign-in may not use |
| `two_factor_locked` | `403` | a method other than a recovery code after `MaxFailures` failures in a row |
| `two_factor_same_channel` | `403` | a sign-in whose user has no method that counts after it, and no recovery code left. The sign-in route returns it. |
| `two_factor_not_pending` | `409` | `Challenge`, `SendCode`, or `Verify` with an active session |
| `two_factor_not_enabled` | `409` | `Disable` of a method that is not on, `RegenerateRecoveryCodes` without a method |
| `method_invalid_input` | `400` | a name that is not a method |
| `phone_number_invalid_input` | `400` | a number that is not in E.164 form |

## Hooks

| Point | Phase | Payload or result |
| --- | --- | --- |
| `auth.twoFactor.beforeEnable` (`twofactor.HookEnableBefore`) | before | `userID`, `method`. Veto only. |
| `auth.twoFactor.afterEnable` (`twofactor.HookEnableAfter`) | after | a `*twofactor.EnableResult`. No secret and no recovery code. |
| `auth.twoFactor.enableFailed` (`twofactor.HookEnableFailed`) | failed | codes `invalid_code`, `rejected_by_hook` |
| `auth.twoFactor.beforeDisable` (`twofactor.HookDisableBefore`) | before | `userID`, `method`, `reason` (`user_disabled`, or `admin_reset` with no method). Veto only. |
| `auth.twoFactor.afterDisable` (`twofactor.HookDisableAfter`) | after | a `*twofactor.DisableResult` |
| `auth.twoFactor.disableFailed` (`twofactor.HookDisableFailed`) | failed | codes `not_enabled`, `rejected_by_hook` |
| `auth.twoFactor.beforeSend` (`twofactor.HookSendBefore`) | before | `userID`, `method`, `purpose` (`setup` or `sign_in`). Veto only. |
| `auth.twoFactor.afterSend` (`twofactor.HookSendAfter`) | after | a `*twofactor.SendResult`. Not the code. |
| `auth.twoFactor.sendFailed` (`twofactor.HookSendFailed`) | failed | codes `method_unavailable`, `locked`, `send_failed`, `rejected_by_hook` |
| `auth.twoFactor.beforeRegenerate` (`twofactor.HookRegenerateBefore`) | before | `userID`. Veto only. |
| `auth.twoFactor.afterRegenerate` (`twofactor.HookRegenerateAfter`) | after | a `*twofactor.RegenerateResult`: the number of codes, not the codes |
| `auth.twoFactor.beforeVerify` (`twofactor.HookVerifyBefore`) | before | `userID`, `method`, `sessionID`. Veto only. |
| `auth.twoFactor.afterVerify` (`twofactor.HookVerifyAfter`) | after | the `*core.SignInResult` of the finished sign-in |
| `auth.twoFactor.verifyFailed` (`twofactor.HookVerifyFailed`) | failed | codes `invalid_code`, `method_unavailable`, `locked`, `rejected_by_hook` |

The after and failed points are audited. Every flow publishes the user under `hooks.HookValueUserID` in `Values`, for rate-limit rules.

A sign-in that waits for a second factor fires `auth.signIn.after` once its first factor passes, with a pending session in the result. The finished sign-in is `auth.twoFactor.afterVerify`. A handler that acts on finished sign-ins checks `Session.State`, or listens on that point.

## Rate limits

| Rule | Limits | Default |
| --- | --- | --- |
| `twofactor.RuleSendUser` | codes sent per user, for every purpose | `SendLimit`, 3 per 15 minutes |
| `twofactor.RuleSendAddress` | codes sent per client address | 10 a minute |
| `twofactor.RuleEnableAddress` | confirmations per client address | 10 a minute |
| `twofactor.RuleVerifyUser` | second factors tried per user, across sign-ins | `VerifyLimit`, 5 per 15 minutes |
| `twofactor.RuleVerifyAddress` | second factors tried per client address | 10 a minute |

The rules per user count across sessions: whoever knows a user's password can open a new pending session at any time. Guessing is bounded twice: by `VerifyLimit` over time, and by `MaxFailures` in all.

The rules are on the flows' before points, so they hold for the flows called from your own code. Change a limit, or turn a rule off, by its name with `RateLimitConfig`; see [Hooks](hooks.md#change-a-rule-by-its-name).

## Limits

The plugin has these limits:

- TOTP and sent codes can be phished by a site that relays them in real time. A passkey would not be, and no plugin offers one yet.
- A request that still carries the pending token when the second factor passes finds no session. Under the cookie deliveries its answer can remove the new cookie, so send the second factor once the other requests have returned.
- One sign-in code per user and channel is live: two sign-ins of one user replace each other's codes.
- The lock does not end by itself.
