# Two-factor plugin

This document explains how `plugins/twofactor` works: what it stores, how a method is set up and turned off, and how its flows stay correct under concurrent calls. [`../plans/two_factor.md`](../plans/two_factor.md) has the design, the threats, and the decisions; this page describes what is built.

**Status:** steps 1 to 6 of the plan are built, as of 2026-10-22. The sign-in (the checkpoint handler, the challenge, the lock) is step 7, and the routes are step 8.

It rests on the code manager ([`../codes/codes.md`](../codes/codes.md)) for the codes it sends, on `Store.Seal` for the TOTP secret, and on the TOTP engine in `plugins/twofactor/totp`.

## What the plugin contributes

| `core.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `twofactor`, no dependency, no mount path | it applies to every sign-in plugin, and needs none of them |
| `Declare` | two tables, eleven points, three hook rules, two permissions | codes are core's, so no token kind |
| `Register` | a handler on `data.user.beforeDelete` | the user's rows go in the delete's transaction |
| `Init` | checks the options against what each offered method needs, and wraps `Disable` with `WithLifecycle` | |

The plugin imports `phonenumber` for `Parse` only: an SMS method's number is the user's input, confirmed by its own code, and not the phone number plugin's column. `layout_test.go` allows the import and the one of `totp` in `sameRow`.

## Data

| Table | Row | Notes |
| --- | --- | --- |
| `two_factor_methods` | one per user and method | `(user_id, method)` is unique. `confirmed_at` set means the method is on, and the plugin is on for a user with one such row. |
| `two_factor_recovery_codes` | one per recovery code | `code_hash` is `Crypto.Secrets.Hash` of the user's id and the normalized code. `used_at` is set when a code is spent. |

A method row holds:

- **`secret` and `pending_secret`** for TOTP, both sealed with `Store.Seal` (`v<version>:<base64>`). `Enroll` writes `pending_secret`; `Confirm` moves it to `secret`. A user with TOTP on keeps signing in with `secret` while a new setup is in progress.
- **`destination`** for email and SMS: the address or number the setup code went to, read back from the code's metadata at `Confirm`.
- **`last_step`**, the time step of the last TOTP code that passed. `Confirm` sets it to the confirming code's step, so the code that turned TOTP on can't also sign in.

Both tables reference `users.id` with a cascade, and `onUserDelete` deletes the rows in `data.user.beforeDelete` through `hctx.Tx`, for MongoDB and for SQLite without foreign keys.

## Codes

The email and SMS setup codes are rows of `verification_codes`, issued by `AuthContext.Codes`, with the user's id as their subject. Their kinds are `twofactor.setup_email` and `twofactor.setup_sms`: a kind per purpose and channel, so that one channel's code can't turn on the other, and a setup code will not complete a sign-in. The destination travels in the code's metadata.

`send` is the flow behind every code that goes out. Like the phone number plugin's, it fires its points itself, since the after point means "a code went out". A send that fails revokes the code, fires `sendFailed` with `send_failed`, and returns the error: the caller is the account's owner, so there is nothing to hide.

## Setting up

| Flow | Caller | Writes |
| --- | --- | --- |
| `Status` | `RequireUser`, `two_factor:read` | nothing |
| `Enroll` | `RequireFreshUser`, `two_factor:manage` | TOTP: the pending secret. Email and SMS: a setup code, sent. |
| `Confirm` | same | the method row, confirmed; with the first method, the recovery codes; then the other sessions end |
| `Disable` | same | deletes the method row, a setup in progress included; with the last method, the recovery codes |
| `RegenerateRecoveryCodes` | same | replaces the user's recovery codes |

The flows follow these rules:

- **`Confirm` fires its points itself**, not through `WithLifecycle`: its caller gets the recovery codes, and the after point's result (`*EnableResult`) must not hold them.
- **The method row and the first set of recovery codes are one transaction** (`enable`), so a user is never left with a method and no codes. "First" is decided inside it: no confirmed row before this one.
- **The other sessions end after the transaction**, through `SessionManager.RevokeAllForUser` with the caller's session excepted. The session manager is not part of the store's transaction. If the revoke fails, `Confirm` returns the error and the method stays on.
- **`upsertMethod` creates or updates a method row.** Of two calls that create one at once, the second hits the unique index and updates the first's row.
- **A recovery code is ten symbols of Crockford's base32.** A random byte modulo 32 picks each symbol uniformly. A code is normalized before hashing: uppercase, without dashes or spaces, with `O` read as `0` and `I` and `L` as `1`.
- **`Disable` accepts a method `Options.Methods` no longer offers,** so a user can turn off what an application stopped offering.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestCodeMatchesRFC4226`, `TestCodeMatchesRFC6238`, `TestCheck`, `TestSecretEncoding`, `TestURI` | `plugins/twofactor/totp/totp_test.go` | the engine against the RFC vectors, the step window, the link's escaping |
| `TestTwoFactorTOTPSetup` | `tests/plugins/twofactor_test.go` | the sealed secret, a wrong code, the recovery codes and their hashes, the confirming step, a second setup |
| `TestTwoFactorEmailAndSMSSetup` | same | the messages, codes not crossing channels, a code used once, the destinations |
| `TestTwoFactorFirstMethodEndsOtherSessions` | same | the revoke reason, the confirming session kept, a later method ending nothing |
| `TestTwoFactorDisable` | same | the last method taking the codes, `not_enabled`, the audit events |
| `TestTwoFactorRegenerateRecoveryCodes` | same | a new set replacing the old, no set without a method |
| `TestTwoFactorSetupNeedsAFreshSession` | same | anonymous, pending, stale, and system callers |
| `TestTwoFactorOffersTheConfiguredMethods`, `TestTwoFactorOptionsAreChecked` | same | the options and `Boot`'s refusals |
| `TestTwoFactorSendsAreLimitedPerUser`, `TestTwoFactorFailedSendRevokesTheCode` | same | the limit across sessions, a failed send |
| `TestTwoFactorRowsGoWithTheUser` | same | the rows deleted with the user, without foreign keys |

The plugin tests create their tables from the prepared application's registry (`testutils.MigrateApp`), so they run against the plugin's own declarations.
