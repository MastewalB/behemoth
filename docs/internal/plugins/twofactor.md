# Two-factor plugin

This document explains how `plugins/twofactor` works: what it stores, how a method is set up and turned off, how a sign-in waits for and passes its second factor, and how the flows stay correct under concurrent calls. [`../plans/two_factor.md`](../plans/two_factor.md) has the design, the threats, and the decisions; this page describes what is built.

**Status:** built, as of 2026-10-22: every step of the plan is done. The API page, [`../../api/twofactor.md`](../../api/twofactor.md), still marks the plugin experimental.

It rests on the code manager ([`../codes/codes.md`](../codes/codes.md)) for the codes it sends, on `Store.Seal` for the TOTP secret, and on the TOTP engine in `plugins/twofactor/totp`.

## What the plugin contributes

| `core.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `twofactor`, no dependency, no mount path | it applies to every sign-in plugin, and needs none of them |
| `Declare` | three tables, fourteen points, five hook rules, two self-service permissions and one admin permission | codes are core's, so no token kind |
| `Register` | handlers on `auth.signIn.credentialsVerified` and `data.user.beforeDelete` | every sign-in passes the first; the user's rows go in the delete's transaction |
| `Init` | checks the options against what each offered method needs, and wraps `Disable` and `Reset` with `WithLifecycle` | |
| `Routes` | eight routes under `/two-factor`, one per flow but `Reset` | no admin principal exists yet, so `Reset` has no route |

The plugin imports `phonenumber` for `Parse` only: an SMS method's number is the user's input, confirmed by its own code, and not the phone number plugin's column. `layout_test.go` allows the import and the one of `totp` in `sameRow`.

## Data

| Table | Row | Notes |
| --- | --- | --- |
| `two_factor_methods` | one per user and method | `(user_id, method)` is unique. `confirmed_at` set means the method is on, and the plugin is on for a user with one such row. |
| `two_factor_recovery_codes` | one per recovery code | `code_hash` is `Crypto.Secrets.Hash` of the user's id and the normalized code. `used_at` is set when a code is spent. |
| `two_factor_failures` | one per user with a failure | `consecutive_failures` counts the failed second factors since the last one that passed. A pass deletes the row, and so does turning the last method off. |

A method row holds:

- **`secret` and `pending_secret`** for TOTP, both sealed with `Store.Seal` (`v<version>:<base64>`). `Enroll` writes `pending_secret`; `Confirm` moves it to `secret`. A user with TOTP on keeps signing in with `secret` while a new setup is in progress.
- **`destination`** for email and SMS: the address or number the setup code went to, read back from the code's metadata at `Confirm`.
- **`last_step`**, the time step of the last TOTP code that passed. `Confirm` sets it to the confirming code's step, so the code that turned TOTP on can't also sign in.

The three tables reference `users.id` with a cascade, and `onUserDelete` deletes the rows in `data.user.beforeDelete` through `hctx.Tx`, for MongoDB and for SQLite without foreign keys.

## Codes

The codes sent by email and SMS are rows of `verification_codes`, issued by `AuthContext.Codes`, with the user's id as their subject. There is a kind per purpose and channel, so that one channel's code can't serve the other, and a setup code can't finish a sign-in:

| Kind | Sent by | Metadata |
| --- | --- | --- |
| `twofactor.setup_email`, `twofactor.setup_sms` | `Enroll` | `destination` |
| `twofactor.sign_in_email`, `twofactor.sign_in_sms` | `SendCode` | `session_id`: the pending session the code is for |

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

## Signing in

### The checkpoint

`onCredentialsVerified` runs on `auth.signIn.credentialsVerified`, which every sign-in fires with `userID` and `factor`. A user without a confirmed method passes untouched. Otherwise `usable` decides what the sign-in may use:

- **A confirmed method that `Options.Methods` offers, and whose name is not among the session's factors.** The method names are the factor names (`email`, `sms`, `totp`), so the channel rule of [ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md) is a comparison of strings.
- **Recovery codes, when the user has one left.** They count after any first factor.

An empty list refuses the sign-in with `two_factor_same_channel`; the sign-in flows report it through `FailIfRejected` as `rejected_by_hook`. Otherwise the handler sets `requireStepUp`.

### The challenge flows

`Challenge`, `SendCode`, and `Verify` take the session from the caller (`pending`): a caller that presented a pending session's token is anonymous with `session_pending`, and keeps the session (`identity.SessionRef`, with its factors). They recompute `usable` from `SessionRef.Factors` on every call, so nothing about the challenge is stored apart from the session.

`Verify` runs in this order:

| Step | What | Refusal |
| --- | --- | --- |
| 1 | publish the user, run `beforeVerify` (the rules per user and per address run here) | a rate-limit error, or a handler's |
| 2 | the method is in `usable` | `method_unavailable` |
| 3 | for a method other than a recovery code, the lock | `locked` |
| 4 | `spend` | `invalid_code`, after `countFailure` |
| 5 | `SessionManager.Promote(sessionID, method)`: a new token, the method recorded | the session's error |
| 6 | `resetFailures`, the user read back, `afterVerify` with the `*core.SignInResult` | |

`spend` makes each kind of code work once:

- **TOTP:** `totp.Check` against the opened secret, then `last_step` is set to the matched step by an update guarded on `last_step` being lower. Two requests with one code, and a code that came again, find the guard failed.
- **A sent code:** `Codes.Consume`, then the metadata's `session_id` must be the caller's session. The consume comes first, so another session's attempt spends the code.
- **A recovery code:** every unused code of the user is compared, without stopping at a match, and the match is marked used by an update guarded on `used_at` being NULL.

### The failure count

`countFailure` creates the user's row with a count of one, or raises the count with an update guarded on the count it read, as `SpendVerificationCodeAttempt` does; of failures arriving together, each counts. `locked` compares the count with `Options.MaxFailures`. The count is per user, not per session: a new pending session does not start it again.

### Reset

`Reset` is an admin operation (`RequireAdmin`, `user:reset_two_factor`). It deletes the user's rows of the three tables in one transaction, revokes the setup and sign-in codes of both channels, and fires the disable points with `admin_reset` and no method.

## Routes

`routes.go` holds the routes, and each handler decodes, calls one flow, and encodes, as [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md) asks:

- **The input types decode themselves** (`EnrollRequest.FromMap` and the others), so a field of the wrong type is refused the same way from any transport that hands the flow a map.
- **No route has a session middleware.** Each flow reads the caller: `Access` for the setup flows, `pending` for the challenge flows. The answers for a missing, pending, or stale session are the flows' own errors.
- **`POST /two-factor/verify` answers with `httpapi.WriteSignIn`,** so a client reads the body of a finished sign-in and gets the new token by the configured delivery. Under the cookie deliveries, that sets the cookie again with the active session's expiry.
- **Every answer is marked `Cache-Control: no-store`,** since each is about one account and some carry a secret, recovery codes, or a token.

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
| `TestTwoFactorRowsGoWithTheUser` | same | the rows of the three tables deleted with the user, without foreign keys |
| `TestTwoFactorSignInWaitsForTheSecondFactor` | `tests/plugins/twofactor_signin_test.go` | a pending sign-in, the challenge, the promotion with a new token and both factors, the pending token gone, a TOTP code used once |
| `TestTwoFactorChannelCountsOnce` | same | no email code after the mailbox, recovery codes counting, the checkpoint's refusal, an email code after a password |
| `TestTwoFactorSentCodeSignIn` | same | a code bound to its session and spent by another's attempt, the masked number, the callers the challenge refuses |
| `TestTwoFactorRecoveryCodeSignIn` | same | a recovery code typed loosely, used once |
| `TestTwoFactorLock` | same | the lock across sign-ins, a recovery code passing it and clearing the count |
| `TestTwoFactorVerifiesAreLimitedPerUser` | same | the rule per user across pending sessions |
| `TestTwoFactorReset` | same | the admin permission, everything deleted, a sign-in by password alone afterwards |
| `TestTwoFactorRoutes` | `tests/plugins/twofactor_routes_test.go` | every route's body and status, the decoding errors, the sign-in route's pending answer, the new token, `no-store` |
| `TestTwoFactorEmailRoutes` | same | the email method's setup and sign-in over the routes, the masked address |

The plugin tests create their tables from the prepared application's registry (`testutils.MigrateApp`), so they run against the plugin's own declarations.
