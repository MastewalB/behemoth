# Two-factor authentication

This document describes the design of the two-factor plugin. It covers the methods a user can turn on, how a sign-in waits for the second factor, the data the plugin keeps, the changes to core it needs, the threats and their controls, the decisions taken, and the order of the work.

**Status:** in progress, as of 2026-10-22. Steps 1 to 7 are done. [`../plugins/twofactor.md`](../plugins/twofactor.md) describes what is built. [Implementation steps](#implementation-steps) lists the work. The package will be `plugins/twofactor`.

The documents it builds on are:

- [ADR-0008](../decisions/0008-renewing-the-session-token-on-promotion.md): a session gets a new token when it passes its second factor.
- [ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md): a session records the factors that authenticated it.
- [`../sessions/token_delivery.md`](../sessions/token_delivery.md): how a pending session's token travels, and what the session check answers for it.
- [`../codes/codes.md`](../codes/codes.md): the one-time codes that the email and SMS methods send.
- [`../plugins/phonenumber.md`](../plugins/phonenumber.md): the closest existing plugin. It sends codes by SMS, and its send flow has the shape this plugin's has.
- [`caller.md`](caller.md): a pending session authenticates nobody, and the caller keeps it for the second-factor flow.
- [`../hooks/5. Hook Dispatching.md`](<../hooks/5. Hook Dispatching.md>): the `auth.signIn.credentialsVerified` checkpoint and `requireStepUp`.
- [`../guidelines/http_contract.md`](../guidelines/http_contract.md), [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md), and [`../guidelines/service_ready_components.md`](../guidelines/service_ready_components.md): the guidelines for routes, flows, and options.

## Terms

| Term | Meaning |
| --- | --- |
| First factor | The credential a sign-in flow checks: a password, a magic link, a code sent to a phone number, or an OAuth provider's answer. |
| Second factor | What the user proves after the first factor, through this plugin: a TOTP code, a code sent by email or SMS, or a recovery code. |
| Factor | What a credential proved, as a session records it: `password`, `email`, `sms`, `oauth`, `totp`, or `recovery_code` ([ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md)). `email` and `sms` name a channel, whichever plugin used it. |
| Method | A second factor that a user turns on: `totp`, `email`, or `sms`. Recovery codes come with the first method. |
| Destination | Where an email or SMS method sends its codes: the address or number confirmed when the method was turned on. |
| Pending session | A session whose user passed the first factor and not yet the second. It lasts `SessionConfig.PendingExpiresIn`, 10 minutes by default. |
| Challenge | The second step of a sign-in: the methods the pending session may use, and the code the user enters. |
| TOTP | A time-based one-time password (RFC 6238): a six-digit code that an authenticator app computes from a shared secret and the current time. |
| Recovery code | A single-use code that the user stores when the plugin turns on, for when no method is at hand. |
| Lock | The state of a user after `Options.MaxFailures` consecutive failed second factors. Only a recovery code passes. |

## Context

Core reserved a place for a second factor before any plugin used it:

- Every sign-in flow fires `auth.signIn.credentialsVerified` once the first factor checks out: email and password (with the username and phone number sign-ins by password), magic link, phone number code, and OAuth. A handler that sets `requireStepUp` in the payload makes the new session pending.
- The sign-in of a pending session answers `{"status": "requires_second_factor"}`, with the token delivered the configured way (`httpapi.WriteSignIn`).
- The authenticator makes the caller of a pending session anonymous with `session_pending`, and keeps the session on the caller (`identity.Caller.Session`). A flow that requires a user refuses it.
- `SessionManager.Promote` turns a pending session into an active one, and resets `FreshAt` and the expiry.
- `AuthContext.Codes` issues one-time codes with an attempt count, and `AuthContext.Mailer` and `AuthContext.SMS` deliver them. `Store.Seal` encrypts a secret that a plugin keeps in a table of its own.

These gaps remain:

- No plugin set `requireStepUp`. Step 7's checkpoint handler does.
- `Promote` kept the pending session's token. Under the cookie deliveries the cookie still expired with the pending session, and the flow that verifies the second factor couldn't set it again: it never sees the raw token. Step 3 renews the token.
- Nothing recorded how a session's first factor was proved, so a later request couldn't tell a magic-link sign-in from a password sign-in. Step 2 records it.
- `MailMessage` has no field for a code. `SMSMessage` has one.
- Pending sessions counted toward `SessionConfig.MaxConcurrent`, and so did expired ones. Step 1 fixed both.

## Goals

- A user turns on TOTP, a code by email, or a code by SMS, and gets recovery codes with the first method.
- Every sign-in of that user waits for the second factor, whichever plugin checked the first.
- A second factor never repeats the channel of the first.
- Guessing is bounded per user, across pending sessions, within the limit NIST SP 800-63B sets.
- The flows give the same guarantees however they are reached.

## Non-goals

Deferred: no step below includes these.

- **Trusted devices** ("remember this browser for 30 days"). The checkpoint's payload carries the user, not the request, and a hook handler doesn't read the request. A device credential would first have to reach every sign-in flow's input.
- **A second factor for an active session**, before a sensitive change. It needs a call that moves `FreshAt` in place, which L24 in `docs/ongoing.md` describes.
- **Requiring two-factor for every user, or for a role.** It needs a state between signed in and signed out, in which a user may only set up a method.
- **Notices** by email when a method is turned on or off, a recovery code is used, or the lock turns on.
- **Passkeys (WebAuthn)**, the phishing-resistant method. They need a plugin of their own.
- **A route for the admin reset.** No admin principal exists yet, so only code in the process can call it, as with `phonenumber.AddNumber`.

## Methods

| Method | What the user proves | What is stored | How it is checked |
| --- | --- | --- | --- |
| `totp` | holds the authenticator app | a 160-bit secret, sealed with `Store.Seal` | RFC 6238 with SHA-1, 6 digits, and 30 seconds, one step either side. Each code works once. |
| `email` | reads the mailbox | the address, and a code in `verification_codes` while one is out | `Codes.Consume`: 5 attempts and 5 minutes by default |
| `sms` | holds the phone number | the number, and a code in `verification_codes` while one is out | as for `email` |
| recovery code | holds the stored codes | 10 single-use codes, as keyed hashes | compared with each unused code of the user |

## Data

### `two_factor_methods`

One row per user and method. A row with `confirmed_at` set is a method the user has turned on, and the plugin is on for a user who has at least one. No other record says so.

| Column | Meaning |
| --- | --- |
| `id` | primary key |
| `user_id` | references `users.id`, deleted with the user |
| `method` | `totp`, `email`, or `sms` |
| `destination` | the address or E.164 number that codes go to. NULL for `totp`. |
| `secret` | the TOTP secret, sealed. NULL until the first confirmation. |
| `pending_secret` | a TOTP secret being set up, sealed. Confirming moves it to `secret`. |
| `last_step` | the time step of the last TOTP code that passed |
| `confirmed_at` | when the method was turned on. NULL while it is set up for the first time. |
| `created_at`, `updated_at` | |

`(user_id, method)` is unique.

### `two_factor_recovery_codes`

| Column | Meaning |
| --- | --- |
| `id` | primary key |
| `user_id` | references `users.id`, indexed |
| `code_hash`, `key_version` | `Crypto.Secrets.Hash` of the user id and the code, so a hash copied to another user's row matches nothing there |
| `used_at` | NULL until the code is used |
| `created_at` | |

### `two_factor_failures`

| Column | Meaning |
| --- | --- |
| `user_id` | primary key, references `users.id` |
| `consecutive_failures` | the failed second factors since the last one that passed |
| `updated_at` | |

A row exists only after a failure. A second factor that passes deletes it.

### Codes

Email and SMS codes are rows of core's `verification_codes`, issued by `AuthContext.Codes`. Their subject is the user id, so `Store.DeleteUser` removes them. A kind per purpose and channel keeps a setup code from completing a sign-in:

| Kind | Issued by | Metadata |
| --- | --- | --- |
| `twofactor.setup_email`, `twofactor.setup_sms` | `Enroll` | `destination` |
| `twofactor.sign_in_email`, `twofactor.sign_in_sms` | `SendCode` | `session_id`, the pending session that the code was sent for |

### In core: `sessions.factors`

[ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md) adds a nullable column to `sessions` that holds the factors in the order they were proved. `Create` stores the first, from `SessionMeta.Factor`, and `Promote` appends the second. `identity.SessionRef.Factors` carries them to flows.

### User deletion

A handler on `data.user.beforeDelete` deletes the user's rows in the three tables through `hctx.Tx`, as [`docs/api/hooks.md`](../../api/hooks.md#delete-a-user) asks of a plugin whose table references users. It covers MongoDB, and SQLite without foreign keys.

## The TOTP engine

`plugins/twofactor/totp` computes and checks codes. It uses the standard library only and keeps no state:

- `Code(secret, t)` returns the code for the time step of `t`: the RFC 4226 truncation of an HMAC-SHA-1, over RFC 6238 steps of 30 seconds.
- `Check(secret, code, t)` compares `code` with the codes of the steps before, at, and after `t`, in constant time, and returns the step that matched.
- `URI(issuer, account, secret)` returns the `otpauth://totp/...` link that a QR code carries, with the secret in base32 without padding.

The package is exported, so an application's tests can compute a valid code. The server returns the link and the client draws the QR code, so the root module gains no QR library. The tests use the vectors of RFC 4226, appendix D, and RFC 6238, appendix B.

## Flows

Each flow takes a context and a typed input, and returns a result and an error. Each route calls one flow.

### Who may call which flow

| Flows | Caller | Check |
| --- | --- | --- |
| `Status` | a signed-in user | `Access.RequireUser` with `two_factor:read` |
| `Enroll`, `Confirm`, `Disable`, `RegenerateRecoveryCodes` | a signed-in user with a fresh session | `Access.RequireFreshUser` with `two_factor:manage` |
| `Challenge`, `SendCode`, `Verify` | a caller that holds a pending session | the caller's session, in the state `pending` |
| `Reset` | an admin caller, which is a system caller today | `Access.RequireAdmin` with `user:reset_two_factor` |

The challenge flows take the user from the pending session, never from their input. A caller without a pending session gets its `AuthError`, such as an expired session, or `session_missing` when it presented no token, or `two_factor_not_pending` when its session is active already.

### Setting up

- **`Enroll`** takes a method. For `totp`, it generates a secret, stores it sealed in `pending_secret`, and returns the secret and the link. A user who has TOTP already keeps the old secret until the new one is confirmed. For `email`, it sends a setup code to the user's address. For `sms`, it sends one to the number in the input, checked with `phonenumber.Parse`.
- **`Confirm`** takes a method and a code. It checks the code against the pending secret, or consumes the setup code, and marks the method confirmed with its destination. For TOTP it records the code's step in `last_step`, so the same code can't sign in afterwards. When this is the user's first method, it also creates the recovery codes, returns them once, and ends the user's other sessions with the reason `two_factor_enabled`.
- **`Disable`** takes a method and deletes it. When no method is left, the recovery codes and the failure count go too.
- **`RegenerateRecoveryCodes`** replaces the user's codes with a new set, and returns the set once. It requires the plugin to be on.
- **`Status`** returns the confirmed methods with their destinations, the number of unused recovery codes, and whether the lock is on.

### Sign-in: the checkpoint

The plugin registers a handler on `auth.signIn.credentialsVerified`. It reads `userID` and `factor` from the payload, then:

1. It loads the user's confirmed methods. With none, it changes nothing.
2. It keeps the methods whose name is not `factor` and that `Options.Methods` still allows, and adds recovery codes when the user has unused ones.
3. When nothing is left, it refuses the sign-in with `two_factor_same_channel`, and the user signs in another way. Otherwise it sets `requireStepUp`.

### Sign-in: the challenge

- **`Challenge`** returns the methods that the pending session may use, computed as in the checkpoint from `SessionRef.Factors`. Destinations are partly hidden: `a***@example.com`, `+1******0123`. Under the lock, it lists recovery codes only, and says that the lock is on.
- **`SendCode`** takes `email` or `sms`. It issues a sign-in code with the pending session's id in its metadata, and sends it to the method's destination. A new code replaces the user's earlier one for that channel. Under the lock it sends nothing.
- **`Verify`** takes a method and a code, and runs these steps:

| Step | What | Refusal |
| --- | --- | --- |
| 1 | publish the user id, and run `auth.twoFactor.beforeVerify`, where the rate-limit rules run | a rate-limit error, or a handler's |
| 2 | check that the session may use the method | `two_factor_method_unavailable` |
| 3 | for a method other than a recovery code, check the lock | `two_factor_locked` |
| 4 | check the code and spend it, as listed below | `invalid_two_factor_code`, and the failure count goes up |
| 5 | `Promote` the session with the method as its second factor: a new token | the session's error: the session ended in the meantime, or, without `EvictOldestOnLimit`, the user reached the session limit |
| 6 | delete the failure count, and run `auth.twoFactor.afterVerify` with the `core.SignInResult` | |

Step 4 spends a code as follows:

- **TOTP:** `Check` against the sealed secret, then an update of `last_step` to the matched step, guarded on `last_step` being lower. Of two requests with one code, one passes.
- **Email and SMS:** `Codes.Consume`, then the metadata's `session_id` must be the caller's session. The consume comes first, so a mismatch spends the code.
- **Recovery code:** normalized for case, dashes, spaces, and the letters Crockford's base32 reads as digits. It is compared with each unused code of the user, then marked used with an update guarded on `used_at` being NULL.

The route answers with `httpapi.WriteSignIn`. The client parses the body of a finished sign-in, and the new token reaches it the configured way. The pending token stops working at once.

### Reset

`Reset` takes a user id. It deletes the user's methods, recovery codes, failure count, and live sign-in codes, and fires the disable points with the reason `admin_reset`. It is for a user who has lost every method and every recovery code.

## Sign-in sequence

1. The client sends the first factor to a sign-in route of any plugin.
2. The plugin's checkpoint handler finds a confirmed method that this sign-in may use, and sets `requireStepUp`.
3. The sign-in creates a pending session with the first factor recorded, and answers `{"status": "requires_second_factor"}`. The pending token travels the configured way.
4. The client calls `GET /two-factor/challenge` and shows the methods.
5. For `email` or `sms`, the client calls `POST /two-factor/send-otp`.
6. The client posts the method and the code to `POST /two-factor/verify`. The answer is the body of a finished sign-in, `{"user": {...}}`, with a new token.

## Routes

The plugin has no mount path, and each path is an exported constant.

| Route | Caller | Body | Answer |
| --- | --- | --- | --- |
| `GET /two-factor` | signed in | | `{"methods": [...], "recovery_codes_left": 8, "locked": false}` |
| `POST /two-factor/enroll` | fresh session | `method`, and `phone_number` for `sms` | for `totp`, `{"secret": "...", "uri": "otpauth://..."}`. For `email` and `sms`, `{"status": "code_sent"}`. |
| `POST /two-factor/confirm` | fresh session | `method`, `code` | `{"status": "enabled"}`, with `recovery_codes` when the plugin was turned on |
| `POST /two-factor/disable` | fresh session | `method` | `{"status": "disabled"}` |
| `POST /two-factor/recovery-codes` | fresh session | | `{"recovery_codes": [...]}` |
| `GET /two-factor/challenge` | pending session | | `{"methods": [{"method": "totp"}, {"method": "sms", "destination": "+1******0123"}, {"method": "recovery_code"}]}` |
| `POST /two-factor/send-otp` | pending session | `method` | `{"status": "code_sent"}` |
| `POST /two-factor/verify` | pending session | `method`, `code` | `{"user": {...}}` from `WriteSignIn`, and the new token |

An answer that carries a secret, a recovery code, or a token is marked `Cache-Control: no-store`.

The plugin's own rejections:

| Code | Status | Answered for |
| --- | --- | --- |
| `invalid_two_factor_code` | 401 | a code that is wrong, expired, used, or out of attempts, recovery codes included |
| `two_factor_locked` | 403 | a method other than a recovery code, under the lock |
| `two_factor_method_unavailable` | 403 | a method that the user hasn't turned on, or that this sign-in may not use |
| `two_factor_same_channel` | 403 | a sign-in whose user has no method that this sign-in may use. The sign-in route returns it. |
| `two_factor_not_pending` | 409 | a challenge flow called with an active session |
| `two_factor_not_enabled` | 409 | `Disable` of a method that is off, or `RegenerateRecoveryCodes` with the plugin off |

An unknown `method` or a malformed body is a validation error (400), and a malformed number gets the phone number plugin's `phone_number_invalid_input`. Session errors keep their codes: `session_missing`, `session_expired`, `session_not_fresh`, and `session_pending` on the routes that require a signed-in user.

## Hook points

The plugin declares the points of five operations. Each before point is veto only: its payload names the user and the method, and a change to it has no effect. No payload or result holds a code or a secret. The after and failed points are audited.

| Points | Fired by | Payload, result, and failure codes |
| --- | --- | --- |
| `auth.twoFactor.beforeEnable`, `.afterEnable`, `.enableFailed` | `Confirm` | `userID` and `method`. An `*EnableResult` without the recovery codes. `invalid_code`, `rejected_by_hook`. |
| `auth.twoFactor.beforeDisable`, `.afterDisable`, `.disableFailed` | `Disable`, `Reset` | `userID`, `method`, and `reason`: `user_disabled` or `admin_reset`. A `*DisableResult`. `not_enabled`, `rejected_by_hook`. |
| `auth.twoFactor.beforeSend`, `.afterSend`, `.sendFailed` | `Enroll` for `email` and `sms`, and `SendCode` | `userID`, `method`, and `purpose`: `setup` or `sign_in`. A `*SendResult` without the code. `method_unavailable`, `locked`, `send_failed`, `rejected_by_hook`. |
| `auth.twoFactor.beforeVerify`, `.afterVerify`, `.verifyFailed` | `Verify` | `userID`, `method`, and `sessionID`. The `*core.SignInResult` of the finished sign-in. `invalid_code`, `method_unavailable`, `locked`, `rejected_by_hook`. |
| `auth.twoFactor.beforeRegenerate`, `.afterRegenerate` | `RegenerateRecoveryCodes` | `userID`. A result with the number of codes, without the codes. |

Core's checkpoint payload gains `factor` ([ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md)), and the payload key `requireStepUp` gets a constant, `hooks.HookValueRequireStepUp`.

## Rate limits

The rules are hook rules, so they hold however a flow is reached. Each flow publishes the user id in `Values` before its before point.

| Rule | Point | Counts per | Default |
| --- | --- | --- | --- |
| `twofactor.verify.user` | `beforeVerify` | user | `Options.VerifyLimit`, 5 per 15 minutes |
| `twofactor.verify.address` | `beforeVerify` | client address | 10 per minute |
| `twofactor.send.user` | `beforeSend` | user | `Options.SendLimit`, 3 per 15 minutes |
| `twofactor.send.address` | `beforeSend` | client address | 10 per minute |
| `twofactor.enable.address` | `beforeEnable` | client address | 10 per minute |

The rules per user matter most. Whoever knows the password can open a new pending session at any time, so a limit per session would bound nothing.

## Permissions

| Permission | Kind | Required by |
| --- | --- | --- |
| `two_factor:read` | self | `Status` |
| `two_factor:manage` | self | `Enroll`, `Confirm`, `Disable`, and `RegenerateRecoveryCodes`, with a fresh session |
| `user:reset_two_factor` | admin | `Reset` |

The challenge flows require no permission. Their caller is anonymous, and the pending session is its proof, as the code is for the phone number plugin's sign-in by code.

## Messages

| Kind | Sent by | Carries |
| --- | --- | --- |
| `core.MailTwoFactorSetup`, `core.SMSTwoFactorSetup` | `Enroll` | the code that confirms the destination |
| `core.MailTwoFactorCode`, `core.SMSTwoFactorCode` | `SendCode` | the sign-in code |

`MailMessage` gains a `Code` field, documented as a credential like `SMSMessage.Code`. The mailer and the SMS queue log only a message's kind. As in the phone number plugin, `Options.WaitForSend` chooses between `Send` and `SendAsync`, and a failed send that the flow waited for revokes the code.

## Options

Every option is data:

```go
type Options struct {
	// Issuer is the name an authenticator app shows next to the account.
	// It is required when Methods allows TOTP.
	Issuer string
	// Methods are the methods a user may turn on. Empty means TOTP only.
	Methods []Method

	// The codes sent by email and SMS. Zero means 6 digits, 5 minutes,
	// and 5 attempts.
	CodeLength  int
	CodeTTL     time.Duration
	MaxAttempts int
	// SendLimit bounds the codes sent per user. Zero means 3 per 15 minutes.
	SendLimit   core.Limit
	WaitForSend bool

	// RecoveryCodes is the number of codes in a set. Zero means 10.
	RecoveryCodes int
	// VerifyLimit bounds the second factors tried per user. Zero means 5
	// per 15 minutes.
	VerifyLimit core.Limit
	// MaxFailures is the number of consecutive failures that turns the lock
	// on. Zero means 100, the most NIST SP 800-63B allows, and a larger
	// value fails Init.
	MaxFailures int
}
```

`Init` fails with a configuration error for TOTP without an `Issuer`, for `email` without a mail sender, for `sms` without an SMS sender, and for code options outside what the code manager accepts. The TOTP parameters are fixed, as [TOTP parameters are fixed](#totp-parameters-are-fixed) explains.

## Core changes

| Change | Why | Step |
| --- | --- | --- |
| The session limit counts only active sessions that have not expired, and evicts only among them | A pending session could evict an active one, and expired sessions refused new sign-ins (M23). | 1 |
| `sessions.factors`, `SessionMeta.Factor`, `SessionRef.Factors`, the factor names in `core`, and `factor` in the checkpoint payload. The four sign-in plugins pass their factor. | The channel rule, [ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md) | 2 |
| `hooks.HookValueRequireStepUp` replaces the string in four plugins | The key is a contract between plugins. | 2 |
| `Promote(ctx, sessionID, factor)` returns a new raw token, and records the factor | [ADR-0008](../decisions/0008-renewing-the-session-token-on-promotion.md) | 3 |
| `MailMessage.Code`, and the mail and SMS kinds of the plugin's codes | An email code has no field today. | 4 |

The factor that each sign-in records:

| Sign-in | Factor |
| --- | --- |
| `emailpassword.SignIn` and `SignInWith`, which the username and phone number sign-ins by password call | `password` |
| the magic link plugin's verify | `email` |
| `phonenumber.SignInWithCode` | `sms` |
| `oauth.Complete` | `oauth` |

## Security

### Rules the design depends on

The design holds only while these rules hold:

- **A pending session authenticates nobody.** `Access` answers `session_pending` for it, and only the challenge flows read it. If another flow accepted it, the first factor would be enough.
- **A second factor is spent before the session is promoted.** One TOTP step, one code, or one recovery code completes at most one sign-in.
- **Promotion renews the token** ([ADR-0008](../decisions/0008-renewing-the-session-token-on-promotion.md)). Otherwise a pending token that leaked becomes an active session.
- **A channel counts once** ([ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md)). A sign-in flow that records no factor leaves the rule nothing to exclude.
- **A failed second factor counts against the user, not the session.** Otherwise a new pending session would start the count again.
- **No code or secret leaves the flow,** except the TOTP secret and the recovery codes in the one answer that hands them to the user. Payloads, results, logs, and audit events carry none.

### Threats and controls

| Threat | Control |
| --- | --- |
| Someone else knows the password | The pending session grants nothing until a second factor passes. |
| Guessing a TOTP code or a sent code | The rate limit per user, and the lock after `MaxFailures` consecutive failures. With 100, each lock leaves a TOTP guesser a chance of at most 0.03%. |
| A TOTP code seen over the user's shoulder and reused | `last_step`: a code works once. |
| A real-time phishing proxy | Not prevented. TOTP and sent codes can be phished, and passkeys are the deferred answer. |
| A mailbox taken over, used for a magic link | Email codes don't count after a magic link. |
| A SIM swap, used for a sign-in by phone code | SMS codes don't count after a phone code. |
| A SIM swap, together with the password | Not prevented. SMS is the weakest method, and an application can leave it out of `Options.Methods`. |
| A pending token in a log, or read by a script | The token is renewed at promotion. |
| A stolen session turns two-factor off | A fresh session is required, and the change is audited. |
| Sessions that were open before two-factor turned on | They end when the first method is confirmed. |
| Pending sessions that evict the user's sessions | They don't count toward `MaxConcurrent` (step 1). |
| Requests for codes as an attack on the SMS budget | The send limits per user and per address. Codes go only to confirmed destinations. |
| A copy of the database | TOTP secrets are sealed. Sent codes and recovery codes are keyed hashes. |
| Someone with the password turns the lock on | Accepted. The user signs in with a recovery code, which lifts the lock. Each failure is audited. |

## Design decisions

Two decisions have records of their own: [ADR-0008](../decisions/0008-renewing-the-session-token-on-promotion.md), the token renewed at promotion, and [ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md), the factors recorded on the session. The other decisions taken for this plan follow.

### Recovery codes come with the first method

Without them, a lost phone means an admin reset, which only code in the process can run today. They are generated when the plugin turns on, shown once, and stored as keyed hashes, so a copy of the table does not give them away. Each code is ten characters of Crockford's base32, shown as `XXXXX-XXXXX`, which is 50 bits. Guessing one is out of reach without a lock of its own.

### A channel counts once

An email code after a magic link proves control of the same mailbox twice, and an SMS code after a sign-in by phone code proves the same phone number twice. Neither adds a factor, and an attacker who holds the mailbox or the number passes both. A method whose name is among the session's factors is not offered. A sign-in that leaves nothing to offer is refused, and the user signs in with a password, after which the email code does count. Recovery codes always count, so a user who has them can finish any sign-in.

The rule compares channels, not destinations: an email code sent to a second address doesn't count after a magic link either. That is stricter than necessary, and simpler to explain.

### Consecutive failures turn on a lock, not a delay

A rate limit alone lets guesses add up. TOTP accepts 3 codes in a million, and 5 tries every 15 minutes reach about 4% in a month. NIST SP 800-63B caps consecutive failed attempts per account at 100. Past the cap, TOTP and sent codes are refused until a recovery code passes or an admin resets the user. The count lives in a row of its own per user, raised with a guarded update, and deleted by any second factor that passes.

A recovery code that lifts the lock also gives a holder of the password another `MaxFailures` tries. A locked user should change their password, and the notice that would say so is deferred.

**Options rejected:**

- *A lock that ends by itself after some hours.* Guessing resumes at a slower pace, and the bound is gone.
- *The rate limiter's `ActionLockout`.* It is not built (L6), and it counts attempts, not consecutive failures.

### The methods table is the only record that the plugin is on

A `two_factor_enabled` column on `users` would be a second copy of a security setting, and a write path to guard: a profile route that copies a request body into `Store.UpdateUser` could turn it off. The phone number plugin needed data handlers for that reason. Clients ask `GET /two-factor`.

**Revisit if:** clients need the state in every answer that carries a user.

### Turning the plugin on ends the user's other sessions

Those sessions were opened without a second factor. A user who turns the plugin on because they suspect a stolen password would otherwise leave the thief signed in. The session that confirms the method stays: it is fresh, and it proved the method in the same request.

### A method keeps the destination it was confirmed with

Codes go to the address or number confirmed at setup, not to the user's current email or `phone_number`. A change of either through another plugin doesn't move the second factor, so a stolen session can't redirect it. The plugin then needs no other plugin installed: it calls the phone number plugin's `Parse` only. A user moves a method by setting it up again.

### TOTP parameters are fixed

SHA-1, six digits, and 30 seconds are the parameters every authenticator app supports. Some apps ignore other values in the link, and their users would then hold an app that computes wrong codes. RFC 6238 recommends accepting at most one step of delay, which is the one step either side.

**Revisit if:** an application needs eight digits or another algorithm for a compliance rule.

### The pending session carries the challenge

The session already has a token, a short expiry, and a state that every other flow refuses. A separate challenge token would duplicate all three. The cost is that a pending session is a row in `sessions`, which step 1 keeps out of the session limit.

## Limits to know

- `auth.signIn.after` fires when the first factor passes, with a pending session in its result. The finished sign-in is `auth.twoFactor.afterVerify`. A handler that acts on finished sign-ins checks `Session.State`, or listens on the plugin's point.
- One sign-in code per user and channel is live. Two pending sessions of one user replace each other's codes, and a code is refused for a session it was not sent for.
- A confirmed method that `Options.Methods` no longer allows can't be used. Recovery codes and the admin reset remain.
- The lock does not end by itself.
- The session that confirms the first method keeps its single factor in `Session.Factors`.
- A request that still carries the pending token when the second factor passes finds no session. Under the cookie deliveries its answer can remove the new cookie, so a client sends the second factor once its other challenge requests have returned. [`../sessions/token_delivery.md`](../sessions/token_delivery.md) has the details.

## Implementation steps

The work is done in this order. Each step ends with its tests and its docs, and leaves the code working.

| Step | Content | Status |
| --- | --- | --- |
| 1 | The session limit counts only active sessions that have not expired, and evicts only among them. A sign-in whose session will be pending is checked against the limit and makes no room, and `Promote` applies the limit. The session manager takes every session time from the store's clock, in UTC, since the limit compares `expires_at` in the database. It resolves M23 and removes its entry. | Done |
| 2 | [ADR-0009](../decisions/0009-recording-the-factors-of-a-session.md): `sessions.factors`, `SessionMeta.Factor`, `SessionRef.Factors`, the factor names in `core`, and `factor` in the checkpoint payload. The email/password, magic link, phone number, and OAuth sign-ins pass theirs. `hooks.HookValueRequireStepUp`. Docs: `docs/api/sessions.md`, `docs/api/hooks.md`, `docs/internal/models/models.md`. | Done |
| 3 | [ADR-0008](../decisions/0008-renewing-the-session-token-on-promotion.md): `Promote(ctx, sessionID, factor)` returns a new raw token and records the factor, in one write guarded on the pending state. Docs: `docs/api/sessions.md`, `docs/internal/sessions/token_delivery.md`. | Done |
| 4 | `MailMessage.Code`, and the plugin's mail and SMS kinds. Docs: `docs/api/mail.md`. The API pages list the kinds once the plugin sends them, in steps 6 and 7. | Done |
| 5 | `plugins/twofactor/totp`, tested with the RFC vectors. | Done |
| 6 | The plugin and its setup: the options and their checks in `Init`, the methods and recovery code tables, the enable, disable, send, and regenerate points, their rules, the two self-service permissions, the user deletion handler, and `Status`, `Enroll`, `Confirm`, `Disable`, and `RegenerateRecoveryCodes`. The `sameRow` entries in `layout_test.go` for the plugin's imports of `totp` and `phonenumber`, and a row for the package in `CLAUDE.md`. Docs: `docs/internal/plugins/twofactor.md` and `docs/api/twofactor.md` start here. | Done |
| 7 | The sign-in: the checkpoint handler, `Challenge`, `SendCode`, `Verify` with the failure table, the lock, and `Options.VerifyLimit` and `MaxFailures`, the verify points and rules, and `Reset` with its permission. The flows' tests run without HTTP. | Done |
| 8 | The routes and their tests, the plugin in the README and in an example application, and the API page completed. | Not started |

Steps 2 and 3 change what a sign-in plugin passes and what `Promote` returns, so they land before a tagged release. A sign-in plugin written outside this repository passes its factor from step 2 on.

## Related entries

These entries in `docs/ongoing.md` affect the design:

- **M23, "The session limit counts sessions that can't be used".** Step 1 resolved it, and removed the entry.
- **L24, "Nothing refreshes a session in place".** A second factor for an active session waits for it.
- **L6, "`ActionLockout` is declared but not built".** The lock here is the plugin's own count, and does not need it.
- **M9, "A new core table has to be migrated before the version that needs it runs".** `sessions.factors` is the same case for a column: an application migrates before it deploys step 2.
- **M10, "Nothing removes old sessions, tokens or rate-limit counters".** Every sign-in with a second factor writes a pending session, and an abandoned one stays until its user is deleted.
- **H1, "Every rate-limit rejection writes an audit row".** The plugin's rules per user add rejections to it.
