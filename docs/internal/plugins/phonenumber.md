# Phone number plugin

This document explains how `plugins/phonenumber` works: how a number gets onto a user, how the three kinds of code differ, what the send and verify routes decide from the session, and what the plugin takes from the email/password plugin.

It rests on two core components that were built for it: the SMS sender ([`../mail/mailer.md`](../mail/mailer.md), *The SMS sender*) and the code manager ([`../codes/codes.md`](../codes/codes.md)).

## What the plugin contributes

| `core.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `phonenumber`, a dependency on `emailpassword`, no mount path | the password is that plugin's |
| `Declare` | the `phone_number` column, six points (nine with reset), a hook rule per address on each flow's before point and one per number | codes are core's, so no table and no token kind |
| `Register` | handlers on `data.user.beforeCreate` and `data.user.beforeUpdate` | only the plugin's flows may set a number |
| `Init` | checks the options, requires an SMS sender, wraps three flows with `WithLifecycle` | |
| `Routes` | send, verify, sign-in, and the two reset routes with `Options.PasswordReset` | |

## A stored number is a confirmed number

`phonenumber.Column` (`phone_number`) is unique, nullable, public and 16 characters long, in E.164 form. There is no "verified" flag. The column is written in one place, `Plugin.write`, and every caller of it has either consumed a code sent to the number (`verifyBody`) or is the application vouching for it (`SetPhoneNumber`).

The two data handlers enforce this for every other writer:

| Write | `onUserCreate` / `onUserUpdate` |
| --- | --- |
| a create with a number on the row | refused, `phone_number_unconfirmed_change` (403) |
| an update that does not name the column | untouched |
| an update that sets it to nil or `""` | passes, stored as `NULL` |
| an update that sets a number, without the note | refused, `phone_number_unconfirmed_change` |
| an update that sets a number, with the note for that number | checked against other users (`phone_number_taken`), then stored |

**The note.** `write` starts an operation (`core.BeginOperation`) and puts the number in its `Values` under `phonenumber.confirmed`. The update's data handlers start from a copy of those `Values`, so `onUserUpdate` finds the note and compares it with the number in the changes. A `Store.UpdateUser` from anywhere else has no note.

The note follows these rules:

- The note names the number, not only "allowed". A flow that confirmed one number can't be used to write another through a `beforeUpdate` rewrite by a different handler.
- It is a convention inside one process, not a security boundary: code that runs in the application can write the same key. What it stops is the common mistake, a profile route that copies a request body into `UpdateUser`.
- Compare with the email verification plugin, whose `beforeUpdate` handler lets a direct change of `email` through and clears `EmailVerified`. `docs/ongoing.md` has that entry; this mechanism is what closing it would look like.

## Codes

All three kinds have a user id as their subject, and the number in their metadata:

| Kind | Issued by | Subject | Consumed by |
| --- | --- | --- | --- |
| `phonenumber.verify` | `SendCode` for a caller that acts for a user | the user adding the number | `Verify` for that caller, or `AddNumber` |
| `phonenumber.sign_in` | `SendCode` for an anonymous caller | the user who holds the number | `SignInWithCode` |
| `phonenumber.password_reset` | `RequestPasswordReset` | the user who holds the number | `ResetPassword` |

- **A kind per purpose** is what keeps a sign-in code from adding a number, and a reset code from signing in. `TestPhoneNumberSignIn` and `TestPhonePasswordReset` try both.
- **The subject is always a user id**, so `Store.DeleteUser` removes a user's codes, and a number nobody holds gets no code at all.
- **`verifyBody` compares the metadata's number with the one in the request.** The code proves control of the number it was sent to. The consume comes first, so a mismatch spends the code.

## The send flow

`Plugin.send` is behind `SendCode` and `RequestPasswordReset`:

| Step | What | When it does not send |
| --- | --- | --- |
| 1 | `Parse` the number | a validation error |
| 2 | publish the number in `Values`, `RunBefore` on `auth.phoneNumber.beforeSend` (the per-number rate limit runs here) | a rate-limit error, or a handler's |
| 3 | find who holds the number | |
| 4 | for `verify`: load the user; refuse a number the user has (`already_set`) or another user has (`number_taken`). Otherwise: refuse a number nobody holds (`no_account`) | a result with `Sent: false` |
| 5 | `Codes.Issue` | the error is returned |
| 6 | `SMS.SendAsync`, or `Send` with `WaitForSend` | the code is revoked; a result with `Sent: false`, `send_failed` |
| 7 | `RunAfter` on `auth.phoneNumber.afterSend` | |

- **It does not use `WithLifecycle`.** That helper fires the after point for every result that is not an error. Here a request that sent nothing still returns a result, and the after point should mean "a code went out". So `send` calls the dispatcher itself and fires `send_failed` for the cases of steps 4 and 6.
- **The flow decides what a client learns, not the handler.** `SendResult.Sent` and `Reason` tell a caller in code everything; `handleSend` ignores the result and answers `{"status": "ok"}`. No wrapper has an error to hide. This follows *What a client may learn is decided in the flow* in [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md); the magic link and reset routes still hide errors in their handlers.
- **The rate limit runs before the lookup**, in step 2, so it counts a number nobody holds like any other.
- **A failed send is logged by the flow**, since the result does not carry the error.

## Verify: one route, two flows

`Plugin.Verify` adds the number when its caller acts for a user, and calls `SignInWithCode` when the caller is anonymous. `SendCode` decides the same way between a code to add a number and a code to sign in. Both ask `Access.OptionalUser` for `phone:change` (`PermissionPhoneChange`); the routes have no session middleware:

| Caller | Result |
| --- | --- |
| anonymous, no session token | no user: the code signs in |
| signed in, or a system caller acting for a user | the user: the code adds the number to that user |
| anonymous because its token is expired, revoked, pending or unknown | the caller's `AuthError`, a session error, `401` |
| a system caller that names no user | a configuration error |

The third row matters. A signed-in user whose session expired while they typed the code would otherwise be taken for a visitor, and their request to add a number would become a sign-in attempt for whoever holds it.

`SignInWithCode` is a sign-in of its own, shaped like the magic link plugin's `verifyBody`: it finds the user by number, consumes the code, runs `auth.signIn.credentialsVerified`, and creates the session. The lookup comes before the consume because the code's subject is the user's id.

## What comes from the email/password plugin

| Flow | Call | What it reuses |
| --- | --- | --- |
| `SignIn` | `passwords.SignInWith` with `Key: "phone_number"` | the whole password sign-in; see *Sign-in by another identifier* in [`emailpassword.md`](emailpassword.md) |
| `ResetPassword` | `passwords.ValidatePassword`, then `passwords.SetPasswordUnchecked` | the password rules, the hash, ending the sessions, the notice. The unchecked entry point because the code is the proof: `SetPassword` is an admin operation, and the caller here is anonymous |

- `SignIn`'s `Find` returns a NotFound error for a string that is not E.164, so a malformed number is answered like a wrong password and not with a `400`. The sign-in route therefore says nothing about the shape of what it was sent.
- `ResetPassword` validates the password before the wrapped flow, so a refused password costs the code no attempt. `SetPasswordUnchecked` validates again; the second check can't fail.
- After the consume, only `SetPasswordUnchecked`'s write can fail, and then the code is spent. The reset by email has the same limit with its token.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestPhoneNumberIsAddedByCode` | `tests/plugins/phonenumber_test.go` | the message, nothing written before the confirmation, the code tied to its number and user, single use, what a caller in code is told, changing a number, E.164 |
| `TestPhoneCodeAttemptsAndReplacement` | same | five tries, a newer code replacing the older |
| `TestCodeManager` | same | kinds and subjects, metadata, expiry, the purge, concurrent guesses, option errors, a deleted user's codes |
| `TestPhoneNumberSignIn` | same | sign-in by code and by password, the payloads, one answer per refusal, codes not crossing purposes |
| `TestPhoneCodeSignInPassesTheSecondFactorCheckpoint` | same | a pending session |
| `TestPhoneNumberDirectWritesAreRefused` | same | create and update refused, removal allowed, `SetPhoneNumber`, `NULL` without a number |
| `TestPhoneNumberTakenBeforeConfirmation` | same | the conflict at the write |
| `TestPhoneCodesAreLimitedPerNumber` | same | the rule across purposes, and for a number nobody holds |
| `TestPhoneCodeSending` | same | a failed send revokes the code; the background send |
| `TestPhonePasswordReset` | same | the reset, the password checked first, sessions ended, off by default |
| `TestPhoneNumberRoutes` | same | every route's bodies and statuses, with and without a session, a bad session token |
| `TestPhoneNumberOptionsAndWiring` | same | the dependency, `Boot` without a sender, option errors |
| `verificationCodesContract` | `tests/store/contract_test.go` | the store's code operations on every adapter, MongoDB included |
| `TestSMSSendsWaitingAndInBackground` | `engine/sms_test.go` | the SMS sender |

The plugin's own tests run on SQLite.

## Limits to know

These limits apply:

- `[Not built]` Sign-up with a number and no email. `users.email` is required and unique in core.
- `[Not built]` National number formats. `Parse` accepts E.164 only; converting needs the caller's country and a numbering-plan library, which by the guidelines is a module of its own.
- `[Not built]` A notice by text message when a number changes or a password is reset. A number change sends nothing to the old number.
- `[Limit]` A request for a number that has an account does more work than one for a number that has none (a code write). `docs/ongoing.md` has the entry it shares with the link plugins.
- The per-address limits are hook rules (`core.KeyByClientIP`), so they hold for the flows called from any transport whose caller has an address. The two send rules share `auth.phoneNumber.beforeSend`: `send` publishes the purpose in `Values`, and `phonenumber.reset_request.address` counts the sends of a password reset while `phonenumber.send.address` counts the others, as the two routes did. A sign-in, by code or by password, is counted by core's `core.signin.address` under the method `phonenumber`.

## Design decisions

### No verified flag: the column holds confirmed numbers only

**Context:** A number can be stored when the user types it and flagged once confirmed, or stored only once confirmed.

**Options considered:**

- *`phone_number` plus `phone_number_verified`.* A profile can show a pending number. Every reader has to check the flag, the unique column can be squatted with a number that was never confirmed, and sign-in has to refuse unverified numbers.
- *Write the number at the confirmation.* One column. The pending number lives in the code's metadata for five minutes and is gone if it is not confirmed.

**Decision:** The second. The email change flow made the same choice for a new address.

**Revisit if:** sign-up by phone is built and has to hold a number before any code is confirmed.

### Direct writes of a number are refused

**Context:** With the choice above, a `Store.UpdateUser` that sets `phone_number` would put an unconfirmed number into a column every reader trusts.

**Options considered:**

- *Document that the flow has to be used.* Nothing to build. An application's profile update route breaks the rule without anyone noticing, which is the open issue with `email`.
- *Refuse in the data handlers unless the write comes from the plugin.* The rule holds for every writer. The application needs a way to vouch for a number, and the handlers need to recognize the plugin's own writes.

**Decision:** The second, with the note in `Values` as the recognition and `SetPhoneNumber` as the way in for the application. Removing a number is allowed directly: it grants nothing.

### Send and verify decide by the session

**Context:** Adding a number and signing in by code are the same two steps for a client.

**Options considered:**

- *Four routes.* Each does one thing. A client has two pairs to wire for what a user sees as "enter the code".
- *Two routes, with a `purpose` field in the body.* One pair. A client could ask for a sign-in code while signed in, or the reverse, and each combination needs an answer.
- *Two routes, decided by the session on the request.* Nothing for the client to choose, and the purpose can't disagree with who is asking.

**Decision:** The third, as requested for the routes' shape. The purpose is fixed when the code is issued, by its kind, so the two requests of a pair can't be mixed.

**Revisit if:** a signed-in user needs a code for something else on these routes, such as re-authentication.

### Password reset by code is opt-in

**Context:** A code by text message can reset a password, as a link by mail can.

**Options considered:**

- *Always on.* One option fewer. Every application's accounts become as strong as their owners' SIM cards, without anyone choosing that.
- *On with `Options.PasswordReset`.* The application decides.

**Decision:** The second. The reset is `emailpassword.SetPassword`, so it ends the sessions and sends the mail notice like a reset by link. Since `SetPassword` became an admin operation, the reset calls its unchecked twin, `SetPasswordUnchecked`, which does the same work.

### Request bodies use `phone_number`

**Context:** The plugins' body keys were camel case (`redirectURL`) and a user's keys column names (`email_verified`).

**Options considered:**

- *Camel case for the new keys (`phoneNumber`), like the other plugins.* No existing key changes. A user in a response would still carry `phone_number`, so one body would hold both styles for the same value.
- *Snake case for the new keys only.* The plugins would then disagree with each other.
- *Snake case for every body key.* One style. It renames `redirectURL`, which no client depended on yet.

**Decision:** The third. `redirectURL` became `redirect_url` in the magic link and email verification plugins in the same change, and [`../guidelines/http_contract.md`](../guidelines/http_contract.md) records the rule.
