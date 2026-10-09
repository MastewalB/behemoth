# Magic link plugin

This document explains how `plugins/magiclink` is put together: what it declares, how its two flows use the token manager, the session manager and the hook dispatcher, and why the request route answers the same for every email. The trusted-origin check it relies on is described at the end, since the plugin was its first user.

The code lives in:

- `plugins/magiclink/magiclink.go`: the plugin
- `types/origins.go`: `TrustedOrigins`, `TrustedRedirect`
- `types/signin.go`: `SignInResult`, shared with the email/password plugin

## What the plugin contributes

| `types.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `magiclink`, no dependencies, no mount path | routes sit directly under the base path |
| `Declare` | the `magic_link` token kind, three hook points, three rate-limit rules | see below |
| `Register` | nothing | the plugin fires points; it does not handle any |
| `Middlewares` | nothing | neither route needs a session |
| `Init` | checks `Options`, parses `LinkURL`, wraps the flows with `types.WithLifecycle` | runs in `Boot`, after the dispatcher exists |
| `Routes` | `POST /sign-in/magic-link`, `POST /magic-link/verify` | |

Compare with the email/password plugin, which declares nothing. This one is the first plugin to use all four catalogs a plugin gets in `Declare` except the schema: it needs no table, because a link is a row in core's `tokens`.

| Declared | Value |
| --- | --- |
| token kind | `types.TokenKindMagicLink`, single use, `Options.TTL`, database backend |
| hook points | `auth.magicLink.beforeRequest` (before), `.afterRequest` (after, audited), `.requestFailed` (failed, audited) |
| route rules | `magiclink.request.route` and `magiclink.verify.route`: 10 a minute per client address |
| hook rule | `magiclink.request.email` on `auth.magicLink.beforeRequest`: `Options.RequestLimit` per `HookValueEmail` |

The token kind is database-backed on purpose. `RevokeAllForSubject` is not supported for a key-value kind, and `Store.DeleteUser` removes a user's tokens from the table.

## Requesting a link

`Plugin.RequestLink` builds the flow's `HookContext`, publishes the normalized email in `Values` (`publishEmail`) and calls the flow wrapped by `WithLifecycle`. `requestBody` then runs these steps:

| Step | What | On failure |
| --- | --- | --- |
| 1 | normalize the email and check its shape (`utils.IsValidEmail`) | a validation error |
| 2 | check `RedirectURL` with `types.TrustedRedirect(ac.Origins, url)`, if one was given | a validation error |
| 3 | `Store.FindUserByEmail` | not found: `Fail` with `userNotFound`, return `ErrNoAccount` |
| 4 | `TokenManager.RevokeAllForSubject(magic_link, user.ID)` | `Fail` with `issueFailed` |
| 5 | `TokenManager.Issue(magic_link, user.ID, {email, redirectURL})` | `Fail` with `issueFailed` |
| 6 | build the URL: `LinkURL` plus `token=<raw>` | |
| 7 | `ac.Mailer.Send(ctx, MailMessage{Kind: MailMagicLink, ...})`, or `SendAsync` with `Options.SendInBackground` | revoke the token, `Fail` with `sendFailed` |
| 8 | return a `*LinkResult`; `WithLifecycle` fires `auth.magicLink.afterRequest` | |

Steps 1 and 2 come before the lookup, so a validation error does not depend on whether the email has an account.

- **The token's subject is the user's id.** The email the link was sent to is in the token's metadata. See the design decision below.
- **`Metadata` is not stored.** It goes from the request to the mail sender and nowhere else. Only the email and the redirect URL are kept with the token.
- **With `SendInBackground`, step 7 only fails when the message could not be queued.** A send that fails later is logged by the mailer; the link is not revoked and no failed point fires. See [`../mail/mailer.md`](../mail/mailer.md).
- **The raw token exists in three places:** the `MailMessage` handed to the mailer, its `URL`, and the token manager's return value. `LinkResult`, which the after handlers and the audit event see, has the token's id and not the token.

### What the route hides

The route has to answer the same for an email with an account and one without. Three failures can only happen for an email that has an account, and each would give the account away if it were reported:

| Failure | Why it is account-dependent |
| --- | --- |
| no user (step 3) | by definition |
| the token could not be issued (steps 4 and 5) | a veto or a rate limit on `token.beforeIssue` is only reached for a known user |
| the send failed (step 7) | the sender is only called for a known user |

`requestBody` returns `ErrNoAccount` for the first and wraps the other two in `afterLookupError`. `handleRequest` turns all three into the `200` it gives a sent link, and logs the wrapped error at Error, since nothing else reports it. `RequestLink` returns them to a caller from code, which is not a stranger asking about an address.

Everything else is reported, because it does not depend on the account: a validation error, a rejection by a handler on `auth.magicLink.beforeRequest`, the plugin's own rate limits (they count unknown emails too), and a failure of the lookup itself.

The response time still differs: a known email pays for the token writes, and without `SendInBackground` for the mail sender. `docs/ongoing.md` has the entry.

## Verifying a link

`Plugin.Verify` first reads the token without consuming it (`TokenManager.Verify`, which fires no hooks). It does that for what the before point needs: the email, which goes in the `auth.signIn.before` payload and in `Values` for rate-limit rules, and the redirect URL, which is returned next to the sign-in. A token that does not check out still enters the flow, without an email, so the refusal fires `auth.signIn.failed` like any other.

`verifyBody`, wrapped with core's three sign-in points:

| Step | What | On failure |
| --- | --- | --- |
| 1 | `TokenManager.Consume(magic_link, token)` | `Fail` with `invalidMagicLink` |
| 2 | `Store.FindUserByID(token.Subject)` | `Fail` with `userNotFound` |
| 3 | compare the email in the token's metadata with the user's | `Fail` with `emailChanged` |
| 4 | set `email_verified` if it is not set (`Store.UpdateUser`) | the error is returned |
| 5 | `RunBefore(auth.signIn.credentialsVerified)`; `requireStepUp` makes the session pending | `Fail` with `secondFactorRejected` |
| 6 | `SessionManager.Create` | the error is returned |
| 7 | return a `*types.SignInResult` with `Method: "magiclink"` | |

The route hands the result to `types.WriteSignIn` with the redirect URL as an extra field, so its response and the delivery of the session token are the ones of every sign-in route ([`../sessions/token_transport.md`](../sessions/token_transport.md)).

Steps 1 to 3 all answer with `errInvalidLink`, one typed unauthorized error with the code `invalid_magic_link`. The audit event of `auth.signIn.failed` has the real code.

- **The token is consumed in step 1 and stays consumed.** A refusal in step 5 or a session limit in step 6 does not give the link back. Consuming last would let a link be tried again and again against a second factor.
- **`Consume` is the at-most-once step.** Two verifies of one link race inside the token manager's transaction, and one loses with `token_already_consumed`.
- **The payload on `auth.signIn.before` is veto-only.** `verifyInput.FromMap` reads nothing back. A handler can refuse the sign-in; it can't swap the token or the email.

## Design decisions

### The link points at the application and verify is a POST
**Context:** Mail servers and clients open the links in a message to scan or preview them. A link that signs in on a `GET` is consumed by the scanner, and the user finds it already used.
**Options considered:**
- *A `GET` route that verifies and redirects.* The shortest path: the link is the whole flow. Scanners use the link up.
- *A `GET` route that serves a confirmation page and a `POST` that verifies.* Scanner-proof, and Behemoth would serve HTML, which it does nowhere else.
- *The link points at a page of the application, which posts the token.* Scanner-proof, and the page is the application's to design. The application has to build that page.
**Decision:** The third. `Options.LinkURL` names the page. Behemoth stays an API.
**Revisit if:** applications without a front end of their own (a server-rendered site with no script) need the flow. A confirmation page could be added as an option.

### The token's subject is the user, not the email
**Context:** The token has to name who it signs in. The request has an email, and the lookup turns it into a user before the token is issued.
**Options considered:**
- *The email.* It is what the link was sent to, and it would allow a link for an address without an account, which sign-up by link needs. `Store.DeleteUser` removes tokens by user id, so the plugin would have to delete its own on `data.user.beforeDelete`. A link would follow the address to whoever holds it next.
- *The user's id, with the email in the metadata.* `DeleteUser` and `RevokeAllForSubject` work as they are. The email is compared at verify, so a link does not outlive a change of address.
**Decision:** The user's id. There is no sign-up by link, so a user always exists when a token is issued.
**Revisit if:** sign-up by link is built. A link for an address without an account has no user to name.

### Verify fires core's sign-in points
**Context:** A magic-link sign-in ends the way a password sign-in does: a user, a session, possibly a second factor. Handlers that care about sign-ins should not need to know every method.
**Options considered:**
- *Points of the plugin's own for verify.* Clear ownership. A second-factor plugin, a sign-in notifier and the audit log would each have to register on every sign-in plugin's points.
- *Core's `auth.signIn.*` points.* One place to hook. The payload of `auth.signIn.before` differs by method: an email and a password there, an email and a method here.
**Decision:** Core's points, which is what they were declared in core for. `SignInResult` moved from `emailpassword` to `types` so that `auth.signIn.after` hands every handler one type, and it gained `Method`. The request for a link is not a sign-in and has the plugin's own points.
**Revisit if:** the differing `auth.signIn.before` payloads cause handler bugs. A `method` key on the email/password payload would let a handler tell them apart there too; today it is set only by this plugin.

### The link is sent through the shared mailer
**Context:** The plugin first took a `SendLink` callback in its options. Email verification then needed to send too.
**Decision:** The callback was replaced by `AuthContext.Mailer`, which every plugin uses; [`../mail/mailer.md`](../mail/mailer.md) has the options that were weighed. The request's `Metadata` map is handed to the sender untouched, in `MailMessage.Metadata`, so an application can pass what its message needs (a locale, a template) without the plugin growing a field for each. It is client input when it comes from the route, and the API doc says so.

### Waiting for the sender is the default
**Context:** The mailer offers `Send`, which waits, and `SendAsync`, which does not.
**Options considered:**
- *Always wait.* A failed send revokes the link and is audited. A sender that calls a provider directly holds the request, and widens the timing gap between known and unknown emails.
- *Never wait.* Fast and even. A link that was never sent stays valid until it expires, and the failure is only in the log.
- *An option.* Both are reasonable, and which is better depends on the application's sender.
**Decision:** `Options.SendInBackground`, off by default. With a sender that enqueues, waiting costs nothing and keeps the revoke.

## Trusted origins

`RouterConfig.TrustedOrigins` existed as a field, and `OriginValidator` as an interface, with nothing behind either. `types.TrustedOrigins` is the implementation, and `Boot` puts it on `AuthContext.Origins`.

| Piece | What it does |
| --- | --- |
| `NewTrustedOrigins(origins)` | parses each entry and rejects one that is not an `http` or `https` origin, or has a path, a query or credentials. `Boot` returns that as a configuration error. |
| `IsTrusted(origin)` | exact match after lowercasing and removing the scheme's default port |
| `TrustedRedirect(v, target)` | whether a browser may be sent to `target` |

`TrustedRedirect` accepts a path on the application's own site or an absolute URL with a trusted origin:

| Target | Result | Why |
| --- | --- | --- |
| `/dashboard?tab=1` | accepted | a path on the same site |
| `https://app.example.com/welcome` | accepted, if the origin is listed | |
| `dashboard` | refused | relative to whatever page does the redirect |
| `//evil.example.com/x` | refused | a browser reads it as another host |
| `/\evil.example.com` | refused | some browsers treat `\` as `/` |
| `https://app.example.com@evil.example` | refused | the host is `evil.example` |
| `https://user@app.example.com/` | refused | credentials |
| `javascript:alert(1)` | refused | not `http` or `https` |
| `` (empty) | refused | a caller with an optional redirect checks for empty first |

A plugin checks a redirect URL when it receives it, before storing it. The magic link plugin checks at request time and not at verify: a bad URL is then a `400` for the request, and nothing unchecked is kept with the token.

### Origins match exactly
**Context:** An application may serve many subdomains, and listing each is tedious.
**Options considered:**
- *Wildcards (`https://*.example.com`).* Convenient. One forgotten or user-controlled subdomain becomes an open redirect, and matching rules are easy to get subtly wrong.
- *Exact match.* Nothing to misread.
**Decision:** Exact match for now.
**Revisit if:** an application has subdomains it can't list, such as one per tenant.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestMagicLinkRequestAndVerify` | `tests/plugins/magiclink_test.go` | both flows from code: unknown email, validation, what `SendLink` receives, a new link replacing the old, a link working once, email verified, the sign-in points' payload and result, the audit events |
| `TestMagicLinkRoutes` | same | the request route's identical answers for a known email, an unknown one and a failed send; validation statuses; the verify route's body and its `401` |
| `TestMagicLinkRequestsAreLimitedPerEmail` | same | the rule per email, from code, for known and unknown emails |
| `TestMagicLinkVerifyRefusalsAndSecondFactor` | same | a pending session, a changed email, a deleted user |
| `TestMagicLinkOptions` | same | the configuration errors, and a flow called before `Boot` |
| `TestTrustedOrigins` | `types/origins_test.go` | origin parsing and matching, and every row of the redirect table above |
