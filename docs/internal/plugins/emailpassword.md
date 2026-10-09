# Email and password plugin

This document explains how `plugins/emailpassword` fits into `Prepare` and `Boot`, and where its email and password rules live.

## What the plugin contributes

| `types.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `emailpassword`, no dependencies, no mount path | routes sit directly under the base path (`/sign-in/email`) |
| `Declare` | nothing | core declares the `auth.*` hook points (`CoreDeclareHookPoints`) and owns `users`, `accounts` and `sessions` |
| `Register` | nothing | the plugin fires points; it does not handle any |
| `Middlewares` | nothing | the session check is on the sign-out route only (`types.RequireSession`) |
| `Init` | checks `Options`, wraps the flows with `types.WithLifecycle` | runs in `Boot`, after the dispatcher exists |
| `Routes` | sign-up, sign-in, sign-out | reads the session manager, so it must run after `Init`; `Boot` guarantees that order |

The sign-in route answers through `types.WriteSignIn`, which writes the body every sign-in route shares and delivers the session token by the configured transport; see [`../sessions/token_transport.md`](../sessions/token_transport.md). The sign-up route answers `{"user": ...}` itself: it has no session.

`SignIn` returns a `*types.SignInResult`, the type every sign-in plugin hands to `auth.signIn.after`. `emailpassword.SignInResult` is an alias kept for callers. `Method` is `"emailpassword"`.

The plugin knows nothing about email verification. A user it signs up is created with `EmailVerified` false, and the email verification plugin, if installed, sends the link from its handler on `data.user.created`; see [`emailverification.md`](emailverification.md).

Compare with a plugin such as the example `auditlog`: that one declares a table in `Declare` and has a mount path. This one adds behaviour on top of core tables and declares nothing.

## The flows

- **Sign-up** (`Plugin.signUpBody`) validates the email and password with the plugin's `Options`, hashes the password with `AuthContext.Crypto.Passwords`, and creates the user and its credential account in one store transaction.
- **Sign-in** (`Plugin.signInBody`) verifies the password against the credential account and creates a session. It passes only the session's state to `SessionManager.Create`; the manager takes the IP address and user agent from the request on the context, so the flow also runs without a request. It applies no password rules, so a password accepted under an older policy still works.
- **Sign-out** (`SignOut`) revokes the session. The route, `handleSignOut`, then takes the token back from the client with `SessionManager.ClearToken`, which removes the cookie under a cookie transport. `SignOut` itself writes no response: see *Taking the token back* in [`../sessions/token_transport.md`](../sessions/token_transport.md).

`signUpBody` and `signInBody` are methods on the plugin, which `Init` wraps with `WithLifecycle`. `signUpBody` reads the options; `signInBody` reads none today and is a method so both flows have the same shape.

The wrapped flows are reached through two exported methods, `Plugin.SignUp(ctx, input)` and `Plugin.SignIn(ctx, creds)`. Each builds the flow's `HookContext` (`Plugin.operation`): the `AuthContext` kept by `Init`, the request found on `ctx` or nil, and `Values` copied from the operation `ctx` belongs to, if any. The route handlers call these methods with `rctx.Ctx`, so a route, a CLI and another plugin all enter the flow the same way. Called before `Boot` has run `Init`, they return a configuration error.

Before entering the wrapped flow, both put the email they were called with in `Values` under `hooks.HookValueEmail`, in its stored form (`publishEmail`, which uses `store.NormalizeEmail`). A rate-limit rule on `auth.signUp.before` or `auth.signIn.before` keys on it, since a rule's `KeyFunc` does not get the payload. A call without an email leaves no entry, and `publishEmail` removes one copied from an enclosing operation, so a rule per email does not apply to that call.

### Sign-in's input

`Plugin.SignIn` takes an `EmailAndPasswordCredentials`: `Email`, `Password` and an `Extra` map. `signInBody` reads the two fields. `Extra` exists for handlers on `auth.signIn.before`.

The struct implements `behemoth.Serializable`, so `WithLifecycle` converts it with its own methods and not with a JSON round trip:

| Step | Method | What happens |
| --- | --- | --- |
| route to struct | `FromMap(body)` | `handleSignIn` decodes the body into a `behemoth.M` first, so unknown fields survive |
| struct to payload | `ToMap()` | a copy of `Extra`, then `email` and `password` set from the fields |
| payload to struct | `FromMap(payload)` | `email` and `password` fill the fields, every other key goes to a new `Extra` |

Rules that follow from the two methods:

- The payload is flat. `Extra: {"captchaToken": "x"}` is `payload["captchaToken"]`, the same lookup a handler uses on `auth.signUp.before`.
- The fields win. An `Extra` key named `email` or `password` is overwritten in `ToMap`, so a caller can't hand handlers one email and the flow another.
- The payload is a copy. A handler's write does not reach the map the caller passed.
- `Extra` is replaced, not merged, on the way back. A key a handler deleted is gone, and `Extra` is nil when no other key is left.
- A missing or null `email` or `password` becomes an empty string, which sign-in refuses with `invalid_credentials`. A value of another type is a validation error (`400`), from the route's body and from a handler's rewrite alike.

`SignOut` is an exported function that takes a `HookContext` and only uses the `AuthContext` on it, so other plugins can call it. It turns the context into one operation with `types.AsOperation`.

## Limits to know

- `[Not built]` Password reset, password change and email verification. They would declare their token kinds in `Declare`.
- `[Not built]` Rehash on sign-in. `PasswordHasher.NeedsRehash` exists but sign-in does not call it.
- Sign-up returns a typed error (`behemotherr.DomainError`) to the router, which maps it with `RouterConfig.ErrorMapper`. This is how a data hook's veto on `data.user.beforeCreate` reaches the client with its own status and message; `signUpBody` also fires `auth.signUp.failed` with `rejectedByHook` for it (`isRejection`). Sign-up's own untyped rejections are a `400`.
- Sign-in and sign-out return every error to the router unchanged (`handleSignIn`, `handleSignOut`). See *Sign-in's refusals are typed* below. The session check in front of sign-out, `types.RequireSession`, does the same: see *`RequireSession` returns its refusals* in [`../sessions/token_transport.md`](../sessions/token_transport.md).
- `Options.ValidateEmail` and `ValidatePassword` errors are replaced by `invalid email` and `invalid password` in the response, so a custom message does not reach the client.

### The email and password rules belong to the plugin
**Context:** Sign-up read `AuthContext.Validator` and `AuthContext.PasswordOptions`. `Boot` set neither and `BootConfig` had no field for them, so a booted application panicked on the first sign-up. Only this plugin read them.
**Options considered:**
- *Wire both through `BootConfig`, with a default validator in core.* Every plugin can read one shared policy. An application without passwords (OAuth or magic links only) still carries a password policy, and core gains a `Validator` interface with one consumer.
- *Make them options of the plugin: `emailpassword.New(Options)`.* The dependency is visible where it is used, the zero value has defaults, and `AuthContext` loses two fields. A second plugin that sets passwords can't read the policy from the `AuthContext`.
**Decision:** The second option. `types.Validator`, `types.PasswordOptions` and the two `AuthContext` fields are removed. The hasher was never a policy choice of the plugin: it comes from `AuthContext.Crypto.Passwords`, which `Boot` builds from `BootConfig.Crypto`. The default email check is `utils.IsValidEmail`, a plain function other plugins can call. Plugins that set passwords are expected to depend on this one and go through it.
**Revisit if:** plugins that don't depend on `emailpassword` need to set passwords. A shared policy on `AuthContext` would then be justified.

### Sign-in takes a struct with an `Extra` map
**Context:** Sign-up takes a `behemoth.M`, so a field a plugin adds to the request (an invite code) reaches `auth.signUp.before`. Sign-in decoded the body into a two-field struct, so a captcha token or a device id was gone before the before chain ran. A handler could not read it from `hctx.Request` either, since the body had been consumed, and a caller of `Plugin.SignIn` had no way to pass it.
**Options considered:**
- *Take a `behemoth.M`, like sign-up.* One convention and the least code. `SignIn(ctx, behemoth.M{"emial": ...})` compiles, the two required values are checked at run time only, and the exported signature changes.
- *Add `Extra behemoth.M` and keep the JSON round trip.* Small. Handlers get `payload["extra"]["captchaToken"]` on sign-in and `payload["inviteCode"]` on sign-up, so one captcha handler for both points needs two lookups.
- *Add `Extra` and implement `behemoth.Serializable`.* The required input stays typed, the payload is flat, and `Plugin.SignIn` keeps its signature. It costs two methods and a rule for a key that collides with a field.

**Decision:** The third. A fixed shape checked by the compiler is preferred over a map, and sign-in's shape is fixed: two required values and an open tail. Sign-up keeps its map because its profile fields are open-ended. Other plugins with a flow of fixed input are expected to follow the same shape: a struct for what the flow reads, an `Extra` map for what only handlers read, and `ToMap`/`FromMap` that keep the payload flat.
**Revisit if:** several plugins repeat the same two methods. A helper in `types` that flattens a struct with an `Extra` field would then be worth having.

### Sign-in's refusals are typed
**Context:** `signInBody` returned `errors.New("invalid email or password")` for an unknown email, a user without a credential account and a wrong password. An untyped error could therefore be a wrong password or a broken system, and `handleSignIn` could not tell them apart. It wrapped every error in a validation error, so a database outage was answered with `400` and never reached the router's log. `handleSignOut` wrote its own `500` with `err.Error()` as the body, which sent internal error text to the client.
**Options considered:**
- *Return typed errors from the handlers and keep the untyped refusal.* The router maps an untyped error to `500`, so a wrong password would become a `500`.
- *Make the refusal a typed error and return everything to the router.* `errInvalidCredentials` is an unauthorized error (`behemotherr.NewUnauthorized`) with the code `invalid_credentials`. After that, every error out of `SignIn` is a typed rejection or a failure of the system, and the handler has nothing to decide.
**Decision:** The second, for sign-in. Sign-out needed only the first half: `SignOut` already returned typed errors. Both handlers now end in `return err`.

What the router does with each error:

| Error from the flow | Status | Body |
| --- | --- | --- |
| `errInvalidCredentials` (all three refusals) | `401` | `{"error": "invalid email or password", "code": "invalid_credentials"}` |
| a hook handler's typed rejection | the status of its category | its public message and code |
| a rate limit | `429` with `Retry-After` | the rate limit message |
| a database error, or any category without a status | `500` | the category's public message, never the error's text |
| an untyped error (a hook handler's `errors.New`, an unexpected failure) | `500` | `{"error": "internal server error"}` |

The three refusals share one code and one message on purpose: a different answer for an unknown email would tell a caller which addresses have an account. The failure code a hook handler sees on `auth.signIn.failed` still tells them apart (`userNotFound`, `noCredentialAccount`, `invalidCredentials`).

Two changes a client can observe: a wrong password is a `401` where it was a `400`, and an untyped error from a handler on a sign-in point is a `500` where it was a `400`. The second matches what the hook docs ask for, a typed error from a handler that rejects.

`[Limit]` Sign-up still has untyped refusals (`invalid email`, `user already exists`), answered with `400` by `handleSignUp` itself. Giving them types would let that handler end in `return err` as well.
