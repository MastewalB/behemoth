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

Compare with a plugin such as the example `auditlog`: that one declares a table in `Declare` and has a mount path. This one adds behaviour on top of core tables and declares nothing.

## The flows

- **Sign-up** (`Plugin.signUpBody`) validates the email and password with the plugin's `Options`, hashes the password with `AuthContext.Crypto.Passwords`, and creates the user and its credential account in one store transaction.
- **Sign-in** (`Plugin.signInBody`) verifies the password against the credential account and creates a session. It passes only the session's state to `SessionManager.Create`; the manager takes the IP address and user agent from the request on the context, so the flow also runs without a request. It applies no password rules, so a password accepted under an older policy still works.
- **Sign-out** (`SignOut`) revokes the session.

`signUpBody` and `signInBody` are methods on the plugin, which `Init` wraps with `WithLifecycle`. `signUpBody` reads the options; `signInBody` reads none today and is a method so both flows have the same shape.

The wrapped flows are reached through two exported methods, `Plugin.SignUp(ctx, input)` and `Plugin.SignIn(ctx, creds)`. Each builds the flow's `HookContext` (`Plugin.operation`): the `AuthContext` kept by `Init`, the request found on `ctx` or nil, and `Values` copied from the operation `ctx` belongs to, if any. The route handlers call these methods with `rctx.Ctx`, so a route, a CLI and another plugin all enter the flow the same way. Called before `Boot` has run `Init`, they return a configuration error.

`SignOut` is an exported function that takes a `HookContext` and only uses the `AuthContext` on it, so other plugins can call it. It turns the context into one operation with `types.AsOperation`.

## Limits to know

- `[Not built]` Password reset, password change and email verification. They would declare their token kinds in `Declare`.
- `[Not built]` Rehash on sign-in. `PasswordHasher.NeedsRehash` exists but sign-in does not call it.
- Sign-up returns a typed error (`behemotherr.DomainError`) to the router, which maps it with `RouterConfig.ErrorMapper`. This is how a data hook's veto on `data.user.beforeCreate` reaches the client with its own status and message; `signUpBody` also fires `auth.signUp.failed` with `rejectedByHook` for it (`isRejection`). Sign-up's own untyped rejections are a `400`. Sign-in and sign-out still map every flow error to a validation error or a `500`.
- `Options.ValidateEmail` and `ValidatePassword` errors are replaced by `invalid email` and `invalid password` in the response, so a custom message does not reach the client.

### The email and password rules belong to the plugin
**Context:** Sign-up read `AuthContext.Validator` and `AuthContext.PasswordOptions`. `Boot` set neither and `BootConfig` had no field for them, so a booted application panicked on the first sign-up. Only this plugin read them.
**Options considered:**
- *Wire both through `BootConfig`, with a default validator in core.* Every plugin can read one shared policy. An application without passwords (OAuth or magic links only) still carries a password policy, and core gains a `Validator` interface with one consumer.
- *Make them options of the plugin: `emailpassword.New(Options)`.* The dependency is visible where it is used, the zero value has defaults, and `AuthContext` loses two fields. A second plugin that sets passwords can't read the policy from the `AuthContext`.
**Decision:** The second option. `types.Validator`, `types.PasswordOptions` and the two `AuthContext` fields are removed. The hasher was never a policy choice of the plugin: it comes from `AuthContext.Crypto.Passwords`, which `Boot` builds from `BootConfig.Crypto`. The default email check is `utils.IsValidEmail`, a plain function other plugins can call. Plugins that set passwords are expected to depend on this one and go through it.
**Revisit if:** plugins that don't depend on `emailpassword` need to set passwords. A shared policy on `AuthContext` would then be justified.
