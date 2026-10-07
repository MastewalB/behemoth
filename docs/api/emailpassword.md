# Email and password

The `emailpassword` plugin adds sign-up, sign-in and sign-out with an email address and a password.

## Setup

Pass the plugin to `Prepare`. It needs no tables of its own: users, accounts and sessions are core tables.

```go
import "github.com/MastewalB/behemoth/plugins/emailpassword"

plugin := emailpassword.New(emailpassword.Options{})

app, err := bmth.Prepare([]types.Plugin{plugin}, bmth.PrepareConfig{})
// ...
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{ /* ... */ })
```

The plugin's name is `emailpassword` (`emailpassword.PluginName`). Use it in `PluginMeta.Dependencies` to build on the plugin, and in `HookOptions.Before`/`After` to order a handler around it.

## Options

The zero value works. Every field is optional.

| Field | Default | Meaning |
| --- | --- | --- |
| `MinPasswordLength` | 8 | Shortest password accepted at sign-up, in characters. |
| `MaxPasswordLength` | 128 | Longest password accepted at sign-up, in characters. |
| `ValidatePassword` | none | An extra check on a new password, run after the length check. Return an error to reject it. |
| `ValidateEmail` | `utils.IsValidEmail` | The check on the email at sign-up. It receives the address trimmed and lowercased. |

```go
plugin := emailpassword.New(emailpassword.Options{
	MinPasswordLength: 12,
	ValidatePassword: func(password string) error {
		if isBreached(password) {
			return errors.New("this password has appeared in a data breach")
		}
		return nil
	},
})
```

- The rules apply at sign-up only. Raising `MinPasswordLength` later does not lock out users whose password is shorter; they still sign in.
- A minimum above the maximum, or a negative limit, is a configuration error from `Boot`.
- Passwords are hashed with the hasher configured in `BootConfig.Crypto`. The plugin has no hashing option of its own.
- The sign-up response says `invalid email` or `invalid password`. The text of the error your function returns is not sent to the client.

## Routes

The routes sit directly under the router's base path.

| Route | Body | Result |
| --- | --- | --- |
| `POST /sign-up/email` | `email`, `password`, and optionally `username`, `firstname`, `lastname`, `image_url` | `201` with the user. Other fields in the body are ignored. |
| `POST /sign-in/email` | `email`, `password` | `200` with the user, and the session token written the way `SessionConfig.Transport` says. `{"status": "requires_second_factor"}` when a plugin asked for a second step. |
| `POST /sign-out` | none; needs a valid session | `200`, and the session is revoked. |

### Error responses

An error response is JSON with an `error` message and, for most errors, a `code`.

| Route | When | Status | Body |
| --- | --- | --- | --- |
| `POST /sign-in/email` | the body is not valid JSON | `400` | `{"error": "request validation error", "code": "request_validation_error"}` |
| `POST /sign-in/email` | unknown email, wrong password, or a user who has no password | `401` | `{"error": "invalid email or password", "code": "invalid_credentials"}` |
| `POST /sign-in/email`, `POST /sign-out` | a hook handler rejected the request with a typed error | the error's status | the error's public message and code |
| any | too many requests | `429` with a `Retry-After` header | `{"error": "too many requests, please try again later", "code": "rate_limited"}` |
| any | Behemoth failed (the database is down, for example) | `500` | a generic message; the error's own text is logged, not sent |

Sign-in gives the same answer for an unknown email and a wrong password, so the response does not show which addresses have an account.

A handler on a sign-in or sign-out hook point that rejects a request should return one of the `errors` package's types. An untyped error (`errors.New`) is treated as a failure of the system: the client gets a `500` and the error is logged.

## Hook points

## Calling the flows from code

The routes are thin wrappers around two methods on the plugin. Use them from a CLI, a job, a test or another plugin, after `Boot`:

```go
user, err := plugin.SignUp(ctx, behemoth.M{
	"email":    "ada@example.com",
	"password": "correct horse battery",
})

result, err := plugin.SignIn(ctx, emailpassword.EmailAndPasswordCredentials{
	Email: "ada@example.com", Password: "correct horse battery",
})
// result.User, result.Session, result.RawToken
```

- They fire the same hook points as the routes, with the same payloads.
- `SignUp` stores `email`, `password` and the profile fields listed above. Other keys in the input are not stored, but handlers on `auth.signUp.before` see them, which is how a plugin accepts a field of its own (an invite code, for example).
- Pass the context of the request you are handling when there is one. Hook handlers get the request from it, and the session records its IP address and user agent. With any other context, `hctx.Request` is nil and the session has neither.
- `SignIn` returns the raw session token. Delivering it (a cookie, a header) is up to you; the route uses `SessionManager.WriteToken`.
- Called before `Boot`, both return a configuration error.
- `SignIn` returns a typed error for a refused credential, so you can tell it from a failure:

```go
result, err := plugin.SignIn(ctx, creds)
switch {
case err == nil:
	// signed in
case behemotherr.IsCode(err, emailpassword.ErrorCodeInvalidCredentials):
	// unknown email, wrong password, or no password: ask again
default:
	// a hook's rejection, a rate limit, or a failure such as a database outage
}
```

`emailpassword.SignOut(hctx, sessionID)` revokes a session and fires the sign-out points.

## Rejecting a sign-up from a hook

A hook handler can reject a sign-up with its own status and message. Return a typed error from a handler on `auth.signUp.before`, `data.user.beforeCreate` or `data.user.afterCreate`:

```go
reg.OnBefore(hooks.HookUserBeforeCreate, func(hctx *types.HookContext, row behemoth.M) (behemoth.M, error) {
	if blocked(row[models.UserEmail]) {
		return nil, behemotherr.NewInvalidInputError("signup", "user", "this email domain is not allowed", nil)
	}
	return row, nil
}, nil)
```

The client gets the status of the error's category (`400` here) and its public message, and `auth.signUp.failed` fires with code `rejectedByHook`. An untyped error (`errors.New`) from a data hook also stops the sign-up, but the client gets `user create failed` and no failed point fires.

With `SessionConfig.CaptureIPAndAgent` on, the session created at sign-in records the client's IP address and user agent. The address is resolved with `RouterConfig.TrustedProxies` and `ClientIPHeader`, so behind a load balancer it is the client's and not the proxy's.

The plugin fires the `auth.signUp.*`, `auth.signIn.*` and `auth.signOut.*` points. See [hooks.md](hooks.md#flow-points-tier-2) for their payloads and failure codes.

## Not built yet

Password reset, password change and email verification. A plugin that adds one of them should depend on `emailpassword` so that the password rules stay in one place.
