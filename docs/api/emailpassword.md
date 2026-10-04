# Email and password

The `emailpassword` plugin adds sign-up, sign-in and sign-out with an email address and a password.

## Setup

Pass the plugin to `Prepare`. It needs no tables of its own: users, accounts and sessions are core tables.

```go
import "github.com/MastewalB/behemoth/plugins/emailpassword"

plugin := emailpassword.New(emailpassword.Options{})

app, err := binit.Prepare([]types.Plugin{plugin}, binit.PrepareConfig{})
// ...
ac, err := binit.Boot(ctx, app, db, binit.BootConfig{ /* ... */ })
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

## Hook points

The plugin fires the `auth.signUp.*`, `auth.signIn.*` and `auth.signOut.*` points. See [hooks.md](hooks.md#flow-points-tier-2) for their payloads and failure codes.

## Not built yet

Password reset, password change and email verification. A plugin that adds one of them should depend on `emailpassword` so that the password rules stay in one place.
