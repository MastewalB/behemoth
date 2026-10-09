# Magic link

The `magiclink` plugin signs a user in with a link sent to their email address. There is no password. The user asks for a link, opens it, and your page hands the link's token back to Behemoth, which creates the session.

The plugin does not send email. It hands the link to the mail sender you give Behemoth at `Boot`.

## How it works

| Step | Who | What happens |
| --- | --- | --- |
| 1 | client | posts an email to `POST /sign-in/magic-link` |
| 2 | plugin | finds the user, issues a single-use token, and hands the link to your mail sender |
| 3 | you | send the message |
| 4 | user | opens the link, which is a page of your application: `https://app.example.com/auth/magic?token=...` |
| 5 | your page | posts the token to `POST /magic-link/verify` |
| 6 | plugin | consumes the token and creates a session |

The link points at your page and not at Behemoth, and step 5 is a `POST`. Mail scanners and link previews open the links in a message. If opening the link were enough to sign in, the scanner would use it up before the user got to it.

## Setup

Pass the plugin to `Prepare`. It uses the core `users`, `sessions` and `tokens` tables and has none of its own.

```go
import "github.com/MastewalB/behemoth/plugins/magiclink"

plugin := magiclink.New(magiclink.Options{
	LinkURL: "https://app.example.com/auth/magic",
})

app, err := bmth.Prepare([]types.Plugin{plugin}, bmth.PrepareConfig{})
// ...
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	Router: types.RouterConfig{TrustedOrigins: []string{"https://app.example.com"}},
	Mail: types.MailConfig{
		Sender: types.MailSenderFunc(func(ctx context.Context, msg types.MailMessage) error {
			return mailQueue.Enqueue(ctx, msg.To, "Your sign-in link", msg.URL)
		}),
	},
	// ...
})
```

The plugin's name is `magiclink` (`magiclink.PluginName`). It works next to the `emailpassword` plugin or without it.

## Options

| Field | Default | Meaning |
| --- | --- | --- |
| `SendInBackground` | false | Whether the request returns without waiting for the mail sender. See [Sending the link](#sending-the-link). |
| `LinkURL` | required | The page of your application the link points to. Absolute, `http` or `https`. The plugin adds the token as the `token` query parameter and keeps any query the URL already has. |
| `TTL` | 15 minutes | How long a link works. `TokenConfig.TTLOverrides[types.TokenKindMagicLink]` takes precedence. |
| `RequestLimit` | 5 per 15 minutes | Link requests allowed per email. See [Rate limits](#rate-limits). |

A missing mail sender (`BootConfig.Mail.Sender`), a `LinkURL` that is not an absolute URL, and a negative `TTL` are configuration errors from `Boot`.

## Sending the link

The link is handed to your mail sender as a `types.MailMessage` with `Kind` set to `types.MailMagicLink`. [Mail](mail.md) describes the message and the sender.

`Metadata` on the message is whatever the request carried under `metadata`. The plugin passes it through without reading or storing it. Use it for what your message needs: a locale, a template name, the name of the device that asked.

- **From the route, `Metadata` is what the client sent.** Treat it like any other request input. A handler on `auth.magicLink.beforeRequest` can set or remove entries before the sender sees them.
- **By default the request waits for your sender.** A returned error revokes the link; the route still answers `200` (see below) and the error is logged at Error under the `magiclink` component. The sender is only called for an email that has an account, so a slow one makes that request slower than one for an unknown email, which shows which addresses are registered.
- **With `SendInBackground` the request does not wait.** It returns once the message is queued. A send that fails later is logged by the mailer, and the link stays valid until it expires. Choose this when your sender talks to a mail provider directly.

## Routes

The routes sit directly under the router's base path.

| Route | Body | Result |
| --- | --- | --- |
| `POST /sign-in/magic-link` | `email`, and optionally `redirectURL` and `metadata` (an object) | `200` with `{"status": "ok"}` |
| `POST /magic-link/verify` | `token` | `200` with `{"user": ..., "redirectURL": "..."}`, and the session token written the way `SessionConfig.Transport` says. `{"status": "requires_second_factor", "redirectURL": "..."}` when a second factor is pending. |

**The request route answers the same whether or not the email has an account.** An unknown email, a link that could not be issued and a failed send are all a `200` with the same body, so the response does not show which addresses are registered. The plugin does not create accounts: an unknown email gets no link.

### Error responses

| Route | When | Status | Code |
| --- | --- | --- | --- |
| both | the body is not valid JSON | `400` | `request_validation_error` |
| request | `email` is missing or not an email address | `400` | `email_invalid_input` |
| request | `redirectURL` is not allowed | `400` | `redirect_url_invalid_input` |
| request | `metadata` is not an object | `400` | `metadata_invalid_input` |
| verify | `token` is missing | `400` | `token_invalid_input` |
| verify | the link is unknown, expired, already used, or replaced by a newer one | `401` | `invalid_magic_link` |
| both | too many requests | `429` with `Retry-After` | `rate_limited` |
| both | a hook handler rejected the request with a typed error | the error's status | the error's code |

Verify gives one answer for every link it refuses, so the response does not tell an expired link from one that never existed.

## The redirect URL

A request can say where the user should land after signing in. The plugin checks the URL when the link is requested, keeps it with the token, and returns it from verify. Your page does the redirect.

Two forms are accepted:

- a path on your own site, starting with one `/`: `/dashboard?tab=1`
- an absolute `http` or `https` URL whose origin is in `RouterConfig.TrustedOrigins`

Anything else is a `400`, including `//other.example.com` and a URL with credentials in it. An origin is a scheme, a host and an optional port, and it is matched exactly: `https://app.example.com` does not cover `http://app.example.com` or `https://www.app.example.com`. List each one. An entry that is not an origin is a configuration error from `Boot`.

Without the check, anyone could mail your users a real sign-in link that ends on a site of their choosing.

## What a link does

- **It works once.** The token is consumed at verify, also when a later step refuses the sign-in (a second-factor handler's rejection, a session limit). The user asks for a new link.
- **A new link replaces the old one.** A user has one live link. Requesting again revokes the earlier ones.
- **It marks the email as verified.** Following the link shows the user controls the address, so `EmailVerified` is set on a user who did not have it.
- **It is tied to the address it was sent to.** If the user's email changes before the link is used, the link is refused.
- **It goes with the user.** `Store.DeleteUser` removes a user's links.

## Calling the flows from code

Both flows are exported for a CLI, a job or another plugin.

```go
result, err := plugin.RequestLink(ctx, magiclink.LinkRequest{
	Email:       "ada@example.com",
	RedirectURL: "/dashboard",
	Metadata:    behemoth.M{"locale": "fr"},
})

signIn, err := plugin.Verify(ctx, rawToken)
// signIn.User, signIn.Session, signIn.RawToken, signIn.RedirectURL
```

- `RequestLink` reports what the route hides. It returns `magiclink.ErrNoAccount` for an unknown email (check with `errors.Is`), and the error of a failed issue or send.
- `Verify` returns the raw session token. Delivering it is up to you; the route uses `SessionManager.WriteToken`.
- Pass the context of the request being handled when there is one, so sessions record the client's address and handlers get the request.
- Called before `Boot`, both return a configuration error.

## Hooks

Verifying a link is a sign-in. It fires the same points as a password sign-in, so a handler written for one sees the other:

| Point | What the handler gets |
| --- | --- |
| `auth.signIn.before` | payload `method` (`"magiclink"`) and, when the token names one, `email`. Veto only. The token is not in the payload. |
| `auth.signIn.credentialsVerified` | `HookValueUserID`. Set `requireStepUp` to make the session pending. |
| `auth.signIn.after` | a `*types.SignInResult` with `Method` set to `"magiclink"` |
| `auth.signIn.failed` | codes `invalidMagicLink`, `userNotFound`, `emailChanged`, `secondFactorRejected`, `rejectedByHook` |

The plugin declares three points of its own around a link request:

| Point | Phase | What the handler gets |
| --- | --- | --- |
| `auth.magicLink.beforeRequest` (`magiclink.HookRequestBefore`) | before | payload `email`, `redirectURL`, `metadata`. The returned payload becomes the request's input. |
| `auth.magicLink.afterRequest` (`magiclink.HookRequestAfter`) | after | a `*magiclink.LinkResult`: user id, email, token id, expiry. Not the token. |
| `auth.magicLink.requestFailed` (`magiclink.HookRequestFailed`) | failed | codes `userNotFound`, `issueFailed`, `sendFailed`, `rejectedByHook` |

The after and failed points are audited under their point names. A captcha check belongs on `auth.magicLink.beforeRequest`: read the answer from `payload["metadata"]` and return an error to refuse.

Issuing and consuming the token also fire the token manager's points (`token.beforeIssue`, `token.afterIssue`, `token.consumed`, `token.failed`) with the kind `magic_link`.

## Rate limits

The plugin declares three rules.

| Rule | Limits | Default |
| --- | --- | --- |
| `magiclink.RuleRequestRoute` | requests to `POST /sign-in/magic-link` per client address | 10 a minute |
| `magiclink.RuleVerifyRoute` | requests to `POST /magic-link/verify` per client address | 10 a minute |
| `magiclink.RuleRequestEmail` | link requests per email | `Options.RequestLimit`, 5 per 15 minutes |

The rule per email is attached to `auth.magicLink.beforeRequest` and not to the route, so it also holds for `RequestLink` called from code. It keeps one address from being sent link after link. It counts requests for unknown emails too, so a `429` does not show whether the address has an account.

## Not built

- **Sign-up by link.** An unknown email gets no link and no account.
- **Wildcards in trusted origins.** Each origin is listed.
