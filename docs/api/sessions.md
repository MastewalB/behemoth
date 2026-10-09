# Sessions

A sign-in creates a session and gives the client a token for it. The client sends the token with later requests, and Behemoth resolves it back to the session. This page covers the session settings, how the token travels, and what a sign-in route answers with.

## Configuration

Sessions are configured with `BootConfig.Session`. Every field is optional.

```go
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	Session: types.SessionConfig{
		ExpiresIn: 24 * time.Hour,
		Transport: types.TransportHeader,
	},
	// ...
})
```

| Field | Default | Meaning |
| --- | --- | --- |
| `Transport` | `types.TransportCookie` | Where the token travels. See [Transports](#transports). |
| `CookieName` | `session_token` | The cookie's name, for the transports that use one. |
| `ExpiresIn` | 7 days | How long a session lasts. |
| `PendingExpiresIn` | 10 minutes | How long a session lasts while it waits for a second factor. |
| `UpdateAge` | 0, off | Rolling expiration: a session in use is extended by `ExpiresIn` once less than `UpdateAge` is left of it. At zero a session ends `ExpiresIn` after its sign-in, however much it is used. Keep it well below `ExpiresIn`: a value that is not smaller extends the session, with a database write, on every request. |
| `FreshAge` | 15 minutes | How long after a sign-in a session counts as fresh. See [Fresh sessions](#fresh-sessions). |
| `MaxConcurrent` | 0, no limit | Live sessions allowed per user. |
| `EvictOldestOnLimit` | false | At the limit, end the oldest session to make room. When false, the new sign-in is refused. |
| `CaptureIPAndAgent` | false | Record the client's IP address and user agent on the session. |

A `Transport` that is not one of the four values, and a negative duration, are configuration errors from `Boot`.

## Transports

The transport names where the token travels in both directions: how a sign-in hands it to the client, and where the client's requests carry it.

| `Transport` | The sign-in response has the token in | A request carries it in |
| --- | --- | --- |
| `types.TransportCookie` | a `Set-Cookie` header | the cookie |
| `types.TransportHeader` | the `Set-Auth-Token` header | `Authorization: Bearer <token>` |
| `types.TransportBody` | the JSON body, under `token` | `Authorization: Bearer <token>` |
| `types.TransportBoth` | the cookie and `Set-Auth-Token` | either |

**Cookie.** The browser stores the token and sends it by itself. The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, with the path `/`, and expires with the session. Scripts on the page can't read it. This is the choice for a browser application served from the same site as the API.

**Header.** The client reads the token from `Set-Auth-Token`, keeps it, and sends it as a bearer token. This suits mobile apps, command-line tools and other servers.

```bash
curl -i -X POST localhost:8080/api/auth/sign-in/email -d '{"email":"ada@example.com","password":"correct horse"}'
# HTTP/1.1 200 OK
# Set-Auth-Token: r8_x6fau4053kWPOukmnuUFxoY8iz...
# {"user":{"id":"8b41...","email":"ada@example.com", ...}}

curl -X POST localhost:8080/api/auth/sign-out -H 'Authorization: Bearer r8_x6fau4053kWPOukmnuUFxoY8iz...'
```

A browser script on another origin can read a response header only when your CORS configuration exposes it. With the header transport and a browser client, add `Set-Auth-Token` to `Access-Control-Expose-Headers`. Without it the sign-in succeeds and the script sees no token.

**Body.** The token is a field of the sign-in response's JSON. The client sends it back the same way as with the header transport, as a bearer token; only the delivery differs. Choose it when reading a response header is awkward for your client, a cross-origin browser script for example.

```json
{"user": {"id": "8b41...", "email": "ada@example.com"}, "token": "r8_x6fau4053kWPOukmnuUFxoY8iz..."}
```

**Both.** A sign-in sets the cookie and the header, and a request may carry either. It is for an application with browser and non-browser clients, or one moving from one to the other.

There is no combination with the body. A token is never read from a request's body.

## The sign-in response

Every route that signs a user in answers with the same JSON, whichever plugin it belongs to:

| Case | Body |
| --- | --- |
| signed in | `{"user": {...}}` |
| a second factor is pending | `{"status": "requires_second_factor"}` |
| either, with `TransportBody` | the same, plus `"token": "..."` |

- A plugin can add fields of its own next to these. The magic link plugin adds `redirectURL`.
- A pending session's token is delivered like any other. The client presents it together with the second factor.
- The response has `Cache-Control: no-store`.
- Sign-up answers `{"user": {...}}` too. It creates no session, so it has no token.

### The user

A user is keyed by its column names, the same names a request uses:

```json
{
  "id": "8b41bcc4-81f3-46a4-920a-9326d9cb01a1",
  "email": "ada@example.com",
  "username": "",
  "firstname": "Ada",
  "lastname": "",
  "email_verified": false,
  "image_url": "",
  "created_at": "2026-10-09T09:21:25.186568934Z",
  "updated_at": "2026-10-09T09:21:25.186568934Z"
}
```

These are the public columns of `users`. A column a plugin added to the table appears next to them, under its own name, if the plugin declared it public, and not at all otherwise. See [What a client sees of a user](core-tables.md#what-a-client-sees-of-a-user).

## Protecting your own routes

```go
{Method: http.MethodGet, Path: "/me", Handler: me,
	Middlewares: []types.Middleware{types.RequireSession(ac.SessionManager)}},
```

`types.RequireSession` reads the token where the transport says, answers `401` without a valid active session, and puts the session in `rctx.Values["session"]` and its id in `rctx.Values["sessionID"]`.

### Fresh sessions

A session is fresh for `FreshAge` after its sign-in, or after its second factor. `types.RequireFreshSession` is `RequireSession` plus that check, for a route that changes something sensitive: the account's email, a password, a deletion. A session that is valid and too old gets `401` with the code `session_not_fresh`, and the client asks the user to sign in again.

```go
Middlewares: []types.Middleware{types.RequireFreshSession(ac.SessionManager)},
```

Nothing refreshes a session in place yet. Signing in again is how a user gets a fresh one.

## Writing a sign-in route

A plugin that signs users in builds a `types.SignInResult` and hands it to `types.WriteSignIn`:

```go
session, rawToken, err := ac.SessionManager.Create(rctx.Ctx, user.ID, types.SessionMeta{State: types.SessionActive})
if err != nil {
	return err
}
result := &types.SignInResult{User: user, Session: session, RawToken: rawToken, Method: "myplugin"}
return types.WriteSignIn(rctx, result, nil) // the body above, and the token by the configured transport
```

`WriteSignIn` is what makes the token arrive. If you write the response yourself, call `ac.SessionManager.WriteToken(rctx, rawToken, session)`: it sets the cookie or the header, and returns `true` when the transport is the body, in which case putting the token in your JSON is up to you.

A flow called from code, such as `emailpassword.Plugin.SignIn`, returns the raw token in its result and delivers nothing. The caller decides what to do with it.
