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
| `UpdateAge` | 0, off | Rolling expiration: a session in use is extended by `ExpiresIn` once less than `UpdateAge` is left of it. At zero a session ends `ExpiresIn` after its sign-in, however much it is used. Keep it well below `ExpiresIn`: a value that is not smaller extends the session, with a database write, on every request. See [Rolling expiration](#rolling-expiration). |
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

**Cookie.** The browser stores the token and sends it by itself. The cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, with the path `/`, and expires with the session. When [rolling expiration](#rolling-expiration) extends the session, the cookie is set again with the new date. Scripts on the page can't read it, and can't delete it either: the sign-out response removes it. See [Signing out](#signing-out). This is the choice for a browser application served from the same site as the API.

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

## Rolling expiration

By default a session ends `ExpiresIn` after its sign-in, however much it is used. Set `UpdateAge` to keep an active user signed in: a session that is used when less than `UpdateAge` is left of it is extended by `ExpiresIn` from that moment.

```go
Session: types.SessionConfig{
	ExpiresIn: 7 * 24 * time.Hour,
	UpdateAge: 24 * time.Hour, // used in its last day, a session gets seven more
},
```

A session is "used" by a request to a route behind `types.RequireSession` or `types.RequireFreshSession`. That is where the extension happens. A request that reaches no such route extends nothing.

Only the request that crosses the threshold writes to the database. The others cost nothing extra: with a session cache (`BootConfig.KV`), a request whose session is not due is checked without a database query.

What the client sees depends on the transport:

| `Transport` | The response of the request that extended the session | What the client does |
| --- | --- | --- |
| `types.TransportCookie` | sets the cookie again, with the same token and the new expiry | nothing |
| `types.TransportHeader`, `types.TransportBody` | has nothing to add | nothing. The client keeps the token without a date, and the server decides when it ends. |
| `types.TransportBoth` | sets the cookie again if the request carried the token in the cookie | nothing |

For a route of yours behind `RequireSession`, here `/me`, and a session that is due:

```bash
curl -i localhost:8080/api/auth/me --cookie 'session_token=r8_x6fau4053kWPOukmnuUFxoY8iz...'
# HTTP/1.1 200 OK
# Cache-Control: no-store
# Set-Cookie: session_token=r8_x6fau4053kWPOukmnuUFxoY8iz...; Path=/; Expires=Fri, 16 Oct 2026 18:16:16 GMT; HttpOnly; Secure; SameSite=Lax
```

- **The response that sets the cookie is marked `Cache-Control: no-store`**, also when your handler set another value. It carries the session token, and a cache that stored it could hand the token to someone else. This affects one response per extension, not every response of the route.
- The token does not change. Only the cookie's date does.
- `FreshAge` is not affected. An extended session is no fresher than before: see [Fresh sessions](#fresh-sessions).

## Signing out

`POST /sign-out` of the `emailpassword` plugin revokes the session the request carries. What happens to the token on the client depends on the transport:

| `Transport` | The sign-out response | What the client does |
| --- | --- | --- |
| `types.TransportCookie` | replaces the cookie with an empty one that has expired, so the browser drops it | nothing |
| `types.TransportHeader`, `types.TransportBody` | has nothing to remove | discards the token it kept |
| `types.TransportBoth` | removes the cookie | discards the token if it kept one from the header |

```bash
curl -i -X POST localhost:8080/api/auth/sign-out --cookie 'session_token=r8_x6fau4053kWPOukmnuUFxoY8iz...'
# HTTP/1.1 200 OK
# Set-Cookie: session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax
# {"status":"signed_out"}
```

The cookie is removed only when the sign-out went through. If a hook handler refuses it, or the request has no valid session, the cookie stays.

A session can also end without a sign-out from that browser: it was revoked from another device, or ended with all the user's sessions. The cookie then stays until it expires or the next sign-in replaces it. A request that carries it gets `401`, like a request without one.

## Protecting your own routes

```go
{Method: http.MethodGet, Path: "/me", Handler: me,
	Middlewares: []types.Middleware{types.RequireSession(ac.SessionManager)}},
```

`types.RequireSession` reads the token where the transport says, answers `401` without a valid active session, and puts the session in `rctx.Values["session"]` and its id in `rctx.Values["sessionID"]`. With `UpdateAge` set it also extends a session that is due, and the session your handler reads then has the new expiry. See [Rolling expiration](#rolling-expiration).

A request it refuses does not reach your handler. The response is JSON with a message and a code your client can act on:

| The request | Status | Body |
| --- | --- | --- |
| has no session token | `401` | `{"error": "missing session token", "code": "session_missing"}` |
| has a token that belongs to no session | `401` | `{"error": "invalid session", "code": "session_invalid"}` |
| has the token of a revoked session | `401` | `{"error": "session has been revoked", "code": "session_revoked"}` |
| has the token of an expired session | `401` | `{"error": "session expired", "code": "session_expired"}` |
| has the token of a session that waits for a second factor | `401` | `{"error": "additional verification required", "code": "session_pending"}` |

A `401` always means the client has no usable session. If Behemoth could not check the session, because the database is down for example, the answer is `500` with a generic message, and the error is logged. A client should not sign its user out on a `500`.

The middleware returns these as typed errors and the router writes the response, so your `RouterConfig.ErrorMapper` shapes them like any other error.

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

## Writing a route that ends the session

A route that ends its caller's own session takes the token back afterwards with `ClearToken`, the counterpart of `WriteToken`. It removes the cookie for the cookie transports and does nothing for the others.

```go
func signOutEverywhere(rctx *types.RequestContext) error {
	session, _ := rctx.Values["session"].(*models.Session) // set by RequireSession
	if err := rctx.Auth.SessionManager.RevokeAllForUser(rctx.Ctx, session.UserID, "signed_out_everywhere", ""); err != nil {
		return err
	}
	rctx.Auth.SessionManager.ClearToken(rctx) // after the revoke succeeded
	return rctx.Response.JSON(http.StatusOK, behemoth.M{"status": "signed_out"})
}
```

Call it only after the session has ended. A response that removes the cookie of a session that is still live leaves that session without a client. Do not call it when the session you ended is someone else's, as in an administrator's route: the cookie on the response is the caller's.

