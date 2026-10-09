## **Session token transport**

This document explains how a session token reaches the client and comes back: the four transports, the split between the session manager and the route that answers a sign-in, the defaults of `SessionConfig`, and the JSON a sign-in answers with.

The code lives in:

- `types/session.go`: `TokenTransport`, `SessionTokenHeader`, the `SessionManager` interface, `RequireSession`, `RequireFreshSession`
- `types/auth-options.go`: `SessionConfig`, `WithDefaults`, `Validate`
- `types/signin.go`: `SignInResult`, `WriteSignIn`
- `transport/session.go`: `DefaultSessionManager.WriteToken`, `ExtractToken`
- `models/user.go`: the user's JSON

---

# **Two directions, one setting**

`SessionConfig.Transport` decides both how a sign-in delivers the token and where a request is expected to carry it.

| Transport | `WriteToken` | `ExtractToken` reads |
| --- | --- | --- |
| `cookie` | `Set-Cookie` with `CookieName` | the cookie |
| `header` | the `Set-Auth-Token` response header | `Authorization: Bearer` |
| `body` | nothing; returns `true` | `Authorization: Bearer` |
| `both` | the cookie and the header | the header, then the cookie |

`header` and `body` differ in delivery only. A client of either sends a bearer token, so `ExtractToken` treats them alike.

# **Who writes what**

The session manager can set headers on the response, and a cookie is a header. It can't write the body: the route decides what the body is. That is why `WriteToken` returns a value.

```go
WriteToken(rctx *RequestContext, rawToken string, session *models.Session) (inBody bool)
```

`WriteSignIn` is the one caller in core, and the one function a sign-in route calls:

1. Copies the plugin's extra fields into the body, minus the keys it owns (`user`, `token`, `status`).
2. Calls `WriteToken`. If it returns `true`, sets `body["token"]`.
3. Sets `status: "requires_second_factor"` for a pending session, and `user` otherwise.
4. Sets `Cache-Control: no-store` and writes the JSON with status `200`.

| Route | Calls |
| --- | --- |
| `POST /sign-in/email` | `types.WriteSignIn(rctx, result, nil)` |
| `POST /magic-link/verify` | `types.WriteSignIn(rctx, result.SignInResult, behemoth.M{"redirectURL": ...})` |

A pending session's token is delivered like an active one's. The client needs it to present the second factor, and `SessionManager.Get` resolves a pending session by its token.

A flow called from code (`Plugin.SignIn`, `Plugin.Verify`) returns the raw token in its `SignInResult` and writes nothing. There is no response to write to.

# **Defaults**

`SessionConfig.WithDefaults` fills the fields below when they are left at zero, and `NewSessionManager` applies it. The manager's own copy of the configuration is the only one with the defaults in it: `BootConfig.Session`, read anywhere else, may still hold zeros.

| Field | Default |
| --- | --- |
| `Transport` | `cookie` |
| `CookieName` | `session_token` |
| `ExpiresIn` | 7 days |
| `PendingExpiresIn` | 10 minutes |
| `FreshAge` | 15 minutes |

`UpdateAge` is not in the table. Its comment used to name a default of one day, which was never applied, and zero has a working meaning: `Touch` then never extends a session. Applying a day would change that for every application that left it unset, and with an `ExpiresIn` of a day or less it would extend the session on every request. `docs/ongoing.md` has the entry.

`SessionConfig.Validate` reports what no default can repair: a `Transport` that is not one of the four values, and a negative duration. `Boot` calls it before it builds the session manager and returns a configuration error.

Before this, the comments on the fields named defaults that nothing applied. A zero `Transport` matched no branch of `WriteToken` or `ExtractToken`, so no token was delivered or accepted. A zero `ExpiresIn` or `PendingExpiresIn` made a session expire the moment it was created. `CookieName` was not read.

# **The user as JSON**

A response carries a user as `AuthContext.Public.Of(user)`: a flat map of the user's public columns, keyed by column name, so it says `email_verified` and `image_url` as a sign-up request does. A column a plugin contributed is in it only if the plugin declared it public. [`../models/models.md`](../models/models.md) has the mechanism under *What a client sees: public columns*.

`models.User` also has `json` tags equal to its column names, for code that decodes a response into the model. Encoding the model directly is not what the routes do: it would carry every contributed column under `extra`.

---

# **Tests**

| Test | File | Covers |
| --- | --- | --- |
| `TestSessionConfigDefaults`, `TestSessionConfigValidate` | `types/auth_options_test.go` | every default, a set field kept, what `Validate` refuses |
| `TestSessionManagerWithAZeroConfig` | `tests/store/managers_test.go` | a zero config: session lifetimes, a session that validates, the default cookie |
| `TestSessionTokenTransports` | same | per transport: what `WriteToken` sets and returns, what `ExtractToken` accepts, the cookie's name |
| `TestSignInDeliversTheTokenByTransport` | `tests/plugins/signin_response_test.go` | through the routes, per transport: where the token arrives and that it arrives nowhere else, the body's shape, the user's keys, `no-store`, and sign-out with the token where the client sends it |
| `TestSignInPendingSecondFactorCarriesTheToken` | same | the pending body, and its token by header and by body |
| `TestBootRefusesAnUnknownSessionTransport` | same | the configuration error |
| `TestMagicLinkRoutes` | `tests/plugins/magiclink_test.go` | the verify route delivers the token like the password route |

---

# **Design decisions**

### `TransportHeader` delivers the token in a response header
**Context:** With the header transport, `WriteToken` put the token in `rctx.Values["token"]` and nothing read it. A client signed in and never received its token.
**Options considered:**
- *The routes add the token to their JSON body.* It is where API clients look first. The setting says "header", and the application that chose it would get something else.
- *A response header.* It is what the setting names, and it mirrors the cookie: the server sets a credential in a header and the client stores it. A cross-origin browser script reads it only if CORS exposes it.
- *The router merges the token into JSON bodies.* No route has to remember. The body is already serialized by then, the merge works only for JSON objects, and for a route that answered with a bare user it would put `token` among the user's columns.
**Decision:** The header, named `Set-Auth-Token`. Whether a header is the right place for a given client is the application's decision, and it made it by choosing the transport. The transport now names both directions, where before it described only how the client sends the token.
**Revisit if:** applications need another header name. It is a constant, `types.SessionTokenHeader`.

### The body is a transport of its own
**Context:** Delivering the token in the JSON body is still what some clients want.
**Options considered:**
- *Always put it in the body as well.* Convenient. Under the cookie transport it would hand scripts the token an `HttpOnly` cookie keeps from them.
- *A fourth transport, `TransportBody`.* The application asks for it. It needs the routes' cooperation, because the session manager does not write bodies.
**Decision:** `TransportBody`. `WriteToken` returns whether the token belongs in the body, and `WriteSignIn` acts on it. A returned value is visible in the signature; the value parked in `rctx.Values` that this replaces was not, and nothing read it.
**Revisit if:** an application wants the body together with the cookie or the header. `Transport` would then become a set of places and not one of four names.

### One body for every sign-in route
**Context:** The email/password sign-in answered with the bare user, and the magic link verify with `{"user": ..., "redirectURL": ...}`. A token in the body needs an object to sit in.
**Options considered:**
- *Wrap only under the body transport.* No change for existing clients. The shape of a response would depend on a server setting.
- *Always `{"user": ...}`.* One shape for every plugin and transport. It changes the email/password responses.
**Decision:** Always the wrapper, written by `WriteSignIn` so that a new sign-in plugin gets it without repeating it. Sign-up answers `{"user": ...}` too, so a client parses a user the same way wherever it gets one.

### The session manager applies the defaults
**Context:** `SessionConfig` named defaults in comments, and each use of a field read the raw value.
**Options considered:**
- *A default at each use.* Local. Easy to miss one, which is what had happened for every field.
- *Normalize once, where the manager is built.* One function to read and test.
- *Require every field.* No hidden values. A zero-value config, which the rest of `BootConfig` supports, would stop working.
**Decision:** `WithDefaults`, called by `NewSessionManager`, so a manager built outside `Boot` (a test, a worker) gets the same values. It covers the fields whose zero value did not work. `UpdateAge` is left alone, because its zero value does. `Boot` calls `Validate` first, because a misspelled transport should stop the process and not quietly become the cookie.

### Users are keyed by column name in JSON
**Context:** The routes encode `models.User` directly. Without `json` tags the keys were Go field names (`EmailVerified`, `ImageUrl`), while requests use column names.
**Options considered:**
- *`json` tags equal to the column names.* Small, and symmetric: a test or a client can decode a response into `models.User`.
- *Answer with `user.ToMap()`.* Flat, with contributed columns next to core ones. Decoding back into the model would need a custom unmarshaller for the timestamps.
**Decision:** The tags, at first. The routes have since moved to the public view (see `models.md`), which is `ToMap` reduced to the public columns, with values normalized for JSON. It needs no unmarshaller, because nothing decodes it back on the server. The tags remain so that a client or a test written in Go can decode a response into `models.User`.
