# The origin check

This document explains how behemoth protects cookie-authenticated routes from cross-site request forgery: what the origin check compares, the refusal of form content types behind it, where both sit in the request pipeline, when `Boot` installs them, and what they leave out.

The code lives in:

- `types/origin_check.go`: `OriginCheck`, `NewOriginCheck`, the refusal reasons, `RefuseFormContentTypes`
- `types/origins.go`: `TrustedOrigins`, `parseOrigin`, `originOf`
- `types/router.go`: `RouterConfig.BaseURL`, `RouterConfig.TrustedOrigins`
- `types/session.go`: `TokenTransport.ReadsCookie`
- `engine/init.go`: `Boot`, which builds the check and decides whether it runs
- `engine/init.go`: `checkCookieAgainstBaseURL`, which ties the cookie's attributes to the base URL
- `errs/origin.go`: `CodeUntrustedOrigin`, `CodeUnsupportedContentType`

[`request_routing.md`](request_routing.md) describes the pipeline the check is a stage of. [`../plugins/magiclink.md`](../plugins/magiclink.md) describes `TrustedOrigins`, which the check shares with the redirect check.

## The problem

Under the cookie transports a browser attaches the session cookie to every request to behemoth's host, whichever page caused the request. A page of another origin can therefore make a signed-in user's browser send a state-changing request.

The cookie's `SameSite=Lax` attribute stops the cookie on a cross-site `POST`. It leaves two cases open:

- **A sibling subdomain.** `evil.example.com` and `auth.example.com` are one site and two origins. `SameSite` does not tell them apart.
- **Sign-in.** A sign-in needs no cookie, so `SameSite` has nothing to withhold. A forged sign-in puts the victim's browser into the attacker's account.

## What the check does

`OriginCheck.Check` looks at three things of a request: its method, its `Origin` header and its `Sec-Fetch-Site` header. It reads no cookie and no session.

| Step | Condition | Result |
| --- | --- | --- |
| 1 | the method is `GET`, `HEAD` or `OPTIONS` | pass |
| 2 | `Origin` is absent or empty, and so is `Sec-Fetch-Site` | pass: not a browser |
| 3 | `Origin` is absent or empty, and `Sec-Fetch-Site` is `same-origin` or `none` | pass |
| 4 | `Origin` is absent or empty, and `Sec-Fetch-Site` is anything else | refused, `cross_site` |
| 5 | `Origin` is sent more than once, or is not an `http` or `https` origin | refused, `malformed_origin` |
| 6 | `Origin` is `null` | refused, `null_origin` |
| 7 | `Origin` is behemoth's own origin, or `TrustedOrigins` has it | pass |
| 8 | anything else | refused, `untrusted_origin` |

Every refusal is one error for a client: a `CategoryForbidden` error with the code `untrusted_origin`, which the router answers as `403 {"error": "request from an untrusted origin", "code": "untrusted_origin"}`. The reason in the last column is the `reason` attribute of the `behemoth.http.origin_refused` counter and part of the error's internal message.

`Sec-Fetch-Site` is read only when there is no `Origin`. A trusted front end on another origin sends `cross-site` together with an `Origin` that step 7 accepts.

### Behemoth's own origin

`RouterConfig.BaseURL` names it: a scheme, a host and an optional port, without `BasePath`. `NewOriginCheck` parses it with `parseOrigin`, the function behind `NewTrustedOrigins`, so both settings accept and refuse the same values. `Boot` returns a malformed one as a configuration error, whatever the transport.

With `BaseURL` empty, the check builds the own origin for each request from the request's `Host` header and the scheme the `Origin` header named. Only the host and the port are compared this way. `logBootSummary` writes a Warn line when `BaseURL` is empty, a cookie transport is on and `BootConfig.HTTP` is set. A process that mounts no routes gets no warning.

## The refusal of form content types

Handlers decode their body as JSON whatever its `Content-Type` says. A page of another origin can post a body that decodes as JSON without a CORS preflight, with a form (`enctype="text/plain"`) or a `no-cors` `fetch`. The only types it can name that way are `text/plain`, `application/x-www-form-urlencoded`, and `multipart/form-data`.

`RefuseFormContentTypes` refuses a state-changing request that names one of the three, parameters ignored, with a `CategoryUnsupportedMedia` error: `415 {"error": "unsupported content type, send application/json", "code": "unsupported_content_type"}`. Every other type passes, and so does a request without the header, such as a sign-out with an empty body.

It is a second layer. The origin check already refuses those requests from another origin. This one holds when the check passed a browser it should not have: one that sent no `Origin` and no `Sec-Fetch-Site`.

Invariant: no route of behemoth reads a form body. A route that has to, such as an OAuth callback a provider posts, is refused under the cookie transports until the middleware gets an exemption per route. See "No route can accept a form body under the cookie transports" in `docs/ongoing.md`.

## The cookie and the base URL

`SessionConfig.CookieSameSite` and `CookieDomain` decide when a browser sends the session cookie, so `Boot` checks them against the base URL (`checkCookieAgainstBaseURL`), under the cookie transports only:

- **`SameSiteNone` needs `BaseURL`.** The browser then sends the cookie with cross-site requests, and the origin check is all that refuses a forged one. Without a base URL the check compares with the `Host` header and ignores the scheme.
- **`CookieDomain` has to cover the host of `BaseURL`.** A browser drops a cookie whose `Domain` is neither the host that set it nor a parent of it. Sign-in would answer `200` and leave no session.

A `CookieDomain` widens who receives the cookie to every subdomain, and one of them may be hostile. The origin check still compares exact origins, so that subdomain's requests are refused.

## Where it runs

`Boot` passes `OriginCheck.Middleware` and then `RefuseFormContentTypes` to `Router.Build` as the first global middlewares, ahead of every plugin's:

```
request scope -> tracing -> metrics -> error mapping -> origin check -> form content types -> plugin middlewares -> route rate limit -> route middlewares -> handler
```

- **Inside error mapping.** A refusal is mapped, logged once at Debug and counted in `behemoth.http.requests` like any other rejection.
- **Outside the plugins' middleware and the rate limit.** A forged request runs no plugin code. It also does not count against the per-address limit of the user whose browser sent it.

`Boot` adds both middlewares when `SessionConfig.Transport` is `cookie` or `both` (`TokenTransport.ReadsCookie`). Under `header` and `body` no request is authenticated by something the browser sends on its own, so the check would refuse requests and protect nothing.

Invariant: the check is the only thing that stands between a cross-origin page and a sign-in under the cookie transports. A route mounted outside `Router.Build`, or a `Build` call that leaves the middleware out, has no protection.

## Deferred

These parts are deferred:

- **A CSRF token.** Nothing implements one. `CSRFProtector`, an interface without an implementation or a caller, was removed. `docs/plans.md` has what a token would take, under "A CSRF token".
- **A requirement of `application/json`.** A request with no `Content-Type`, or with one that is not a form type, is decoded as JSON.
- **`X-Forwarded-Host`.** An application behind a proxy that rewrites `Host` sets `BaseURL`. Deferred: see "The origin check does not read `X-Forwarded-Host`" in `docs/ongoing.md`.
- **A `Referer` fallback and wildcard origins.**
- **An audit event for a refusal.** The counter and the Debug line are the record.
- **Routes that change state on `GET`.** There are none. A plugin that adds one is not covered. A WebSocket upgrade is a `GET` too, so a future socket transport calls `OriginCheck.Check` itself or adds a check of its own (`docs/plans.md`, "Long-lived connections").

## Design decisions

### An origin check, not a token

**Context:** A cookie-authenticated route has to tell a request of the application's own page from one another page caused.

**Options considered:**

- *A CSRF token.* A value the page reads and sends back in a header. It works in a browser that sends no `Origin`. It adds a cookie, a header and a way to fetch the token to the HTTP contract, every client has to carry it, and a sign-in needs a token that is bound to no session.
- *The `Origin` header.* The browser sets it and a script can't change it. It needs nothing from the client, so it changes no client later.

**Decision:** the origin check. A token can be added next to it without changing it.

**Revisit if:** applications have to support browsers that send neither `Origin` nor `Sec-Fetch-Site` on a `POST`.

### A request with neither header passes

**Context:** Command-line tools, mobile apps and other servers send no `Origin`. The planned SvelteKit package calls behemoth from its server with the browser's cookie.

**Options considered:**

- *Refuse a request without `Origin`.* The strictest. Every non-browser client has to set the header, and one that forgets gets a `403` that is hard to explain.
- *Pass when `Sec-Fetch-Site` is absent too.* Current browsers send `Sec-Fetch-Site` with every request to an HTTPS site and a script can't set it, so a request without both headers did not come from one. Go's `http.CrossOriginProtection` decides the same way.
- *A setting that allows a missing `Origin`.* One more switch, and one that turns the protection off for browsers as well.

**Decision:** pass when both are absent. A browser too old to send either also predates `SameSite=Lax` as a default, so the application is exposed there with or without this check.

**Revisit if:** a current browser turns out to send a state-changing request with neither header.

### `null` is refused

**Context:** A browser sends `Origin: null` from a sandboxed frame, a `file:` or `data:` page, and after some cross-origin redirects.

**Options considered:**

- *Accept it.* Nothing legitimate breaks. A page of any origin can produce it on purpose with a sandboxed frame, so accepting it accepts every origin.
- *Refuse it.* A page that posts from one of those contexts is refused.

**Decision:** refuse. Behemoth's routes are JSON calls a page makes with `fetch`, which sends the page's origin.

**Revisit if:** a supported front end is shown to send `null` for its own requests.

### The base URL is optional

**Context:** Behemoth does not own the server, and learns its public origin only if the application says it. Requiring the setting would fail `Boot` for every application on a cookie transport.

**Options considered:**

- *Require `BaseURL` under the cookie transports.* Exact, scheme included. Every existing application and test has to set it before it boots again.
- *List the own origin in `TrustedOrigins`.* No new field. The list would then mix where a browser may be sent with where behemoth lives, and later uses of the base URL, such as an OAuth callback, would need the field anyway.
- *Optional, with the `Host` header as the fallback.* Works unconfigured for an application reached directly. The scheme is not compared, because behind a proxy that ends TLS the request arrives over plain HTTP. A proxy that rewrites `Host` makes every browser request fail, which is visible at once.

**Decision:** optional, with a Warn line at `Boot`. The fallback fails closed.

**Revisit if:** the Warn line is ignored in practice and applications run in production on the fallback. `BaseURL` would then become required under the cookie transports.

### Installed for the cookie transports only

**Context:** `SessionConfig.Transport` decides whether a request is ever authenticated by a cookie.

**Options considered:**

- *Always.* One behavior to describe. A bearer-only API would refuse a browser front end on another origin until it is listed, and gain nothing: a bearer token is sent by a script that already holds it.
- *When the transport reads a cookie.* The check runs where a forged request can do something.

**Decision:** `cookie` and `both`. Under `both` a request that carries a bearer token is checked as well, because the stage runs before anything reads the token.

### Form types are refused, and JSON is not required

**Context:** A second layer against a forged body should not depend on the `Origin` header. It changes what a client may send, which is part of the HTTP contract.

**Options considered:**

- *Require `application/json` on every route that reads a body.* The strictest, and it forces a preflight for every cross-origin request. It refuses every client that sends no `Content-Type` today.
- *Refuse the three types a form can send.* Those are the only ones that reach behemoth from another origin without a preflight. A client that sends JSON under one of them is refused, which in practice is `curl -d` without a header.
- *Leave it to the origin check.* Nothing breaks, and there is one layer.

**Decision:** refuse the three, under the cookie transports only. A bearer-only API gains nothing from it, and its `curl -d` callers would break.

**Revisit if:** a route has to accept a form, or a contract file makes each route's content type explicit and the check can move there.

### A status of its own for the refused content type

**Context:** The refusal needs a category, and the router maps a category to one status.

**Options considered:**

- *`CategoryValidation`, a `400`.* No new category. A client sees the status of a missing field for a request whose fields were never read.
- *A new category mapped to `415`.* One more entry in `categoryToStatus`. The status says what is wrong before the client reads the code.

**Decision:** `CategoryUnsupportedMedia`. It is not in `Category.IsRejection`: the list there is the subject of "Which error categories count as a rejection" in `docs/ongoing.md`, and no hook point fires for this refusal.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestOriginCheck` | `types/origin_check_test.go` | every row of the table above, with and without a base URL |
| `TestNewOriginCheckRefusesABadBaseURL` | `types/origin_check_test.go` | the values `NewOriginCheck` refuses |
| `TestOriginCheckMiddlewareInThePipeline` | `types/origin_check_test.go` | the `403` body, and that a refused request reaches no later stage |
| `TestRefuseFormContentTypes` | `types/origin_check_test.go` | the three refused types, the types that pass, and a `GET` |
| `TestBootInstallsTheOriginCheckForCookieTransports` | `tests/plugins/origin_check_test.go` | both middlewares per transport, on the sign-in route |
| `TestBootChecksTheSessionCookieAgainstTheBaseURL` | `tests/plugins/origin_check_test.go` | `SameSiteNone` without a base URL, and a domain that does not cover the host |
| `TestBootRefusesAMalformedBaseURL` | `tests/plugins/origin_check_test.go` | the configuration error |
