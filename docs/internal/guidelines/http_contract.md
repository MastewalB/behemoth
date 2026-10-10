# The HTTP contract and its clients

This document explains what a client of behemoth's routes depends on, and what follows for anyone who adds or changes a route. Client SDKs are planned, a SvelteKit SDK first, and none exists yet. The guidelines are here so that routes written in the meantime do not have to change when one does.

They are suggestions for new code and for changes. They do not describe a finished state: *Where the code differs today* lists the places that do not follow them yet.

The code it refers to lives in:

- `types/plugins.go`: `Route`, `RequestContext`, `ResponseRecorder`
- `types/signin.go`: `WriteSignIn`, the body every sign-in answers with
- `types/public_view.go`: the user a response carries
- `errors/errors.go`, `errors/session.go`: `DomainError`, `DefaultErrorMapper`
- `plugins/*`: each plugin's routes, body keys and error codes

The other guideline documents are [`transport_neutral_flows.md`](transport_neutral_flows.md), about what belongs in a handler and what belongs in the flow behind it, and [`service_ready_components.md`](service_ready_components.md), about options, state and background work in a component that may run in a standalone service.

## What a client depends on

A client never sees hooks, the store, migrations or the router adapters. Those can change freely. It sees this:

| Part of the contract | Example | Decided by |
| --- | --- | --- |
| Method and path | `POST /api/auth/sign-in/email` | `Route`, `RouterConfig.BasePath`, `PluginMeta.MountPath` |
| Request body keys | `email`, `password`, `redirectURL` | the input type's `FromMap` |
| Response body | `{"user": {...}}`, `{"status": "ok"}` | the handler, `WriteSignIn`, `PublicView` |
| Error status and code | `401` with `invalid_credentials` | the `DomainError`'s category and code, the error mapper |
| Response headers | `Set-Cookie`, `Set-Auth-Token`, `Retry-After`, `X-Request-ID` | the session manager, the router |
| Where the session token travels | a cookie, a bearer token | `SessionConfig.Transport` |

A change to a row of this table reaches every client. A question to ask before a change to a route: would a client written against yesterday's response still work?

## Guidelines

### Reject with a typed error that has an exported code

A client tells errors apart by `code`. The message is for a person and can be reworded. A code keeps its meaning and its status once it has shipped.

```go
// ErrorCodeEmailTaken is the code of the conflict error (409) for a
// sign-up with an email that already has an account.
const ErrorCodeEmailTaken = "email_taken"
```

The flow returns the typed error, the handler returns it unchanged, and the router answers `409 {"error": "an account with this email already exists", "code": "email_taken"}`.

Compare with a handler that writes the response itself, `rctx.Response.Error(400, "user already exists")`. The body has no code, so a client can only compare the English text. Sign-up answered this way before its rejections were given types.

- A new rejection gets a new code. An existing code is not reused for something else.
- Codes are snake case and name what is wrong: `email_taken`, `invalid_magic_link`, `session_expired`.
- A hook handler of the application can reject with a code of its own, so a client treats codes as an open set. A code is not a promise that no other code can come from the route.

### Add to a response, and leave what is there

A client ignores keys it does not know, so a new key is safe. A renamed or removed key, a changed type and a changed status are not. `WriteSignIn` follows this for plugins: its `extra` argument adds keys next to `user`, and can't replace `user`, `token` or `status`.

### Answer in the shapes that exist

| Answer | Shape | Written by |
| --- | --- | --- |
| A finished sign-in | `{"user": {...}}`, or `{"status": "requires_second_factor"}`, with `token` under the body transport | `types.WriteSignIn` |
| A user | `{"user": {...}}`, the public columns | `AuthContext.Public.Of` |
| An action with nothing to return | `{"status": "<what happened>"}` | the handler |
| An error | `{"error": "<message>", "code": "<code>"}` | the router's error mapper |

A new sign-in plugin calls `WriteSignIn`, as the magic link plugin does, and its clients parse one shape whichever way the user signed in. A route that answers with a user wraps it under `user` and takes it from the public view, not from the model: the model carries every column a plugin contributed.

### Keep the input fields the flow does not read

Sign-in and sign-up decode the body into a map and hand the fields they do not read to the before hooks (`EmailAndPasswordCredentials.Extra`). An application sends a captcha token this way. A route that decodes into a struct drops those fields, and one that refuses unknown fields breaks the applications that send them.

### Name a body key in the style of the body it joins

The style is not settled: a user's keys are column names (`email_verified`), and the plugins' own keys are camel case (`redirectURL`). `docs/ongoing.md` has the entry, "Body keys mix two naming styles". Until it is decided, a new key follows the keys already in the same body, and a single word avoids the question.

### Keep a route's path a constant of its plugin

A path is an exported constant (`magiclink.PathVerify`) that the route and its rate-limit rules share. It is not an option of the plugin. `RouterConfig.BasePath` and `PluginMeta.MountPath` are the only things that move a route, so a client is configured with a base URL and a base path and knows the rest.

### Put what every client needs in core

Reading the caller's session and signing out do not depend on how the user signed in. A client's core calls them whichever plugins the application installed. When a sign-in plugin mounts such a route, an application that installs another plugin does not have it.

The same reasoning applies between plugins. A plugin's routes work without another plugin's routes unless `PluginMeta.Dependencies` names it.

### Deliver the session token through the session manager

A sign-in route calls `WriteSignIn`, which asks the session manager where the token goes. A route that also puts the raw token in its body hands scripts the token that an `HttpOnly` cookie keeps from them. A client relies on `SessionConfig.Transport` naming every place the token appears.

### Point an email link at a page of the application

The page posts the token to behemoth. `docs/internal/plugins/magiclink.md` has the reason: mail scanners open links, and a `GET` that acts on a token is used up by the scanner. For a client it also means that every flow is a JSON call, and no route redirects a browser.

### Treat a header a client reads as part of the contract

`Set-Auth-Token`, `Retry-After` and the request ID header are read by clients. A script on another origin reads a response header only when the application's CORS setup exposes it, so a new one is listed in `docs/api` for the application to expose. The body has no such condition and is the better place for new data.

### Update the API docs in the same change

`docs/api/<plugin>.md` lists each route's body, answers and codes. Until a contract file is generated from the routes, these pages are the only description a client's author has.

## How the clients are expected to be built

The plan is one core client with client plugins, and thin packages per framework:

- **The core client** sends requests, keeps a bearer token where the transport needs one, turns an error body into one error type (status, code, message, request ID, retry delay) and holds the session's state.
- **A client plugin** matches one server plugin and adds its methods and types. Email and password is a client plugin like the others, since it is optional on the server.
- **A framework package** (Svelte, SvelteKit, React) takes a client and adds reactivity or server integration. It does not know about plugins.

Two things follow for server code. A plugin's routes, keys and codes should make sense on their own, because one client plugin is written against one server plugin. What the core client calls has to exist whichever plugins are installed, which is the reason for *Put what every client needs in core*.

## Where the code differs today

Not models to copy. Each has an entry in `docs/ongoing.md` under the quoted title, unless noted.

- No route returns the caller's session, and `POST /sign-out` is mounted by the email/password plugin. "No route answers with the caller's session, and sign-out belongs to one plugin".
- An application's `RouterConfig.ErrorMapper` returns the whole error body and can leave `code` out. "An application's error mapper decides the error body".
- Two sign-ups racing for one email answer with the store's code and not `email_taken`. "Two sign-ups racing for one email answer with the store's code".
- Body keys come in two styles. "Body keys mix two naming styles".
- A route does not describe its input, its output or its codes, so no contract file can be generated or tested. "Routes do not describe their input and output".
- The session cookie's attributes are fixed, which limits where a front end can be hosted. "The session cookie's attributes are fixed".
- The email/password plugin's sign-up, sign-in and sign-out paths are string literals, repeated in core's rate-limit rules. No entry.

## Design decisions

### The error code is the contract, the message is not
**Context:** A client has to tell rejections apart: a wrong password, an email that is taken, a session that expired, a rate limit. It needs something that stays the same while the wording improves.
**Options considered:**
- *The status alone.* Nothing to maintain. A `401` is a wrong password, an expired session and a used link, which a client treats differently.
- *The message.* It is already there. Rewording it breaks clients, and it can't be translated without breaking them.
- *A code next to the message.* One more constant per rejection, exported so that the tests and the API docs name it.

**Decision:** the code. A rejection a client can cause is a `DomainError` with an exported code, and handlers do not write error bodies themselves.
**Revisit if:** clients need more than a code to act on a rejection, such as the field a validation error is about. The error body would then gain a key, which the guideline on adding allows.
