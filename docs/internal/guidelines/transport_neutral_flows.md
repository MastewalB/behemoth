# Flows and the transports that reach them

This document explains the split between a flow and the code that exposes it over a transport, and what follows for anyone who adds a flow, a handler, a hook handler, a rate-limit rule or a method on a core interface. HTTP is the only transport today. gRPC, WebSockets, or GraphQL may follow where there is a need, and not every flow will get every wrapper.

The guidelines are suggestions for new code and for changes. They do not describe a finished state: *Where the code differs today* lists the places that do not follow them yet.

The code it refers to lives in:

- `plugins/*`: each plugin's flows (`Plugin.SignIn`, `Plugin.RequestLink`, ...) and their handlers
- `core/plugins.go`: `RequestContext`, `HookContext`, `RequestFrom`
- `core/session.go`: `SessionManager`, `RequireSession`
- `core/ratelimit.go`: the route and hook rate-limit rules
- `core/router.go`: the pipeline around a handler
- `errs/errors.go`: `DomainError` and its categories

The other guideline documents are [`http_contract.md`](http_contract.md), about what a client of the HTTP routes depends on, and [`service_ready_components.md`](service_ready_components.md), about options, state, and background work in a component that may run in a standalone service.

## Three layers

| Layer | What it does | What it knows | Example |
| --- | --- | --- | --- |
| Wrapper | decodes the input, calls one flow, encodes the result | its transport | `handleSignIn`, a gRPC method |
| Flow | the operation: its rules, its hook points, its writes | a `context.Context`, typed input and result | `Plugin.SignIn` |
| Services | sessions, tokens, storage, mail | a `context.Context` | `SessionManager`, `TokenManager`, `Store`, `Mailer` |

The sign-in route shows the wrapper at its size:

```go
func (p *Plugin) handleSignIn(rctx *core.RequestContext) error {
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil {
		return errs.NewValidationError("SignIn", "request", err)
	}
	var creds EmailAndPasswordCredentials
	if err := creds.FromMap(body); err != nil {
		return err
	}
	result, err := p.SignIn(rctx.Ctx, creds) // the flow
	if err != nil {
		return err
	}
	return core.WriteSignIn(rctx, result, nil)
}
```

A gRPC method for sign-in would be the same three steps with other types.

## The goal

A flow gives the same guarantees however it is reached: its rate limits, its hook points, its audit events, and what a client may learn from its answer.

"The package does not import `net/http`" is a weaker statement. A flow can avoid the import and still leave its protection to the HTTP handler, and then a second wrapper is less safe than the first.

A question to ask for a small decision: if this flow were called from a gRPC method tomorrow, would that method have to copy anything from the HTTP handler to be as safe and as correct? What it would have to copy belongs in the flow.

## Guidelines

### A wrapper decodes, calls one flow and encodes

A second call to the store, a rule, or an `errors.Is` that changes the answer is a sign that part of the operation is in the wrapper. Each further wrapper then has to repeat it, and a caller in code does not get it at all.

### A flow takes a context and typed input, and returns a result and an error

It takes no `*RequestContext` and no `*http.Request`, and it sets no status, cookie, or header. `Plugin.SignIn` returns a `SignInResult` with the raw session token and writes nothing: "the raw session token is in the result and is the caller's to deliver".

A flow is exported and documented as the flow behind its route, so that a job, a CLI or another plugin calls the same code.

### A flow returns typed errors, and a transport maps them

A `DomainError` has a category (`validation`, `unauthorized`, `conflict`, `rate_limited`, ...), a code and a public message. None of them is HTTP's. The router maps the category to a status with one table (`categoryToStatus`), and another transport would have a table of its own. A flow that picks a status has made that choice for HTTP only.

### A check on the input lives with the input

`LinkRequest.FromMap` refuses an email that is not a string, and the flow refuses one that is not an address. A caller in code and every wrapper get both checks. A check that exists only in a handler is skipped by all the others.

### A protection belongs to the operation, not to the path

Password reset declares two kinds of limit, and its comment says why the second is a hook rule:

```go
// Per email on the request itself, so it also holds for
// RequestPasswordReset called from code.
return ic.RateLimits.DeclareHookRateLimitRule(core.HookRateLimitRule{
	Name: RuleResetRequestEmail, Point: HookResetRequestBefore,
	KeyFunc: core.KeyByValues(hooks.HookValueEmail), Limit: p.opts.Reset.RequestLimit,
})
```

A hook rule on the flow's before point counts every call of the flow. A route rule counts requests to one path and nothing else. Prefer the hook rule for a limit that protects an account, a mailbox or a resource. A route rule suits what is about HTTP itself.

### What a client may learn is decided in the flow

A request for a reset link answers the same for an email with an account and one without. That is a property of the operation. When the flow returns `ErrNoAccount` and the handler turns it into a `200`, each wrapper has to know to do the same, and one that returns the flow's error tells a client which emails are registered.

A caller in code can be told more than a client. That calls for two entry points to the flow, or a result that says both, and not for a decision in the wrapper.

### Learn about the caller from the context

A flow, a manager or a rate-limit rule in core does not need the request. It needs a few facts about the caller: the address, the user agent, the session. When a flow needs one of them, the wrapper passes it in the input or publishes it in the operation's `Values`, the way `publishEmail` does with `HookValueEmail`, and the way `SessionMeta.IPAddress` lets a caller name the address.

Today the address and the user agent are read from the `*http.Request` found with `core.RequestFrom(ctx)`, in the session manager and in the audit event builder. A caller value in the context is planned to replace those reads, and to carry the session and the principal as well. [`../plans/caller.md`](../plans/caller.md) has the design, and [ADR-0004](../decisions/0004-carrying-the-caller-in-the-context.md) the choice of the context. Until it is built, avoid adding a new place that reads the request below the wrapper.

### A hook handler reads the payload and `Values`

`HookContext.Request` is nil when the flow was not reached over HTTP. A handler that wants a captcha token reads it from the payload, where the body's extra fields arrive, and not from a header. A handler that does read `Request` checks it for nil first.

### A result carries data, and the wrapper decides what to do with it

The magic link flow returns a `RedirectURL` in its result. The HTTP wrapper puts it in the JSON body, and another transport is free to do something else with it. Cookies, `Cache-Control`, and the shape of a body are the wrapper's, or a helper's that wrappers share, such as `WriteSignIn`.

### A new method on a core interface takes a context

`SessionManager.Create`, `Validate`, `Revoke`, and `Touch` take a `context.Context`, and so do the token manager's and the mailer's methods. A new method that takes a `RequestContext` can't be called by a job or by another transport.

### A transport's dependency stays in its own module

The framework adapters are modules of their own, so that an application downloads gin only if it uses gin. A gRPC or WebSocket wrapper would be packaged the same way, and the root `go.mod` would not change.

### Test the flow without HTTP

A flow's guarantees are tested by calling the flow: the limit that refuses the eleventh attempt, the audit event, the answer for an unknown email. The route's test covers what is on the wire: the status, the body, the headers. A guarantee that can only be tested through the route lives in the wrapper.

## Where the code differs today

Not models to copy. Each has an entry in `docs/ongoing.md` under the quoted title, unless noted:

- The limits per client address are route rules, so sign-in and sign-up called from code have no rate limit. "A flow called from code skips the per-address limits of its route".
- The handlers of the link request, verification send, email change and reset request routes hide whether an account exists. "Hiding whether an account exists is done by the HTTP handlers".
- The session manager, the audit event builder and hook rules learn about the caller from the `*http.Request`. A flow reached another way is audited as the system, without an address. "The caller of an operation is known only through the HTTP request" and "A hook rule has no direct way to the resolved client address".
- `SessionManager` has four methods that take HTTP types, and the session check exists only as the `RequireSession` middleware. "The session manager also carries the token over HTTP".
- `core.Plugin` requires `Routes` and `Middlewares`. The stages around a handler are built in `Router.Build`. `core`, `errors`, `auth`, and each plugin's package import `net/http`, so no import rule checks any of this yet. [`../plans/package_layout.md`](../plans/package_layout.md) plans a package for the HTTP types, and the check. "`Plugin` requires HTTP routes, and the request pipeline lives in the router".
- The email change route requires a fresh session through `RequireFreshSession`, and `RequestChange` doesn't check it. "The fresh-session rule of an email change is checked by its route only".
- The verify, confirm, and revert handlers refuse a missing token themselves, and several flows take positional arguments that no input type checks. "Some flows take loose arguments instead of a request type".

## Design decisions

### Thin wrappers per transport, without a shared transport interface

**Context:** Flows should be reachable over more than HTTP, without every transport repeating a flow's rules.

**Options considered:**

- *One handler type for every transport.* `RequestContext` would be widened until a gRPC call and a WebSocket message fit it, and a plugin would write each handler once. Unary calls, streams, cookies, and metadata differ too much: the shared type would carry fields that mean nothing on most transports, and code that reads them would depend on the transport after all.
- *A wrapper per transport over complete flows.* Each transport keeps its own types, and a wrapper is a few lines. It works only when the flow holds everything that matters, which is what the guidelines above ask for.

**Decision:** wrappers per transport. The effort goes into making a flow complete, not into an abstraction over transports.

**Revisit if:** two transports turn out to share most of their wrapper code for most flows. Generating the wrappers from a description of each operation would then be worth a look.

### Equal guarantees are the goal, and the import rule is a check

**Context:** "HTTP-agnostic" needs a meaning that a reviewer can apply to a small change.

**Options considered:**

- *No `net/http` import below the wrappers.* A tool can check it. It says nothing about a rate limit that is declared on a path, or an answer that the handler softens: both pass the check and both are missing on a second transport.
- *The same guarantees however a flow is reached.* It covers those cases. A tool can't check it, so it needs tests that call the flow without HTTP.

**Decision:** the second is the goal. The import rule is added as a check once the HTTP types and the handlers are in packages of their own.
