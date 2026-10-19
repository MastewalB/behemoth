# 0004. Carry the caller of an operation in the context

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** MastewalB
- **Affects:** `types` (`HookContext`, `Access`, `Authenticator`), `identity` (new), `types/init` (the dispatcher, the rate limiter, `Boot`), `auth` (`DefaultSessionManager`), `telemetry` (`NormalizeAuditEvent`), the router, every plugin's flows

## Context and problem

[`../plans/caller.md`](../plans/caller.md) introduces `Caller`: who an operation runs for, and where the call came from. A flow requires a user or a permission of it, the session manager records its address, the audit log names its principal, and hook rate-limit rules key on its address. Something has to carry the caller from the transport that authenticates a call to each of these readers.

The readers don't all take the same inputs:

| Reader | What it takes today |
| --- | --- |
| A flow, such as `Plugin.SignIn` | a `context.Context` and typed input |
| A flow that another plugin's flow calls, such as `emailpassword.SignInWith` from the username plugin | a `context.Context` and typed input |
| A hook handler, a hook rate-limit rule, the audit event builder | a `*HookContext` |
| `SessionManager.Create` | a `context.Context` and a `SessionMeta` |
| A data hook, fired from inside a store write | a `context.Context`, passed through the store, which never imports `types` |
| `telemetry.NormalizeAuditEvent` | a `context.Context` |

Two values already travel in the context for this reason. `types.ContextWithRequest` carries the HTTP request, and `types.ContextWithHookValues` carries an operation's `Values` "because the code in between, the store and the managers, takes only a context." The caller replaces the request as the value these readers learn the caller from.

## Decision drivers

In priority order:

1. Every component that limits, records, or authorizes an operation sees the same caller.
2. The caller reaches the readers that take only a context (the store's data hooks, the session manager, and the audit normalization) without a change to their signatures.
3. A missing caller fails closed. [ADR-0005](0005-treating-a-missing-caller-as-anonymous.md) makes it anonymous.
4. A second transport sets the caller the way that transport usually carries request data.
5. A reader of a flow can see that the flow depends on its caller.

## Options considered

### Option A: the context only

`WithCaller(ctx, c)` stores the caller, and `CallerFrom(ctx)` returns it, or the zero value when there is none. Hook code reads `hctx.Caller()`, a method that reads `hctx.Ctx`.

- **Pros:** One place holds the caller. It reaches every reader through a parameter the reader already takes. Flow signatures don't change. A nested flow inherits its caller. A gRPC interceptor puts values on the context, which is how grpc-go hands a handler its peer and its metadata.
- **Cons:** A flow's signature doesn't show that the flow depends on its caller. A callee that is handed a fresh context loses the caller.
- **Fails when:** code starts a fresh context for work that belongs to an operation, such as `context.Background()` in a goroutine. The work runs as anonymous: a self-service flow refuses it, its audit events name no actor, and per-address limits don't count it.

### Option B: explicit at the flow, and the context below it

Each flow takes the caller, as a parameter or as a field of its input, and puts it on the context for the code it calls.

- **Pros:** The dependency is in the signature, and the compiler asks every caller in code for a caller.
- **Cons:** The caller is in two places. Every flow's signature changes, including the public flows', because sign-in needs the address. A flow that calls another flow passes the caller on, and code in the process passes `System(...)` on every call.
- **Fails when:** a flow receives a caller other than the one on its context and doesn't put it on the context first. The audit log reads the context, so it names a different caller from the one the flow authorized.

### Option C: explicit everywhere

Flows, managers, and the store take the caller as a parameter.

- **Pros:** No value travels implicitly.
- **Cons:** Every store and manager method gains a parameter that most of them only pass on to the data hooks and the audit log. `store.Hooks`, `SessionManager`, and an application's implementation of either change.
- **Fails when:** one method in a chain drops the parameter. That is Option A's failure, with many more signatures in which to make it.

## Decision

We chose Option A.

## Rationale

Drivers 1 and 2 rule out Option B. Its two copies of the caller can disagree, which is the failure driver 1 exists to prevent, and below the flows it needs the context anyway. Option C meets both drivers at the price of a parameter on every store and manager method, and it fails in the same way as Option A when one link drops the value.

Option A loses on driver 5 only. Two things limit that cost:

- Driver 3 makes the hidden dependency fail loudly. A flow called without a caller sees an anonymous caller and refuses with `session_missing`. It doesn't act with privileges it shouldn't have.
- Every self-service flow requires its caller in its first statement, through `Access`, and its doc comment names the permission and whether the session must be fresh.

The context is Go's place for request-scoped data that crosses API boundaries. The `context` package documentation reserves its values for "request-scoped data that transits processes and APIs", and the Go blog's introduction to the package gives "the identity of the end user" as an example of such data.

## Consequences

- **Gains:**
  - Flow signatures don't change for the caller.
  - A nested flow, the session manager, the data hooks, and the audit log see the same caller without a parameter.
  - Background work started with `context.WithoutCancel`, as the send queue does, keeps its caller.
- **Costs and risks we accepted:**
  - A reader learns a flow's requirements from its first statement and its doc comment, not from its signature.
  - A fresh context loses the caller, and code review has to catch it.
  - A test sets a caller explicitly, with `System("test").For(userID)` or through the authenticator.
- **Follow-up work:** the implementation steps of [`../plans/caller.md`](../plans/caller.md).

## Invariants

- **The context is the only carrier.** No flow, manager, or hook handler takes a caller as a parameter or keeps one in a struct for later. If a second copy exists, the audit log and the flow can disagree about who acted.
- **`HookContext` has no caller field.** `hctx.Caller()` reads `hctx.Ctx`. If a field is added, a handler can see a different caller from the one the dispatch's context holds.
- **A transport sets the caller once per call, and replaces any caller it finds.** If it inherits one, a middleware in front of Behemoth can plant an identity.
- **Work that belongs to an operation keeps the operation's context, or carries the caller over** with `WithCaller(fresh, CallerFrom(ctx))`. If it doesn't, the work runs as anonymous: self-service flows refuse it, the audit log doesn't attribute it, and per-address limits don't count it.
- **What leaves the process carries the caller as data.** A context value doesn't cross a process boundary, so a hook callout that relies on the context loses the caller.

## Revisit when

- Lost callers become a recurring bug, for example because flows run under a job runner that can't pass a context through.
- A transport appears whose framework can't put a value on the context it hands to Behemoth.
- Most flows end up taking a value derived from the caller in their input anyway, so that the second copy of Option B exists in practice.

## References

- [`../plans/caller.md`](../plans/caller.md): the caller, its principals, the authenticator, and the permissions
- [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md): "Learn about the caller from the context"
- `types/plugins.go`: `ContextWithRequest`, `ContextWithHookValues`
- `messaging/sendqueue.go`: the send queue keeps the context's values with `context.WithoutCancel`
- [The `context` package documentation](https://pkg.go.dev/context)
- [Go Concurrency Patterns: Context](https://go.dev/blog/context), on the Go blog
- grpc-go: `peer.FromContext` and `metadata.FromIncomingContext`
