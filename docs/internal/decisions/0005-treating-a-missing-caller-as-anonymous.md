# 0005. Treat a call without a caller as anonymous

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** MastewalB
- **Affects:** `identity` (new), `core` (`Access`), `engine` (the audit event builder), `telemetry` (`NormalizeAuditEvent`), the admin operations (`emailpassword.SetPassword`, `username.SetUsername`, `phonenumber.SetPhoneNumber`, `phonenumber.AddNumber`), and every application that calls a flow from code

## Context and problem

[ADR-0004](0004-carrying-the-caller-in-the-context.md) carries the caller of an operation in the context, and [`../plans/caller.md`](../plans/caller.md) describes the caller. A transport always puts a caller on the context, built by the authenticator. Code in the process calls flows too: a job, a CLI command, a test, another plugin, or an application's own transport, such as a GraphQL resolver. Such code may put no caller on the context at all. Flows, hook handlers, and the audit log then need one answer to what `CallerFrom(ctx)` returns, and to what that caller may do.

Today the answer is implicit, and it favors trust:

- `DefaultDispatcher.auditEvent` names the system as the actor of an operation outside an HTTP request, and `telemetry.NormalizeAuditEvent` does the same for an event without a request ID.
- The admin operations, such as `SetPassword(ctx, userID, password)`, check nothing. A caller from code vouches for the request itself.
- Code that treats calls from code in the process differently tests `hctx.Request == nil`, as the audit event builder does.

Code in the process holds the store, so it can do anything the store can. The question is not whether to trust it. The question is what happens when code that should have set a caller didn't.

## Decision drivers

In priority order:

1. Forgetting to set a caller never grants privileges.
2. An application's own transport gets the protections of Behemoth's own, even when it forgets to authenticate.
3. Code in the process can still run any flow, an admin operation included, by saying who it is.
4. The audit log names who ran each operation, a job included.
5. Code in the process writes as little as possible to run a flow.

## Options considered

### Option A: a missing caller is the system

`CallerFrom` returns a system caller when the context carries none. This is what the audit log assumes today.

- **Pros:** Jobs, CLI commands, and tests need no change. Admin operations keep working from code as they do now.
- **Cons:** The default is the most privileged caller there is.
- **Fails when:** an application's own transport forgets to authenticate. Every flow then runs for the internet with the system's privileges. Admin operations go through, and a hook that relaxes its check for the system, such as a captcha check that skips calls from code, lets every request past.

### Option B: a missing caller is anonymous, and the system is explicit

The zero `Caller` is anonymous and holds no permission, and `CallerFrom` returns it when the context carries none. Code in the process names itself with `System(name)`, and acts for a user with `System(name).For(userID)`. Admin operations require a privileged caller.

- **Pros:** Forgetting fails closed: a self-service flow answers `session_missing`, and an admin operation is refused. The audit log names each job.
- **Cons:** Each job, CLI command, and test that runs a flow adds a line. Admin operations called from code without a caller stop working, which changes existing applications.
- **Fails when:** a job runs a public flow, such as sign-up, without naming itself. The flow runs, and the audit log records an anonymous caller instead of the job. The failure is a wrong label, not a wrong grant.

### Option C: a caller is required

A flow called without a caller on its context returns a configuration error.

- **Pros:** Nothing is implicit.
- **Cons:** Every call to every flow from code needs a caller, including a test of sign-up and a script that seeds users. The zero value stops being a usable default, against [`../guidelines/service_ready_components.md`](../guidelines/service_ready_components.md) ("The zero value is the default").
- **Fails when:** code that runs a public flow with no identity to give, such as a test, has to invent one. The name nearest to hand is the system, which brings back Option A's failure.

### Option D: decide by the transport

A missing caller is the system for a call from code in the process, and anonymous for a call that arrived over a transport.

- **Pros:** Jobs need no change, and Behemoth's own transports fail closed.
- **Cons:** It branches on how a call arrived, which the plan's rules forbid: a flow branches on who calls, never on how the call arrived.
- **Fails when:** an application's own transport runs inside the process and forgets to authenticate. Its calls look like calls from code, and get the system's privileges, as in Option A.

## Decision

We chose Option B.

## Rationale

Drivers 1 and 2 rule out Options A and D. Each turns a forgotten caller into the most privileged one, and Option D does it exactly where an application writes its own transport. Option C meets drivers 1 and 2, but it makes every call from code name a caller, and the easiest name to reach for is the system, so in practice it decays into Option A.

Option B meets drivers 1 to 4. It costs one line per job, and a wrong label when a job forgets that line, which driver 5 ranks last. Its change to existing applications, admin operations that need a system caller, is cheapest before a tagged release.

The rest of the design relies on the same property. The zero `Caller` and the zero grant are what code gets when it does nothing, so doing nothing never grants anything.

## Consequences

- **Gains:**
  - A forgotten caller fails closed in every flow and every hook.
  - An application's own transport is as safe as Behemoth's own, without its author knowing a rule.
  - The audit log names each job, such as `System("purge-sessions")`, instead of one anonymous system.
- **Costs and risks we accepted:**
  - Jobs, CLI commands, examples, and tests that run flows add a caller. Until they do, their audit events say anonymous.
  - Admin operations called from code without a system caller are refused. That changes applications that call `SetPassword`, `SetUsername`, `SetPhoneNumber`, or `AddNumber` today.
  - The audit actor of code in the process changes from the system to anonymous, or to the job's name, so a query that filters on the system actor type returns fewer rows.
- **Follow-up work:** steps 2, 4, and 6 of [`../plans/caller.md`](../plans/caller.md).

## Invariants

- **The zero `Caller` has no principal and holds no permission, and `CallerFrom` returns it for a context without a caller.** If the zero value grants anything, a forgotten caller grants it.
- **Only the authenticator and `System` build a caller with a principal.** If other code can, every guarantee depends on that code getting it right.
- **No flow or hook handler relaxes a check for a missing caller.** A check that relaxes for code in the process tests for a system principal. If it tests for a missing caller, Option A's failure comes back for that check.
- **A transport never builds a system caller.** It builds its caller through the authenticator, which builds users, services, and anonymous callers. If a transport builds a system caller, a request from outside runs with the system's privileges.

## Revisit when

- Jobs routinely forget to name themselves, and the audit log fills with anonymous events from them. A lint that finds flow calls without a caller would then be worth building.
- An application's transport needs to run flows for callers it authenticated itself, without Behemoth's authenticator. A third way to build a caller would then need rules of its own.

## References

- [`../plans/caller.md`](../plans/caller.md): the caller, `System`, `For`, and `Access`
- [ADR-0004](0004-carrying-the-caller-in-the-context.md): the caller travels in the context
- [ADR-0006](0006-requiring-declared-permissions.md): the zero grant, and what a system caller holds
- [`../guidelines/service_ready_components.md`](../guidelines/service_ready_components.md): "The zero value is the default, and a wrong value fails at start"
- `dispatch/dispatcher.go`: `auditEvent`, which names the system outside a request today
- `telemetry/audit.go`: `NormalizeAuditEvent`
