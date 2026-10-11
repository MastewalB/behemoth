# 0001. Report a hook chain's error through one helper, with one code

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** MastewalB
- **Affects:** `errors`, `types`, `types/init`, `plugins/emailpassword`, `plugins/magiclink`, `plugins/phonenumber`, `plugins/emailverification`

## Context and problem

A flow runs hook chains that can stop it. A before chain can stop it (`Dispatcher.RunBefore`), and so can a data hook inside a store write. In both cases the flow gets back one error and has to answer three questions:

- Is this a refusal of the request, or did the system fail?
- If it is a refusal, which code does the flow's failed point report?
- Where does the real reason go?

The failed point matters because it is audited and counted. A lockout rule, a dashboard and the audit log all read it.

Before this decision, each place that ran a chain answered for itself, and the answers differed:

- `types.WithLifecycle` fired the failed point for every error from the before chain, with the code `rejectedByHook`.
- The three sign-in flows fired it for every error from `auth.signIn.credentialsVerified`, with the code `secondFactorRejected`. The point was added for a second factor, but any plugin can register a handler on it. The email verification plugin refuses an unverified address there, and the audit event named a second factor that was never involved.
- Sign-up, password reset and phone verification fired it for a data hook's error only when a private `isRejection` function said so. Two plugins each had a copy, written differently.

This produced two wrong behaviors:

- A system error inside a before handler, such as a database lookup that failed, was audited and counted as a failed sign-in for that user. The password was right and nothing had refused the user.
- The failure code named a cause the firing site could not know.

A second, smaller problem sat next to it. A failure code was camelCase (`invalidCredentials`), and the error code a client receives was snake_case (`invalid_credentials`). The same refusal had two spellings.

## Decision drivers

In priority order:

1. A system failure is never audited or counted as a refused request.
2. A new flow or plugin gets the right behavior without its author knowing the rule.
3. The audit event says what actually refused the request.
4. The set of values of the metric's `reason` attribute stays small and under behemoth's control.
5. An application's own `Dispatcher` and its hook handlers need no change.

## Options considered

### Option A: a constant and an exported `IsRejection`, used by each site

Each site checks `behemotherr.IsRejection(err)` and calls `Dispatcher.Fail` with a shared constant for the code.

- **Pros:** Small. No new function in `types`.
- **Cons:** Each site still writes the same five lines and has to remember both parts.
- **Fails when:** A new plugin runs a before chain and calls `Fail` without the check. This is how the three behaviors above came to differ.

### Option B: a field on `DomainError` that says business or system

The error states which kind it is. Firing sites read the field.

- **Pros:** The handler's author decides outright, case by case.
- **Cons:** It is a second source of truth next to the error's category. Every constructor and every plugin author has to set it.
- **Fails when:** The two disagree, for example a `CategoryDatabase` error marked as a business error. Nothing can say which one is right.

### Option C: take the failure code from the handler's error

The firing site reports the error's own code (`email_not_verified`) as the failure code.

- **Pros:** The audit event's code is the exact reason.
- **Cons:** The failure code is also the metric's `reason` attribute. An untyped error has no code, so a fallback is needed anyway.
- **Fails when:** A plugin defines many error codes, or builds one from input. Each becomes a metric label value, and the number of time series is no longer bounded.

### Option D: the dispatcher decides inside `RunBefore`

`RunBefore` fires the failed point itself when a handler refuses.

- **Pros:** Nothing for a flow to remember.
- **Cons:** `RunBefore` would need the flow's failed point and the subject of the refusal, so its signature changes, and an application's own `Dispatcher` changes with it.
- **Fails when:** A data hook refuses a write. That error comes out of `Store.Transaction`, not out of `RunBefore`, so those sites would still decide for themselves.

### Option E: one function in `types` that reports a chain's error

`types.FailIfRejected(dispatcher, hctx, failed, err, reason)` takes the error, the flow's failed point, and what only the site knows: the subject and the metadata. It fires the failed point for a rejection and returns the error the flow should return.

- **Pros:** One call per site. The rule and the code are in one place. It serves a before chain and a data hook's error alike.
- **Cons:** A site can still call `Dispatcher.Fail` directly and skip it. The rule is a convention, with a helper that makes it the short path.
- **Fails when:** A handler refuses with an untyped error or a category that is not a rejection. The flow stops, and the refusal is not audited.

## Decision

We chose Option E, with these parts:

- **The category decides what a rejection is.** `behemotherr.Category.IsRejection` holds the list: validation, conflict, unauthorized, forbidden and rate limited. `behemotherr.IsRejection(err)` applies it. An untyped error is not a rejection.
- **A chain's error is reported through `types.FailIfRejected`.** `WithLifecycle` and every flow body that runs a chain call it.
- **The code is always `types.FailureRejectedByHook`.** The site can't know which handler refused. The handler's error is the reason's `Cause`.
- **The audit event carries the cause's own code.** A cause that is a `DomainError` with a code adds `causeCode` to the event's metadata. It is not a metric attribute.
- **A failure code is snake_case,** like an error code a client receives. Where both name the same thing, they are the same string.

`secondFactorRejected` is removed. A second-factor plugin reports its own failures from its own flow, with its own code.

## Rationale

Option E is the only one that meets the first two drivers together. The check for a system failure is inside the helper, so a site that uses the helper can't get it wrong, and using the helper is less code than not using it.

- **Option A** meets the first driver only when every author remembers the check. The code before this decision shows that they don't.
- **Option B** adds a way for an error to contradict itself, and solves nothing the category does not already solve. No case came up where one category has to be both a refusal and a system failure.
- **Option C** gives the best audit event and fails the fourth driver. We kept its benefit another way: the cause's code goes into the audit metadata, where the number of distinct values costs nothing.
- **Option D** fails the fifth driver and still leaves the data hook sites out.

Deriving the answer from the category also matches how the rest of the system already treats an error: the category picks the HTTP status.

The casing follows from the `causeCode` key. One audit event now shows a failure code beside an error code, and two spellings of the same idea in one row is a defect a reader notices. Error codes are part of the HTTP contract and can't change, so the failure codes moved.

## Consequences

- **Gains:**
  - A system error inside a before handler no longer fires a failed point, in any `WithLifecycle` flow or at the sign-in checkpoint.
  - A hook's refusal has one code everywhere, and the audit event has the handler's own code next to it.
  - The private copies of `isRejection` and the string literals for the code are gone.
- **Costs and risks we accepted:**
  - Every failure code changed its spelling, and `secondFactorRejected` no longer exists. An application that filters audit events or metrics on the old values has to change. Stored audit rows keep the old spelling, and no migration rewrites them.
  - A handler that refuses with an untyped error stops the flow without an audit event. The `BeforeHookFunc` contract already asks for a typed error, and now a missing one costs the audit record as well.
  - The list of rejection categories is short. `not_found`, `duplicate_key`, `session` and `token` are not on it, so a handler that refuses with one of them is taken as a system failure.
- **Follow-up work:** `docs/ongoing.md` holds the open question of which further categories count as a rejection ("Which error categories count as a rejection").

## Invariants

- **A flow reports the error of a hook chain only through `types.FailIfRejected`.** If a site calls `Dispatcher.Fail` for such an error directly, an outage inside a handler is counted as a refused request again, and a lockout rule built on the failed point can lock a user out for it.
- **`behemotherr.Category.IsRejection` is the only place that says which categories are refusals.** If a second list appears, two flows disagree about the same error.
- **A hook's refusal has the code `types.FailureRejectedByHook`, whatever the point and whichever handler.** If a site picks a more specific code, it names a cause it can't know, which is the defect that started this record.
- **A failure code never comes from a handler's error or from input.** It is a metric label value. If it does, the number of time series is unbounded.
- **A failure code is snake_case.** If one is not, the same refusal has two spellings in one audit event.

## Revisit when

- A handler needs to refuse with a category that is not on the list, and adding the category to the list would be wrong for other errors of that category. That is the case Option B was for.
- A flow needs to tell two hook refusals apart in a metric, not only in the audit log.
- A site appears that cannot use the helper, for example because it has to fire the failed point before it knows the subject.
- `Dispatcher` gains a method for another reason. Moving the helper's work behind the interface (Option D) is then cheaper.

## References

- `errors/errors.go`: `Category.IsRejection`, `IsRejection`
- `types/plugins.go`: `FailureRejectedByHook`, `FailIfRejected`, `WithLifecycle`
- `types/init/init.go`: `auditEvent`, which adds `causeCode`
- `tests/plugins/hook_rejection_test.go`, `errors/rejection_test.go`
- [`../hooks/5. Hook Dispatching.md`](<../hooks/5. Hook Dispatching.md>): how the dispatcher and `WithLifecycle` work
- [`../telemetry/audit.md`](../telemetry/audit.md): the audit event's fields
- [`../guidelines/http_contract.md`](../guidelines/http_contract.md): the casing of codes and keys
