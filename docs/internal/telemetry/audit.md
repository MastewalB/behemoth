# Audit

This document describes the audit log as built: the event model, how an event is produced and by whom, where it is stored, and what is guaranteed about it. It is phase 3 of `plan.md`.

An audit event differs from a log line in purpose. A log line is for whoever operates the system and may be dropped or sampled. An audit event is the record of an action on an account: who did what to whom, and how it ended. It is stored in the application's database and queried.

The code lives in:

- `telemetry/audit.go`: `AuditEvent`, the recorder and reader interfaces, `NormalizeAuditEvent`, `Telemetry.RecordAudit`, `MultiRecorder`
- `models/audit.go`, `models/schema.go`: the `AuditLog` model and the `audit_log` table
- `store/audit.go`: `Store.RecordAuditEvent`, `QueryAuditEvents`, `PurgeAuditEvents`, and `store.AuditRecorder`
- `types/init/init.go`: `DefaultDispatcher.auditEvent`, `recordAudit`, `recordAuditTx`, the `AuditSpec` declarations in `CoreDeclareHookPoints`, the default recorder in `Boot`

## Components

```
 firing site                         dispatcher                          recorder
 ───────────                         ──────────                          ────────
 RunAfter / Fail  ───────────────►  auditEvent ─► Telemetry.RecordAudit ─► Audit.Record        best effort
 (flows, managers)                                 (normalize, log a failure)

 RunAfterTx       ───────────────►  auditEvent ─► NormalizeAuditEvent ──► TxAuditRecorder.RecordTx(hctx.Tx.DB())
 (the store's data hooks)                                                  in the write's transaction
                                                                      └─► other recorders, after commit

 rate limiter, migration runner,
 key manager      ──────────────────────────────► Telemetry.RecordAudit ─► Audit.Record        best effort
```

| Type | Role |
| --- | --- |
| `telemetry.AuditRecorder` | write side: `Record(ctx, event)` |
| `telemetry.TxAuditRecorder` | a recorder that can also write through a transaction: `RecordTx(ctx, tx, event)` |
| `telemetry.AuditReader` | read side: `Query(ctx, filter)` returning an `AuditPage` |
| `store.AuditRecorder` | the database implementation of all three, over a `*store.Store` |
| `telemetry.MultiRecorder` | fans one event out to several recorders |
| `telemetry.NoOpAuditRecorder` | drops events; passing it turns auditing off |

The recorder and the reader are separate interfaces because a sink such as a log stream can record an event and cannot query one.

## The event

```go
type AuditEvent struct {
	ID          string       // assigned by the recorder
	Type        string
	Outcome     AuditOutcome // success | failure | denied
	ActorType   ActorType    // user | anonymous | system
	ActorID     string
	SubjectType string       // a table's canonical name for a row: "users", "sessions", "tokens"
	SubjectID   string
	SessionID   string
	RequestID   string
	IPAddress   string
	UserAgent   string
	Metadata    behemoth.M
	Timestamp   time.Time
}
```

`failure` and `denied` differ in when the action stopped. A failure was attempted and rejected (a wrong password, an expired token). A denial was stopped before the attempt (a rate limit).

`NormalizeAuditEvent(ctx, event)` fills what a producer left out:

| Field | When empty |
| --- | --- |
| `Timestamp` | now, UTC |
| `RequestID` | the context's request ID |
| `Outcome` | `success` |
| `ActorType` | `user` if `ActorID` is set, `anonymous` inside a request, `system` otherwise |
| `Metadata` | always replaced by a redacted copy. The log redaction rules apply, except that email addresses are kept. |

`Telemetry.RecordAudit(ctx, event)` normalizes, calls `Audit.Record`, and reports a failed write through `Telemetry.AuditFailed`: an Error line with the event's type and one `behemoth.audit.record_failures`. Every producer outside the dispatcher's transaction path records through it, so no audit failure is dropped silently. Before this phase the rate limiter and the migration runner ignored the error.

### Event types

An event recorded for a hook point is named after the point unless its `AuditSpec` gives a type. The others are constants in `telemetry`.

| Type | Produced by | Outcome | Written |
| --- | --- | --- | --- |
| `user.created` | `data.user.afterCreate` | success | in the insert's transaction |
| `user.updated` | `data.user.afterUpdate` | success | in the update's transaction |
| `user.deleted` | `data.user.afterDelete` | success | in the delete's transaction |
| `auth.signUp.after` | sign-up | success | best effort |
| `auth.signUp.failed` | sign-up | failure | best effort |
| `auth.signIn.after` | sign-in | success | best effort |
| `auth.signIn.failed` | sign-in | failure | best effort |
| `auth.signOut.after` | sign-out | success | best effort |
| `auth.session.afterCreate` | session manager | success | best effort |
| `auth.session.afterRevoke` | session manager | success | best effort |
| `token.afterIssue` | token manager | success | best effort |
| `token.consumed` | token manager | success | best effort |
| `token.failed` | token manager | failure | best effort |
| `ratelimit.exceeded` | rate limiter | denied | best effort |
| `migration.applied` | migration runner | success | best effort |
| `crypto.secret.rotated` | key manager | success | best effort |

The two data events have types of their own (`user.created`, not `data.user.afterCreate`) because the hook point name describes when a handler runs, and the event describes what happened to the user.

`[Not built]` There is no "password changed" event, because no flow changes a password yet. The flow that adds it declares the audited point.

## How the dispatcher builds an event

A point declared with `Audit: &types.AuditSpec{}` records one event per dispatch, after its chain. `DefaultDispatcher.auditEvent` builds it from what the dispatcher can see.

**Subject**, first match:

1. `FailureReason.SubjectType` and `SubjectID`, for a failed point. The sign-in flow sets them once it has found the user, so a wrong password is recorded as an attempt on that account.
2. The result (`auditSubject`): a `*models.Session` is its own subject; a result implementing `types.AuditSubject` says what it is about (`types.SignInResult` and `magiclink.LinkResult` name their user); any other `behemoth.Model` is its table and primary key.
3. `HookContext.Values[HookValueUserID]`, the user the operation concerns.

**Actor**, first match:

1. The user of the session the request was authenticated with: `RequestContext.Values["session"]`, which `types.RequireSession` sets.
2. For a successful operation inside a request, the user the subject belongs to. This covers sign-up and sign-in, where no session exists yet and the user acts for themselves.
3. Otherwise `anonymous` inside a request and `system` outside one.

A failed operation is never attributed to its subject. A wrong password for an account was not typed by its owner as far as behemoth knows, so the event has that account as subject and an anonymous actor.

**Other fields:**

| Field | Source |
| --- | --- |
| `Outcome` | `failure` for `Fail`, otherwise left to normalization (`success`) |
| `Metadata` | for `Fail`: `FailureReason.Metadata`, then `code`, and `cause` when the reason has one. For a token result: `kind`. |
| `SessionID` | the request's session; else the result's, when it is a session; else `Values[HookValueSessionID]` |
| `IPAddress` | `types.ClientIP` with the router's proxy configuration, so it is the same address a session and a rate limit see |
| `UserAgent` | the request's `User-Agent` header |

`FailureReason.Metadata` carries what was attempted when there is no subject to name. A sign-in for an address with no account records the address there.

`[Limit]` `HookContext.Values` are not used to pass audit detail from a flow, apart from the two keys above that were already part of the hook contract. Handlers see `Values`, and a flow that published extra keys for the dispatcher would change what every handler observes.

### The actor of a write is derived, not passed
**Context:** The dispatcher has to say who did something, and no firing site passes an actor.
**Options considered:**
- *Add an actor to `HookContext`.* Explicit. Every firing site and every caller of a flow would have to set it, and most have nothing to set: sign-in has no session until it succeeds.
- *Derive it from the request's session and the operation's subject.* No change at firing sites. The rule for unauthenticated success (the subject's user is the actor) is a convention and is wrong for an operation one user performs on another without a session on the request.
**Decision:** Derive it. With `RequireSession` on a route the actor is exact. Without a session the rule is right for the two flows that have none by nature.
**Revisit if:** an admin flow acts on other users through code paths that carry no session, at which point an explicit actor on the context is needed.

## Reliability

An event is written one of two ways, by which dispatcher method fires its point.

### Best effort: `RunAfter` and `Fail`

The operation is over when the event is recorded. `recordAudit` calls `Telemetry.RecordAudit`; a failed write is logged at Error and changes nothing. A process that stops between the operation and the write loses the event.

### In the transaction: `RunAfterTx`

`data.user.afterCreate` and `data.user.afterUpdate` run inside the write's transaction, with `HookContext.Tx` bound to it. `recordAuditTx` runs once the chain has passed:

1. Build and normalize the event.
2. Split the recorder with `telemetry.SplitAuditRecorders`, which looks inside a `MultiRecorder`.
3. Call `RecordTx(hctx.Ctx, hctx.Tx.DB(), event)` on each recorder that implements `TxAuditRecorder`. An error is returned, the store rolls the write back, and the caller gets the error.
4. Queue every other recorder on `hctx.Tx.AfterCommit`. They are called once the outermost transaction has committed, best effort, and never for a write that rolled back.

So with the database recorder a user row and its audit row commit together or not at all. With a recorder that cannot join a transaction, the event is never recorded for a rolled-back write, and may be lost if the process stops after the commit.

A dispatch with no `HookContext.Tx` (a caller other than the store) has no transaction to join and records best effort.

`[Consequence]` A database without the `audit_log` table cannot write users while the database recorder is in use: the audit insert fails and takes the user write with it. The table is a core table and the migration engine creates it. An application upgrading from a version without it has to run its migrations before it serves requests.

### A failed in-transaction audit write fails the write
**Context:** The audit insert runs in the user write's transaction. It can fail on its own (a missing table, a full disk).
**Options considered:**
- *Log it and let the write commit.* The user is created and the audit row is not, which is the gap in-transaction recording exists to close. On PostgreSQL it is also not possible without a savepoint: a failed statement aborts the transaction.
- *Return the error.* The write fails with the audit insert. A broken audit table stops sign-ups.
**Decision:** Return the error. The data points promise that the row and its event commit together, and an audit log that silently misses writes is worse than a visible failure.
**Revisit if:** availability of sign-up has to outrank the audit trail, which would call for a configuration switch.

## Storage

### The table

`audit_log` is a core table, declared in `CoreDeclareSchema` like `users` and `sessions`.

| Column | Type | Note |
| --- | --- | --- |
| `id` | string(36), primary key | UUIDv7 |
| `event_type` | string(128) | `AuditEvent.Type`. Not `type`: adapters emit column names unquoted. |
| `outcome`, `actor_type` | string(16) | |
| `actor_id`, `subject_id` | string(255), nullable | |
| `subject_type` | string(64), nullable | |
| `session_id` | string(36), nullable | |
| `request_id` | string(128), nullable | |
| `ip_address` | string(64), nullable | |
| `user_agent` | text, nullable | |
| `metadata` | json, nullable | stored as JSON text, like `tokens.metadata` |
| `created_at` | timestamp | `AuditEvent.Timestamp` |

Indexes: `event_type`, `actor_id`, `subject_id`, `request_id`, `created_at`.

There is no foreign key to `users`. An event outlives the user it is about.

An empty optional value is stored as NULL (`models.AuditLog.ToMap`), so "no actor" is one value in the column.

### The store

- `Store.RecordAuditEvent(ctx, event)` inserts one row with a new id. It writes through `s.db` directly: the table fires no data hooks. On a store bound to a transaction the row belongs to it.
- `Store.QueryAuditEvents(ctx, filter)` returns one page, newest first.
- `Store.PurgeAuditEvents(ctx, before)` deletes the events recorded before a time. Behemoth never calls it; the application runs it from its own scheduled job.

There is no operation to change or delete one event.

`store.AuditRecorder` wraps a store as a recorder. Its `RecordTx` copies the store, binds the copy to the transaction's adapter and inserts through it.

### Paging

`AuditFilter` selects by types, outcome, actor, subject, session, request ID and a time range (`From` inclusive, `To` exclusive), with `Limit` (default 50, at most 500) and `Cursor`.

Events are ordered by `id` descending, and the cursor is the id of the last event of the page: the next page is `id < cursor`. `QueryAuditEvents` asks for one row more than the page to learn whether another follows.

### Audit ids are UUIDv7 and the page order
**Context:** `Database.FindMany` orders by one column and pages by limit and offset. The audit log needs a stable newest-first order.
**Options considered:**
- *Order by `created_at`, page by offset.* Uses what exists. Events recorded while a caller pages shift every later page, so events are repeated. Two events in one timestamp have no defined order.
- *Order by `created_at` and `id`, keyset on both.* Stable. Needs ordering by two columns, which `QueryOptions` cannot express.
- *Make the id time-ordered and order by it alone.* One column gives a total order that follows recording time, and a keyset cursor is one condition.
**Decision:** UUIDv7 ids, ordered by `id`. `newAuditID` falls back to a random UUID when the clock or entropy source fails, which keeps ids unique and loses order for that event.
**Revisit if:** events are recorded by several processes whose clocks disagree by more than the application tolerates in the order. The `From` and `To` filters use `created_at` and are not affected.

## The default recorder

`Boot` uses the database recorder unless the application chose one:

```go
tel := telemetry.OrDefault(cfg.Telemetry)
if !tel.AuditConfigured() {
	tel.Audit = store.NewAuditRecorder(store.New(db, store.WithSchema(app.Resolver)))
}
```

- `telemetry.New` puts an unexported `unsetAuditRecorder` in place of a nil recorder. It drops events like the no-op, and `AuditConfigured` reports false for it. That is how "not chosen" is told apart from `NoOpAuditRecorder{}`, which is a choice.
- The recorder gets a store of its own, without data hooks or an encryptor. It is built before the crypto suite, so the key manager can record a rotation, and the table uses neither.

To keep the table and add a sink, the application passes `telemetry.MultiRecorder(store.NewAuditRecorder(st), sink)`. The dispatcher finds the database recorder inside it, so the data events are still written in their transaction.

## Not built

- An HTTP route to query events. It needs an authorization model behemoth does not have. Reading is a Go API: `ac.Store.QueryAuditEvents`.
- Tamper evidence, such as a hash chain over rows.
- A fail-closed mode for best-effort events.
