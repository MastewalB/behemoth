# Telemetry Plan: Logging, Audit, Metrics and Tracing

This document is the plan for finishing behemoth's logging, audit, metrics and tracing. It describes what exists today, the target design for each concept, the order of work, and the decisions already made. Nothing in the "target" sections is built yet unless the "Where things stand" section says so.

When a phase lands, its section moves into a document of its own under `docs/internal/telemetry/` that describes the code as built, and the phase is struck from this plan.

## Where things stand

Three phases are built:

- Phase 1, foundations (`foundations.md`): the `telemetry` package, field keys, `ErrorFields`, redaction, the request ID, the slog logger, `telemetrytest`.
- Phase 2, logging (`logging.md`): named loggers per component, request failures logged by the router, statement logging in the SQL adapters, the boot summary.
- Phase 3, audit (`audit.md`): the event model, the `audit_log` core table, the database recorder with querying and purging, in-transaction recording for user writes, actor and subject, audited core points.

The interfaces live in `telemetry/` and reach components as a `*telemetry.Telemetry` taken from `BootConfig.Telemetry`. A nil value becomes a set of no-ops through `telemetry.OrDefault`, except for audit, where `Boot` then uses the database recorder.

| Concept | Defined | Used by |
| --- | --- | --- |
| Logger | `Debug`, `Info`, `Warn`, `Error`, each taking a `context.Context`, a message and a `behemoth.M` of fields. Redacted and tagged with the request ID by `telemetry.New`. | every component that swallows an error, the router for request failures, `Boot`, the SQL adapters. See the table in `logging.md`. |
| Audit | `AuditRecorder`, `TxAuditRecorder`, `AuditReader`, the database recorder in `store` | the hook dispatcher for audited points, the rate limiter, the migration runner, the key manager. See the event table in `audit.md`. |
| Metrics | `Counter`, `Gauge` | no call sites |
| Tracing | nothing | nothing |

Gaps the remaining phases close:

- **Nothing is measured.** `Metrics` has no call sites, so rejections, failed audit writes and hook errors are visible only as log lines or audit rows.
- **Nothing is traced.**

## Shape: taxonomy in core, backends in adapter modules

Behemoth's part is a thin layer: interfaces, names and conventions. A real backend does the work. This is the same split as the error taxonomy (`errors/` defines categories and codes, `ErrorMapper` adapts them to HTTP) and the storage layer (`storage.go` defines `Database`, each adapter lives in its own module).

| Piece | Location | Depends on |
| --- | --- | --- |
| Interfaces, no-ops, field keys, audit event types, metric names, span names, request-ID helpers, redaction | `telemetry/` in the root module | standard library |
| Logger backed by `log/slog` | `telemetry/` in the root module | standard library |
| In-memory recorder for tests | `telemetry/telemetrytest/` | standard library |
| Database audit recorder | `store/` | the store, like other core tables |
| OpenTelemetry logger, metrics and tracer | `telemetry/adapters/otel/`, with its own `go.mod` | the OpenTelemetry API |

Notes on backends:

- **Stdout** is the slog logger with a text or JSON handler.
- **Zap and zerolog** plug in through their slog handlers. They need no adapter of their own.
- **Jaeger** has no adapter of its own. Jaeger's client libraries are deprecated and Jaeger ingests OTLP, so it is the OpenTelemetry adapter with an OTLP exporter pointed at a Jaeger endpoint.
- **Exporter lifecycle** belongs to the application. It creates the providers and exporters, passes them to the adapter, and flushes and shuts them down. This matches the HTTP ownership boundary described in `docs/internal/http/request_routing.md`.

The first three rows are built. `types` imports `telemetry`; `telemetry` imports only the root package and `errors`.

## 1. Logging

### Interface

The four methods stay as they are. One helper is added:

```go
// Named returns a Logger that adds component to every line.
sessionLog := telemetry.Named(tel.Logger, "session")
```

Each component takes a named logger at construction, so a reader can filter a deployment's logs down to `component=ratelimit`.

### Standard fields

Field keys are constants in `telemetry/`, not strings at call sites.

| Key | Meaning |
| --- | --- |
| `component` | the behemoth component writing the line, set by `Named` |
| `op` | the operation, in the same form as `DomainError.Op` |
| `request_id` | see Request correlation below |
| `trace_id`, `span_id` | added by a tracing-aware backend from the context |
| `user_id`, `session_id` | when known |
| `plugin`, `point` | for hook dispatch |
| `error`, `error_code`, `error_category` | see below |

`telemetry.ErrorFields(err)` returns the last three plus the internal message. For a `*DomainError` it reads `Category`, `Code` and `InternalMessage`; for any other error it sets `error` to `err.Error()` and `error_code` to `unknown_error`. Call sites use it instead of building the `error` field by hand.

### Levels

| Level | Meaning | Examples |
| --- | --- | --- |
| Error | behemoth failed at something it owed | a 5xx response, a hook handler panic, a failed audit write |
| Warn | behemoth continued in a degraded state | session cache write failed, rate-limit store unavailable with fail-open, secret watch could not start |
| Info | lifecycle events | boot summary, migration applied, key rotation applied |
| Debug | per-request detail | SQL statement text, hook chain steps |

A business rejection (wrong password, expired token) is not an Error. It is an audit event and a metric, and a Debug line at most.

### Redaction

The logger wrapper applies redaction before a backend sees the fields.

- A key denylist replaces the value of `password`, `token`, `secret`, `hash`, `cookie` and `authorization` (matched case-insensitively, also as a suffix such as `refresh_token`).
- Email addresses are not logged by default. See the decision "Email addresses in logs".
- SQL argument values are never logged. Debug lines carry the statement text only.

### Integration work

Done; see `logging.md`. Two points differ from what this plan first said:

- The store logs nothing, and the token manager logs one line. On inspection neither swallows errors: they return them, and the router logs what reaches it.
- `PluginContext` was deleted. A plugin names its own logger from `AuthContext.Telemetry`.

## 2. Audit

Done; see `audit.md`. Points that differ from what this plan first said:

- `ActorID` and `SubjectID` are strings, not `any`. Every id behemoth stores is a string, and a typed column can be indexed and filtered.
- Audit ids are UUIDv7, and pages are ordered by id. The plan did not say how paging would stay stable.
- In-transaction recording goes through an optional interface, `TxAuditRecorder`, so an application's own recorder is still honored for the data points: it is called after the commit.
- The data events are named `user.created` and `user.updated`, not after their hook points.
- There is no "password changed" event, because no flow changes a password yet.
- A failed best-effort write is logged at Error. The `audit.record_failures` metric waits for phase 4.

Still deferred: an HTTP route for querying (needs an authorization model), tamper evidence, and a fail-closed mode for best-effort events.

## 3. Metrics and tracing

### Metrics interface

```go
type Metrics interface {
	Counter(ctx context.Context, name string, delta int64, attrs behemoth.M)
	Histogram(ctx context.Context, name string, value float64, attrs behemoth.M)
}
```

The context lets a backend attach exemplars that link a measurement to a trace. `Gauge` is removed: nothing in the library reports a level, and no call site uses it.

Attribute values are bounded. A route is its pattern (`/users/{id}`), not the request path. User IDs, session IDs, IP addresses and emails are never attributes.

### Metric catalog

| Metric | Type | Attributes |
| --- | --- | --- |
| `behemoth.http.requests` | counter | route, method, status |
| `behemoth.http.duration` | histogram | route, method, status |
| `behemoth.auth.sign_in`, `behemoth.auth.sign_up` | counter | plugin, outcome, reason code |
| `behemoth.session.created`, `behemoth.session.revoked` | counter | |
| `behemoth.session.validated` | counter | cache hit or miss, outcome |
| `behemoth.token.issued`, `behemoth.token.consumed`, `behemoth.token.failed` | counter | kind |
| `behemoth.ratelimit.checks` | counter | rule, result |
| `behemoth.hook.duration` | histogram | point, plugin |
| `behemoth.hook.errors` | counter | point, plugin |
| `behemoth.store.duration` | histogram | op, entity |
| `behemoth.store.errors` | counter | op, entity, error category |
| `behemoth.audit.record_failures` | counter | type |

### Tracing interface

`Telemetry` gains a `Tracer`, with a no-op default.

```go
type Tracer interface {
	Start(ctx context.Context, name string, attrs behemoth.M) (context.Context, Span)
}

type Span interface {
	SetAttributes(attrs behemoth.M)
	RecordError(err error)
	End()
}
```

### Span sites

| Span | Started by |
| --- | --- |
| one per behemoth route | the router's wrapping pipeline |
| one per hook chain, with a child per handler | `DefaultDispatcher` |
| store operations and `Store.Transaction` | `store` |
| session create, validate, revoke | `DefaultSessionManager` |
| token issue, consume | `DefaultTokenManager` |
| password hashing and verification | `crypto` |
| rate-limit check | `DefaultRateLimiter` |
| each applied migration | the migration runner |

Behemoth does not read trace headers. The application's framework middleware puts the parent span on the request context, and behemoth's spans nest under it because every span is started from that context.

SQL-level spans are left to driver instrumentation such as `otelsql`. Behemoth's store spans describe the operation (`store.users.create`), not the statement.

## Related areas

- **Request correlation.** Built for logs and audit events; see `foundations.md` and `audit.md`. Spans get the ID in phase 5 through `telemetry.RequestIDFrom(ctx)`.
- **Health.** `AuthContext.Health(ctx)` checks the database, the KV store and the key manager and returns a per-component result. The application exposes it on its own readiness endpoint; behemoth mounts no health route.
- **Test helpers.** `telemetrytest` has an in-memory logger, audit recorder and metrics sink. A tracer is added in phase 5.
- **Catalogs as contract.** Field keys, audit event types, metric names and span names are public once released. Renaming one is a breaking change for dashboards and alerts, so they are documented in `docs/api/telemetry.md` and changed only with a release note.

## Order of work

| Phase | Content |
| --- | --- |
| ~~1. Foundations~~ | done; see `foundations.md` |
| ~~2. Logging~~ | done; see `logging.md` |
| ~~3. Audit~~ | done; see `audit.md` |
| 4. Metrics | new interface, the metric catalog, call sites |
| 5. Tracing | `Tracer`, span sites, the `telemetry/adapters/otel` module |
| 6. Docs and example | `docs/api/telemetry.md`, per-concept internal docs, an example wiring stdout and OTLP |

Phase 5 can be built before or after phase 4.

## Design decisions

### Telemetry is a thin taxonomy over external backends
**Context:** Behemoth needs logs, audit events, metrics and traces, and applications already run a logging and observability stack of their own.
**Options considered:**
- *Depend on the OpenTelemetry API in the root module.* One standard interface for all three signals. Every user of behemoth pulls in the OpenTelemetry dependency tree, including those who only want stdout logs.
- *Take a `*slog.Logger` directly and define nothing for metrics and traces.* No interface to maintain for logging. Leaves metrics and tracing without a seam, and call sites pick field names freely.
- *Define small interfaces and a naming taxonomy in core, with backends as adapters.* More code to maintain. The root module stays on the standard library, and the names (field keys, event types, metric names) are owned by behemoth and stay the same across backends.
**Decision:** The third option, the same split as the error taxonomy and the storage adapters. Core ships the slog-backed logger; OpenTelemetry lives in `telemetry/adapters/otel` with its own `go.mod`. Jaeger is reached through the OpenTelemetry adapter over OTLP and has no adapter of its own.
**Revisit if:** the interfaces start to mirror the OpenTelemetry API method for method, at which point depending on it directly is simpler.

### Audit is recorded by default
**Context:** `BootConfig.Telemetry == nil` currently means a no-op audit recorder, so an application that configures nothing has no audit trail, and `audit_log` is not declared by any schema.
**Options considered:**
- *Opt-in.* Keeps today's default and adds no writes. An application finds out it has no audit trail when it first needs one.
- *On by default, with an opt-out.* `audit_log` is a core table and the database recorder is the default. Each audited action costs one extra insert, and the table grows until the application purges it.
**Decision:** On by default. `audit_log` is declared by core and created by the migration engine like the other core tables. When `Telemetry.Audit` is nil, `Boot` uses the database recorder. An application opts out, or sends events elsewhere, by setting `Telemetry.Audit` to another recorder (a no-op recorder is exported for this).
**Revisit if:** the extra insert shows up as a measurable cost on the sign-in path.

### Audit rows for data writes commit with the write
**Context:** An audit event recorded after commit is lost if the process stops between the commit and the callback. An event recorded before commit through a separate connection can describe a row that was rolled back. This was raised in `docs/ongoing.md` as "Should data points be audited, and how reliably".
**Options considered:**
- *Best effort everywhere.* One code path. A crash at the wrong moment loses the record of a user being created or changed.
- *In the transaction for data writes, best effort elsewhere.* The dispatcher records through the transaction-bound store (`hctx.Tx`) when there is one. Needs the recorder to accept a transaction-bound store, and `RunAfterTx` to record where today it deliberately does not.
- *An outbox table drained by a worker.* Reliable for every event. Needs a background worker, which behemoth does not run.
**Decision:** The second option. Events for data points are written inside the write's transaction and commit or roll back with the row. Events with no transaction (a failed sign-in, a rate-limit rejection, an applied migration) are best effort: a failed write is logged at Error and counted, and the request proceeds.
**Revisit if:** a compliance requirement needs every event to be durable, which would call for the outbox or a fail-closed mode.

### Email addresses in logs
**Context:** Logs are often shipped to third-party services and kept under looser access control than the database. An email address identifies a person; a user ID does not without database access.
**Options considered:**
- *Log emails.* Easiest to debug from logs alone. Spreads personal data into every log sink.
- *Log user IDs only.* Logs hold no personal data by default. Debugging a sign-in problem for a known email needs a lookup of the ID first, or the audit log.
**Decision:** Logs carry user IDs only by default. Audit rows keep the email, because the audit log is in the application's database and is the record of who did what. A logging option lets an application allow emails in logs.
**Revisit if:** other personal fields (IP address, user agent) need the same treatment in logs.
