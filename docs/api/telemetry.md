# Telemetry

Behemoth reports what it does through three sinks: a logger, an audit recorder and a metrics sink. The logger and the metrics sink are optional and silent when you leave them out. Audit is on by default and writes to the `audit_log` table.

This page covers logging, request IDs and the audit log. The metric catalog and tracing are not built yet; the metrics interface exists so the configuration below will not change shape when they arrive.

## Setup

Build a `Telemetry` with `telemetry.New` and pass it to `Boot`:

```go
import (
	"log/slog"
	"os"

	"github.com/MastewalB/behemoth/telemetry"
)

tel := telemetry.New(
	telemetry.NewJSONLogger(os.Stdout, slog.LevelInfo), // logger
	nil, // audit recorder: the default, the audit_log table
	nil, // metrics: none
)

ac, err := binit.Boot(ctx, app, db, binit.BootConfig{
	Crypto:    cryptoCfg,
	Telemetry: tel,
})
```

A nil logger or metrics sink means none. A nil audit recorder means the default; see [Audit](#audit). `BootConfig.Telemetry` itself may be nil.

## Choosing a logger

| You want | Use |
| --- | --- |
| readable lines on stdout | `telemetry.NewTextLogger(os.Stdout, slog.LevelInfo)` |
| JSON lines on stdout | `telemetry.NewJSONLogger(os.Stdout, slog.LevelInfo)` |
| your existing `*slog.Logger` | `telemetry.NewSlogLogger(logger)` |
| zap or zerolog | their slog handler, through `telemetry.NewSlogLogger(slog.New(handler))` |
| anything else | implement `telemetry.Logger` |

The interface has four methods:

```go
type Logger interface {
	Debug(ctx context.Context, msg string, fields behemoth.M)
	Info(ctx context.Context, msg string, fields behemoth.M)
	Warn(ctx context.Context, msg string, fields behemoth.M)
	Error(ctx context.Context, msg string, fields behemoth.M)
}
```

`fields` may be nil. The map you receive is yours to keep; Behemoth does not reuse it.

## What Behemoth does to every line

Whichever logger you pass, `telemetry.New` wraps it. Your backend receives fields that are already:

- **Redacted.** The value of a field whose key is, or ends with, `password`, `token`, `secret`, `hash`, `cookie`, `authorization` or `email` is replaced by `[REDACTED]`. Matching ignores case, so `newPassword` and `refresh_token` are covered. `tokenID` is not: it is an identifier.
- **Correlated.** A line written while handling a request has a `request_id` field.

Two options change redaction:

```go
tel := telemetry.New(logger, nil, nil,
	telemetry.WithEmailsInLogs(),               // let email addresses through
	telemetry.WithRedactedKeys("api_key", "otp"), // redact more keys
)
```

By default logs identify a user by ID only. Use `WithEmailsInLogs` if your log storage is allowed to hold email addresses.

Redaction works on field keys. Text inside a log message is not inspected.

## What Behemoth logs

| Level | When | Examples |
| --- | --- | --- |
| Error | Behemoth failed at something it should have done | a request answered with a 5xx, a hook handler that returned an error or panicked, a rejected secret rotation |
| Warn | Behemoth continued, with something degraded | a session cache write failed, the rate-limit store is unavailable, a configuration that is probably a mistake |
| Info | lifecycle | the boot summary, a secret rotation applied |
| Debug | per-request detail | a request that was rejected (wrong password, rate limit), SQL statements |

A rejected request is not an error. A wrong password or an expired token is logged at Debug only, so the Error level stays reserved for problems on your side.

Every line has a `component` field naming its source: `boot`, `router`, `hooks`, `ratelimit`, `session`, `token`, `crypto`, `migration`, a plugin's name such as `emailpassword`, or a storage adapter such as `storage.postgres`.

### Failed requests

A request that ends in a 5xx produces one Error line from the router:

```json
{"level":"ERROR","msg":"request failed","component":"router",
 "method":"POST","route":"/api/auth/sign-up/email","status":500,
 "error":"dial tcp 10.0.0.5:5432: connection refused",
 "error_code":"database_error","error_category":"database","op":"Create",
 "request_id":"5f2c8e0d9a7b4c1e8f3a6d2b9c4e7a10"}
```

The client receives only `{"error": "internal server error"}` and the `X-Request-ID` header, whose value matches `request_id`. `route` is the route's pattern, such as `/users/{id}`, not the path that was requested.

### Boot summary

When `Boot` succeeds it writes one Info line, `behemoth booted`, with the plugins in boot order (`plugins`), the number of routes (`routes`), whether they were mounted on an HTTP framework (`routes_mounted`), and whether a key-value store is configured (`kv`).

It also warns about configurations that work but are probably not what you meant. For now there is one: `RouterConfig.ClientIPHeader` set without `TrustedProxies`, in which case the header is ignored.

### SQL statements

The `sqlite`, `postgres`, `mysql` and `sqlserver` adapters can log each statement they run. This is off unless you give the adapter a logger:

```go
tel := telemetry.New(telemetry.NewTextLogger(os.Stdout, slog.LevelDebug), nil, nil)

db := pgAdapter.NewPostgresAdapter(conn, app.Resolver).WithLogger(tel.Logger)
```

Statements are logged at Debug, with the SQL text in the `statement` field. Argument values are never logged, so a line shows `WHERE email = $1` and not the address.

Pass `tel.Logger`, the logger `telemetry.New` returned, and not your raw logger, so statement lines get the request ID like every other line.

## Field names

Behemoth uses the same keys in every line. They are constants in the `telemetry` package.

| Constant | Key | Meaning |
| --- | --- | --- |
| `FieldComponent` | `component` | the part of Behemoth that wrote the line |
| `FieldOp` | `op` | the operation that failed |
| `FieldRequestID` | `request_id` | the request being handled |
| `FieldUserID` | `user_id` | |
| `FieldSessionID` | `session_id` | |
| `FieldPlugin` | `plugin` | the plugin a hook handler belongs to |
| `FieldPoint` | `point` | a hook point |
| `FieldError` | `error` | the error's text |
| `FieldErrorCode` | `error_code` | the error's code, or `unknown_error` |
| `FieldErrorCategory` | `error_category` | the error's category |
| `FieldMethod` | `method` | HTTP method |
| `FieldRoute` | `route` | a route's pattern |
| `FieldStatus` | `status` | HTTP status code |
| `FieldStatement` | `statement` | SQL text without values |
| `FieldTraceID`, `FieldSpanID` | `trace_id`, `span_id` | reserved for tracing backends |

## Request IDs

Every request to a Behemoth route has an ID. Behemoth takes it from, in order:

1. the request's context, if your own middleware stored one there with `telemetry.ContextWithRequestID`;
2. the `X-Request-ID` request header, if its value is 1 to 128 visible ASCII characters;
3. a newly generated ID.

The ID is returned in the same header of the response, including error responses, so a client can quote it in a bug report. Change the header with `RouterConfig.RequestIDHeader`:

```go
Router: types.RouterConfig{RequestIDHeader: "X-Correlation-ID"},
```

Read the ID in a route handler or a hook handler:

```go
id := telemetry.RequestIDFrom(rctx.Ctx) // in a route handler
id := telemetry.RequestIDFrom(hctx.Ctx) // in a hook handler; "" outside a request
```

## Logging from a plugin

A plugin takes the logger from the `AuthContext` and names itself, so its lines can be told apart:

```go
func (p *Plugin) Init(ac *types.AuthContext) error {
	p.log = telemetry.Named(ac.Telemetry.Logger, "invites")
	return nil
}

func (p *Plugin) accept(rctx *types.RequestContext) error {
	if err := p.redeem(rctx.Ctx, code); err != nil {
		p.log.Warn(rctx.Ctx, "invite could not be redeemed", telemetry.ErrorFields(err))
		return err
	}
	...
}
```

`ac.Telemetry` and its fields are never nil, so no checks are needed.

`telemetry.ErrorFields(err)` returns `error`, `error_code`, `error_category` and `op` for a Behemoth error, and `error` with the code `unknown_error` for any other. Pass your own fields as a second argument to have them in the same line:

```go
p.log.Warn(ctx, "invite could not be redeemed", telemetry.ErrorFields(err, behemoth.M{"invite_id": id}))
```

An error your route handler returns is logged by the router, so log only the errors you handle yourself.

## Audit

The audit log records actions on accounts: who signed up and signed in, which sign-ins failed and for which account, which sessions were created and revoked, which users were created or changed. A log line can be dropped; an audit event is stored in your database and can be queried.

### What is recorded

| Event type | When | Outcome |
| --- | --- | --- |
| `user.created`, `user.updated` | a user row is inserted or updated, by any flow | success |
| `auth.signUp.after`, `auth.signUp.failed` | a sign-up finished, or was refused | success, failure |
| `auth.signIn.after`, `auth.signIn.failed` | a sign-in finished, or was refused | success, failure |
| `auth.signOut.after` | a sign-out finished | success |
| `auth.session.afterCreate`, `auth.session.afterRevoke` | a session was created or revoked | success |
| `token.afterIssue`, `token.consumed`, `token.failed` | a token was issued, used, or refused | success, failure |
| `ratelimit.exceeded` | a request was stopped by a rate limit | denied |
| `migration.applied` | a migration was applied | success |
| `crypto.secret.rotated` | a secret rotation took effect | success |

Each event has:

| Field | Meaning |
| --- | --- |
| `ID` | assigned when the event is stored |
| `Type`, `Outcome` | see the table above |
| `ActorType`, `ActorID` | who did it: a `user` with its id, `anonymous` for a request without a signed-in user, or `system` for work outside a request |
| `SubjectType`, `SubjectID` | what it was done to: a table name such as `users` or `sessions`, and the row's id |
| `SessionID`, `RequestID` | the session and request involved, when there is one |
| `IPAddress`, `UserAgent` | of the request, when there is one |
| `Metadata` | details of the event type: the failure `code`, a token's `kind`, the `email` tried in a sign-in for an unknown address |
| `Timestamp` | when it was recorded |

Things worth knowing:

- **A failed sign-in names the account, not the person.** A wrong password for an existing user has that user as subject and an anonymous actor. Behemoth does not know who typed it.
- **Email addresses are kept** in audit metadata, where logs redact them. Passwords, tokens and other secrets are redacted in both.
- **IP address and user agent are always recorded**, also when `SessionConfig.CaptureIPAndAgent` is off. That setting covers session rows only.
- **Rate-limit rejections are recorded one by one.** A client that keeps sending requests past its limit adds one event per request.

### Reading events

```go
page, err := ac.Store.QueryAuditEvents(ctx, telemetry.AuditFilter{
	SubjectType: "users",
	SubjectID:   userID,
	From:        time.Now().Add(-30 * 24 * time.Hour),
	Limit:       50,
})
for _, e := range page.Events {
	fmt.Println(e.Timestamp, e.Type, e.Outcome, e.IPAddress)
}
```

Events come newest first. A filter field you leave empty matches everything; the ones you set must all match.

| Filter field | Selects |
| --- | --- |
| `Types` | events of any of these types |
| `Outcome` | `telemetry.OutcomeSuccess`, `OutcomeFailure` or `OutcomeDenied` |
| `ActorID` | events done by this user |
| `SubjectType`, `SubjectID` | events about this row |
| `SessionID`, `RequestID` | events of one session or one request |
| `From`, `To` | events recorded at or after `From` and before `To` |
| `Limit` | page size, 50 by default and at most 500 |
| `Cursor` | the next page |

To read on, pass the page's `NextCursor` back as `Cursor` and keep the other fields the same. An empty `NextCursor` means the page was the last. Events recorded while you page do not shift the pages.

```go
filter := telemetry.AuditFilter{Outcome: telemetry.OutcomeFailure}
for {
	page, err := ac.Store.QueryAuditEvents(ctx, filter)
	if err != nil {
		return err
	}
	handle(page.Events)
	if page.NextCursor == "" {
		break
	}
	filter.Cursor = page.NextCursor
}
```

Behemoth has no HTTP route for the audit log. Put `QueryAuditEvents` behind a route of your own, with your own access check.

### How reliable it is

- **User creation and updates** are written in the same database transaction as the user row. The event exists exactly when the change does. If the audit row cannot be written, the change fails too.
- **Everything else** is recorded after the action, best effort. If the write fails, the action has still happened, and Behemoth logs the failure at Error (`audit event could not be recorded`).

### The table

`audit_log` is one of Behemoth's own tables and is created by your migrations like `users` and `sessions`. Because user changes write to it in their transaction, it has to exist before your application serves requests. After upgrading from a version without it, run your migrations first.

Behemoth never deletes audit events. Remove old ones from a scheduled job of your own:

```go
err := ac.Store.PurgeAuditEvents(ctx, time.Now().AddDate(-1, 0, 0)) // keep one year
```

There is no way to change or delete a single event through Behemoth.

### Recording your own events

```go
ac.Telemetry.RecordAudit(ctx, telemetry.AuditEvent{
	Type:        "billing.plan.changed",
	ActorID:     adminID,
	SubjectType: "users",
	SubjectID:   userID,
	Metadata:    behemoth.M{"from": "free", "to": "pro"},
})
```

`RecordAudit` fills in the time, the request ID and the outcome (`success`) when you leave them out, and redacts the metadata. It is best effort and returns the error after logging it.

A plugin that declares its own hook points can have them audited without recording anything itself; see [Hooks](hooks.md#audit).

### Sending events somewhere else

The second argument of `telemetry.New` chooses the recorder.

| You want | Pass |
| --- | --- |
| the `audit_log` table | `nil` (the default) |
| the table and another destination | `telemetry.MultiRecorder(store.NewAuditRecorder(st), yours)` |
| only your own destination | your `telemetry.AuditRecorder` |
| no auditing | `telemetry.NoOpAuditRecorder{}` |

A recorder is one method:

```go
type AuditRecorder interface {
	Record(ctx context.Context, event AuditEvent) error
}
```

For the table and another destination, build the database recorder over a store on your database:

```go
st := store.New(db, store.WithSchema(app.Resolver))
tel := telemetry.New(logger, telemetry.MultiRecorder(store.NewAuditRecorder(st), siem), nil)
```

User creation and updates are still written to the table in their transaction. Your recorder is called for them once the transaction has committed, and never for a change that was rolled back.

`QueryAuditEvents` and `PurgeAuditEvents` always work on the `audit_log` table. With only your own recorder, or with auditing off, the table stays empty.

## Testing

`telemetry/telemetrytest` records what was emitted:

```go
tel, rec := telemetrytest.New()
// ... boot with tel, exercise the code ...

for _, line := range rec.Logger.At(slog.LevelError) {
	t.Errorf("unexpected error line: %s %v", line.Message, line.Fields)
}
events := rec.Audit.OfType("auth.signIn.failed")
```

Passing `tel` replaces the default recorder, so in such a test events go to `rec.Audit` and not to the `audit_log` table.

Recorded lines are redacted and correlated like those a real backend receives.
