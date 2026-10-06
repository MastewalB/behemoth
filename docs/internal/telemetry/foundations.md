# Telemetry Foundations

This document describes the `telemetry` package as built: what it defines, how a log line travels from a call site to a backend, and how a request gets its ID. It is phase 1 of `plan.md`. Audit storage, the metric catalog and tracing are later phases and are described there.

The code lives in:

- `telemetry/telemetry.go`: `Telemetry`, `New`, `OrDefault`, the options
- `telemetry/logger.go`: `Logger`, `NoOpLogger`, `Named`, the wrapper `New` applies
- `telemetry/fields.go`: the field keys, `ErrorFields`
- `telemetry/redact.go`: redaction
- `telemetry/requestid.go`: the request ID on a `context.Context`
- `telemetry/slog.go`: the `log/slog` backend
- `telemetry/audit.go`: the audit event and recorder interfaces, described in `audit.md`
- `telemetry/metrics.go`: the metrics interface, unchanged from before the move
- `telemetry/telemetrytest/`: in-memory sinks for tests
- `types/router.go`: `withRequestScope`, which assigns the request ID

## Place among other packages

`telemetry` imports the root package (for `behemoth.M` and `behemoth.Model`) and `errors` (for `DomainError`). It imports nothing else from behemoth, so every other package can import it: `types`, `store`, `crypto`, `transport`, `migration/core`, and the adapter modules.

It relates to the error taxonomy in two ways. It follows the same split: behemoth owns interfaces and names, something external does the work. And `ErrorFields` is the bridge between them, turning a `DomainError` into log fields.

`types.AuditSpec` stayed in `types`, next to `HookPointDef`, because it is part of a hook point's declaration and not of a sink.

## `Telemetry`, `New` and `OrDefault`

```go
type Telemetry struct {
	Logger  Logger
	Audit   AuditRecorder
	Metrics Metrics
}

func New(logger Logger, audit AuditRecorder, metrics Metrics, opts ...Option) *Telemetry
func OrDefault(t *Telemetry) *Telemetry
```

`New` replaces each nil argument with a no-op (`NoOpLogger`, `NoOpMetrics`, and for audit a placeholder that tells `Boot` no recorder was chosen; see `audit.md`) and wraps the logger (next section). Components hold a `*Telemetry` and call its fields without nil checks.

`Telemetry.Named(component)` returns a copy whose logger is named and whose other sinks are shared. Components call it once at construction.

`OrDefault` exists for constructors whose `*Telemetry` parameter is optional. `Boot` and `crypto.New` call it.

| Input | Result |
| --- | --- |
| `nil` | `New(nil, nil, nil)` |
| built by `New` | the same sinks; the logger is not wrapped a second time and keeps its options |
| a struct literal such as `&telemetry.Telemetry{Logger: l}` | nil fields become no-ops, and `l` is wrapped with the default options |

The third row is why `Boot` calls `OrDefault` and does not only check for nil: an application that skips `New` still gets redaction.

`AuthContext.Telemetry` is a `*telemetry.Telemetry`, the same pointer every component received.

## How a log line travels

```
call site
  │  log.Warn(ctx, "session cache write failed", fields)
  ▼
namedLogger            adds component, unless the line set it      (telemetry.Named, optional)
  ▼
guardedLogger          copies and redacts the fields,              (telemetry.New, always)
  │                    adds request_id from ctx unless the line set it
  ▼
backend                slogLogger, an OpenTelemetry adapter, the application's own Logger
```

- **`guardedLogger`** is unexported and is applied by `New` only. It is the one place redaction and request correlation happen, so a backend cannot receive an unredacted field and no call site adds the request ID by hand.
- **`namedLogger`** sits outside the guard, so its `component` field passes through redaction like any other field.
- **Copies.** Both wrappers build a new map. A caller's `behemoth.M` is never modified, so a call site can reuse the map after logging.
- **No-op short circuit.** `guard` and `Named` return `NoOpLogger{}` for a nil or no-op logger, so a deployment without a logger pays for one interface call per line and no map copy.

### Redaction

`redactor.redact` replaces a field's value with `"[REDACTED]"` when its key, lowercased, equals or ends with one of:

`password`, `token`, `secret`, `hash`, `cookie`, `authorization`, and `email` unless `WithEmailsInLogs` is set.

| Key | Redacted | Why |
| --- | --- | --- |
| `password`, `newPassword` | yes | equals, suffix |
| `refresh_token` | yes | suffix |
| `passwordHash` | yes | suffix `hash` |
| `tokenID`, `token_kind` | no | an identifier or a label; the key does not end with `token` |
| `user_email` | yes, by default | suffix `email` |

Values that are a `behemoth.M` or a `map[string]any` are redacted recursively. Slices and structs are passed through as they are.

`WithRedactedKeys` adds keys with the same matching. `telemetry.Redact(fields, opts...)` applies the rules outside a logger.

Limits: matching is by key. A secret inside a message string, or under a key that does not match, is not detected. Call sites still have to avoid logging secrets; redaction is the second line of defense.

### Design decision

### Suffix matching for redacted keys
**Context:** Field keys are free-form, and the same secret appears under different names (`password`, `newPassword`, `passwordHash`).
**Options considered:**
- *Exact match.* Predictable. Misses every variant, so each new field name needs a new entry.
- *Substring match.* Catches the most. Also redacts `tokenID` and `token_kind`, which are the fields that make a token-related log line useful.
- *Suffix match.* Catches the variants where the secret word is the noun (`refresh_token`, `newPassword`) and leaves keys where it qualifies something else (`tokenID`).
**Decision:** Suffix match, case-insensitive.
**Revisit if:** a field that holds a secret is found with the secret word at the start of its key.

## Field keys and `ErrorFields`

`telemetry/fields.go` holds the keys as constants: `FieldComponent`, `FieldOp`, `FieldRequestID`, `FieldTraceID`, `FieldSpanID`, `FieldUserID`, `FieldSessionID`, `FieldPlugin`, `FieldPoint`, `FieldError`, `FieldErrorCode`, `FieldErrorCategory`.

`ErrorFields(err)` returns a new map:

| `err` | `error` | `error_code` | `error_category` | `op` |
| --- | --- | --- | --- | --- |
| `nil` | | | | |
| a plain error | `err.Error()` | `unknown_error` | | |
| a `*DomainError`, possibly wrapped | `err.Error()` | its `Code` | its `Category` | its `Op`, if set |

`err.Error()` on a `DomainError` is its internal message, which is the right text for a log and the wrong one for a response. The error mapper uses `PublicMessage` for the response.

`ErrorFields(err, extra...)` also copies the fields of `extra` into the result, for a line that says more than the error does. A key the error sets wins over the same key in `extra`.

Further keys were added with the logging phase: `FieldMethod`, `FieldRoute`, `FieldStatus` and `FieldStatement`. How components use the keys and `Named` is described in `logging.md`.

## Request ID

`Router.withRequestScope`, the outermost wrapper of every behemoth route, assigns the ID. `Router.requestID` picks it in this order:

1. The ID already on the context. An application whose own middleware assigns request IDs calls `telemetry.ContextWithRequestID` and behemoth keeps that value.
2. The value of the request header `RouterConfig.RequestIDHeader` (default `X-Request-ID`), when `telemetry.ValidRequestID` accepts it.
3. `telemetry.NewRequestID()`: 16 random bytes, hex encoded.

The wrapper then stores the ID on `rctx.Ctx` and sets it on the response header. Because this happens outside error mapping, an error response carries the header too.

`ValidRequestID` accepts 1 to 128 visible ASCII characters. The header comes from the client and its value is written to logs, so a value with spaces, control characters or line breaks is replaced by a generated ID instead of being passed on. Behemoth treats the ID as a label for correlation and makes no decision based on it.

Code reads the ID with `telemetry.RequestIDFrom(ctx)`. It returns `""` for a call made outside a request (a CLI command, a background job, a test), and the guarded logger then adds no `request_id` field.

Audit events carry the ID too: `telemetry.NormalizeAuditEvent` fills `AuditEvent.RequestID` from the context. See `audit.md`.

## The slog backend

`NewSlogLogger(l *slog.Logger)` adapts any slog logger; `NewTextLogger` and `NewJSONLogger` build one over an `io.Writer` at a minimum level.

- Fields become attributes in key order, so output is stable between runs.
- The level check runs before the attributes are built.
- The source location slog records is the adapter's own frame. Recovering the call site would need a frame count that changes with each wrapper, so handlers are best built without `AddSource`.

## Test helpers

`telemetrytest.New(opts...)` returns a `*telemetry.Telemetry` and a `Recorder` holding its three sinks.

| Sink | Reads |
| --- | --- |
| `Logger` | `Entries()`, `At(level)`, `Reset()` |
| `AuditRecorder` | `Events()`, `OfType(type)`; set `Err` to make `Record` fail |
| `Metrics` | `Counters()`, `Gauges()` |

The telemetry goes through `telemetry.New`, so recorded log lines are what a real backend would receive: redacted, with the request ID. All sinks are safe for concurrent use.
