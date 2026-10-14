# Tracing

This document describes tracing as built: the `Tracer` interface, where spans start and end, how a span is marked as failed, and the OpenTelemetry adapter module. It is phase 5 of `plan.md`.

A metric says that sign-in is slow. A trace says where one slow sign-in spent its time: the password hash, a store operation, a hook handler.

The code lives in:

- `telemetry/tracer.go`: `Tracer`, `Span`, `NoOpTracer`, `WithTracer`, the span names, `Telemetry.StartSpan`, `SpanFrom`, `FinishSpan`, `IsSystemFailure`
- `types/router.go`: `Router.withTracing`
- `store/instrument.go`: `WithTelemetry`, `instrumentedDB`
- `types/init/init.go`: `DefaultDispatcher.chainSpan`, `handlerSpan`, the span in `DefaultRateLimiter.evaluate`
- `transport/session.go`, `transport/token.go`: the span wrappers around `Create`, `Get`, `Revoke`, `Issue`, `Consume`
- `plugins/emailpassword`: `hashPassword`, the verify span in `signInBody`
- `migration/core/runner.go`: `applyTraced`
- `telemetry/adapters/otel/`: the OpenTelemetry backend, in its own module
- `telemetry/telemetrytest`: the recording tracer

## The interface

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

`Start` returns a context carrying the new span. Work done with that context nests under it. That is the only way spans relate to each other: behemoth passes the context on and never names a parent.

The tracer is the one sink set by an option, `telemetry.WithTracer(t)`, and not by a positional argument of `New`. `New(logger, audit, metrics)` has many callers, and tracing was added after them. `OrDefault` and `Telemetry.Named` keep the tracer.

### Helpers

| Helper | Use |
| --- | --- |
| `Telemetry.StartSpan(ctx, name, attrs)` | starts a span. Safe on a nil `Telemetry`, where it starts nothing. Also keeps the span on the context for `SpanFrom`. |
| `Telemetry.TracingEnabled()` | false for `NoOpTracer`. Checked before building attributes on a hot path. |
| `telemetry.SpanFrom(ctx)` | the innermost span `StartSpan` put on the context, or one that records nothing |
| `telemetry.FinishSpan(span, err)` | describes `err` on the span and ends it |

`SpanFrom` exists for one case: the router's span is started in `withTracing`, and the error that should fail it is only known further in, in `wrapWithErrorMapping`, which has the context and not the span.

### When a span is marked as failed

`FinishSpan` splits errors the way the router splits its log level:

| Error | On the span |
| --- | --- |
| a failure of the system (`IsSystemFailure`) | `error_code`, `error_category`, and `RecordError` |
| a rejection: not found, expired session, a hook's veto, a rate limit | `error_code` and `error_category` only |

`IsSystemFailure` is true for an error outside the taxonomy and for the categories `database`, `transaction`, `undefined_table`, `internal`, `configuration`, `security`, `not_implemented` and `migration`.

A sign-up looks the email address up and expects to find nothing. If that lookup failed its span, every sign-up trace would show an error. A trace view that highlights failed spans should light up for an outage and stay quiet for a wrong password.

## Span sites

| Span | Attributes | Started in |
| --- | --- | --- |
| `behemoth.request` | `method`, `route`, `request_id`, `status` | `Router.withTracing` |
| `behemoth.hook.chain` | `point`, `phase` | `DefaultDispatcher.chainSpan` |
| `behemoth.hook.handler` | `point`, `plugin` | `DefaultDispatcher.handlerSpan` |
| `behemoth.store.<op>` | `entity` | `instrumentedDB.run` |
| `behemoth.session.create`, `.validate`, `.revoke` | | the session manager |
| `behemoth.token.issue`, `.consume` | `kind` | the token manager |
| `behemoth.password.hash`, `.verify` | | the email/password plugin |
| `behemoth.ratelimit.check` | `rule`, `result` | `DefaultRateLimiter.evaluate` |
| `behemoth.migration.apply` | `id`, `baseline` | `DefaultMigrationRunner.applyTraced` |

Names are constants in `telemetry/tracer.go`. Attribute keys are the `Attr` constants of the metrics, plus `AttrRequestID` and `AttrErrorCode`. The same bounded-value rule applies, with one exception: `request_id` is unique per request, which is fine on a span and would not be on a metric.

The trace of a sign-up through the example application, as Jaeger received it, is shown in [`telemetry.md`](telemetry.md#seen-working).

### The request

`Router.Build` wraps each route as `withRequestScope(withTracing(withMetrics(wrapWithErrorMapping(...))))`.

- `withTracing` starts the span from `rctx.Ctx` and stores the returned context back in `rctx.Ctx`. Everything inside uses that context: middleware, the handler, and through `HookContext.Ctx` and the store, everything they call.
- It runs inside `withRequestScope`, so the request ID is known and becomes an attribute. A trace can be found from the ID a client quotes.
- Behemoth reads no trace headers. The application's framework middleware (`otelgin`, `otelhttp`, ...) extracts the incoming trace and starts the server span. `behemoth.request` is its child because `rctx.Ctx` comes from the request's context.
- `status` is set after the chain returns. `wrapWithErrorMapping` fails the span for a 5xx through `SpanFrom`.
- Without a tracer `withTracing` returns the handler itself.

### Hook chains and handlers

All four dispatcher methods start with `forPoint`, which gives the dispatch its own copy of the hook context. `chainSpan` starts a span and sets it as that copy's `Ctx`, so the handlers, the rate-limit check of `RunBefore` and the audit record all nest under it.

`[Convention]` A point without handlers gets no chain span. Most dispatches have none, and an empty span per point would bury a trace in noise. The audit record of such a point is then a child of whatever span surrounds the dispatch.

`handlerSpan` starts one span per handler call and gives the handler another copy of the hook context carrying it. A handler that passes `hctx.Ctx` on, to the store or to an HTTP client with its own instrumentation, gets its work traced under its own span with no code of its own. The copy shares `Values`, so the operation's scratch space is unaffected.

`observeHandler` ends the handler span with `FinishSpan`. A before handler's veto is a rejection and does not fail the span.

### Store operations

`store.WithTelemetry(tel)` replaces the `WithMetrics` option of phase 4. `store.New` wraps the adapter in an `instrumentedDB` when `tel` has a metrics sink or a tracer.

`instrumentedDB.run` is the one place a database operation is reported:

1. Start a span named `behemoth.store.<op>` with the table as `entity`. A transaction has no table and no `entity` attribute.
2. Call the adapter with the span's context.
3. `FinishSpan` with the error.
4. Record the duration and, on error, the error count.

Because the adapter is called with the span's context, a driver's own instrumentation (`otelsql`, for example) nests its statement spans under the operation. Behemoth's span says what was asked (`find_one` on `users`); the driver's says which SQL ran.

`Transaction` runs the whole callback inside the `transaction` span and hands it a wrapped adapter, so operations inside are children of the transaction span.

`[Limit]` The adapter derives the callback's context from the one it is given. That holds for every adapter in the repository. An adapter that built a fresh context for the callback would cut the operations inside off from the transaction span.

### Managers

`Create`, `Get` and `Revoke` of the session manager, and `Issue` and `Consume` of the token manager, are each a thin method that starts a span, calls the unexported method holding the body (`create`, `get`, ...), and finishes the span with its error. The body is unchanged, and none of its many return paths has to remember the span.

`Validate` goes through `Get`, so `behemoth.session.validate` covers both. The token manager reads the `Telemetry` from its `AuthContext` on use, as it does for its logger.

### Passwords

`cryptotypes.PasswordHasher.Hash` and `Verify` take no context, so the hasher cannot start a span that has a parent. The email/password plugin starts the spans around its calls: `hashPassword` for the four `Hash` calls, and inline for `Verify`. The plan placed these spans in `crypto`.

`[Limit]` Another plugin that hashes a password is not traced unless it does the same. See "PasswordHasher takes no context" in `docs/ongoing.md`.

## The OpenTelemetry adapter

`telemetry/adapters/otel` is its own module (`github.com/MastewalB/behemoth/telemetry/adapters/otel`, package `behemothotel`), like the storage adapters. The root module has no OpenTelemetry dependency.

| Constructor | Returns | Maps to |
| --- | --- | --- |
| `NewTracer(trace.TracerProvider)` | `telemetry.Tracer` | one `trace.Span` per span |
| `NewMetrics(metric.MeterProvider)` | `telemetry.Metrics` | an `Int64Counter` or `Float64Histogram` per name |
| `WithTraceIDs(telemetry.Logger)` | `telemetry.Logger` | adds `trace_id` and `span_id` to lines |

A nil provider means the global one. The instrumentation scope of every span and instrument is `github.com/MastewalB/behemoth`.

- **It depends on the OpenTelemetry API.** The SDK appears in `go.mod` for the tests only. The application builds the SDK, its providers and exporters, and shuts them down.
- **Attributes keep their type.** `attributes` converts strings, booleans, integers and floats to typed key-values, in key order, and formats anything else.
- **`RecordError`** adds the error as a span event and sets the status to `Error`. Since `FinishSpan` only calls it for system failures, a rejected request keeps the status `Unset`.
- **Instruments are created on first use** and cached by name behind a read-write lock. A histogram whose name ends in `.duration` gets the unit `s`. An instrument that cannot be created is reported to OpenTelemetry's error handler and its measurements are dropped.
- **`WithTraceIDs` decorates a logger** and does not export logs. It reads the span context from the line's context and adds the two IDs. It goes inside `telemetry.New`, which adds redaction and the request ID around it.

### No log exporter in the adapter
**Context:** The plan listed an OpenTelemetry logger next to the tracer and the metrics.
**Options considered:**
- *Implement `telemetry.Logger` on the OpenTelemetry Logs API.* Logs would reach the collector with no further setup. The Logs API for Go is younger than the trace and metric APIs, and the adapter would duplicate what `otelslog` already does for any slog logger.
- *Decorate an existing logger with the trace and span IDs.* Works with stdout today. An application that wants logs in its collector builds a slog logger over `otelslog` and passes it to `telemetry.NewSlogLogger`, and the decorator still adds the IDs.
**Decision:** The decorator. Correlating a line with its trace is the part only behemoth's adapter can do; transporting log records is not.
**Revisit if:** applications keep writing the same `otelslog` wiring, at which point a constructor for it belongs here.

### No Jaeger adapter
**Context:** Jaeger was named as a backend alongside OpenTelemetry and stdout.
**Options considered:**
- *A Jaeger adapter on the Jaeger client library.* The library is deprecated in favor of OpenTelemetry.
- *Reach Jaeger through OpenTelemetry.* Jaeger ingests OTLP. The application points an OTLP exporter at it.
**Decision:** No Jaeger code. The choice of destination is the exporter's, and the exporter is the application's.

## Testing

`telemetrytest.New` returns a `Telemetry` with a recording `Tracer`.

| Method | Returns |
| --- | --- |
| `Tracer.Spans()`, `Tracer.Named(name)` | recorded spans, in start order |
| `Span.Parent` | the span on the context this one was started from |
| `Span.Attrs()`, `Span.Err()` | what was set on it |
| `Span.Ended()` | how many times `End` was called; anything but 1 is a bug |

`tests/plugins` checks the tree of a sign-up against a database: inserts under their transaction, the handler under its chain, the handler's own read under the handler, and every span ended once. The adapter module's tests run against the OpenTelemetry SDK's in-memory span recorder and manual metric reader.
