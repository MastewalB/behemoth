// Package behemothotel records behemoth's spans and metrics with
// OpenTelemetry, and ties its log lines to traces.
//
// It is the backend behind the interfaces of the telemetry package, in the
// way a storage adapter is the backend behind behemoth.Database. It depends
// on the OpenTelemetry API only. The application builds the SDK, its
// providers and exporters, passes the providers in, and flushes and shuts
// them down:
//
//	tel := telemetry.New(
//		behemothotel.WithTraceIDs(telemetry.NewJSONLogger(os.Stdout, slog.LevelInfo)),
//		nil, // audit: the audit_log table
//		behemothotel.NewMetrics(meterProvider),
//		telemetry.WithTracer(behemothotel.NewTracer(tracerProvider)),
//	)
//
// Any OTLP destination works, a collector or Jaeger directly: that is the
// exporter's concern, not this package's. There is no Jaeger-specific code
// because Jaeger ingests OTLP.
//
// The package lives in its own module so that the root module does not
// depend on OpenTelemetry.
package behemothotel

// scopeName is the instrumentation scope of every span and instrument.
const scopeName = "github.com/MastewalB/behemoth"
