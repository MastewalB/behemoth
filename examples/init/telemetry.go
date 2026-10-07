package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/MastewalB/behemoth/telemetry"
	behemothotel "github.com/MastewalB/behemoth/telemetry/adapters/otel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// observability is what the application builds once and hands to behemoth:
// the Telemetry, plus the pieces it owns itself.
type observability struct {
	// tel goes to Boot (BootConfig.Telemetry), and its Logger to the
	// database adapter for statement logging.
	tel *telemetry.Telemetry

	// tracerProvider is nil when tracing is off. serve gives it to the gin
	// tracing middleware, which starts the span behemoth's spans nest under.
	tracerProvider oteltrace.TracerProvider

	// shutdown flushes what the exporters still hold. The application calls
	// it before it exits; behemoth never does, because it did not create
	// the exporters.
	shutdown func(context.Context) error
}

// newObservability wires behemoth's four signals for this application:
//
//   - Logs go to stdout as text. LOG_LEVEL=debug adds rejected requests and
//     SQL statements; the default is info.
//   - Audit events go to the audit_log table. That is behemoth's default,
//     chosen by passing a nil recorder.
//   - Traces are exported over OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT or
//     OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is set.
//   - Metrics are exported over OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT or
//     OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is set.
//
// With none of the OTEL variables set, the application logs and audits and
// has no OpenTelemetry provider at all.
//
// Jaeger takes traces and no metrics, so point only the traces variable at
// it. A collector takes both through the general one.
func newObservability(ctx context.Context) (*observability, error) {
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	// WithTraceIDs adds trace_id and span_id to lines written inside a span.
	// Without tracing it adds nothing.
	logger := behemothotel.WithTraceIDs(telemetry.NewTextLogger(os.Stdout, level))

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "behemoth-example"
	}
	res := resource.NewSchemaless(attribute.String("service.name", serviceName))

	obs := &observability{}
	var shutdowns []func(context.Context) error
	obs.shutdown = func(ctx context.Context) error {
		var errs []error
		for _, fn := range shutdowns {
			errs = append(errs, fn(ctx))
		}
		return errors.Join(errs...)
	}

	var opts []telemetry.Option
	if envSet("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
		exporter, err := otlptracehttp.New(ctx) // reads the endpoint from the environment
		if err != nil {
			return nil, err
		}
		provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
		shutdowns = append(shutdowns, provider.Shutdown)
		obs.tracerProvider = provider
		// The gin middleware reads the caller's trace from the traceparent
		// header with this propagator.
		otel.SetTextMapPropagator(propagation.TraceContext{})
		opts = append(opts, telemetry.WithTracer(behemothotel.NewTracer(provider)))
	}

	var metrics telemetry.Metrics // nil: nothing is measured
	if envSet("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") {
		exporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			obs.shutdown(ctx)
			return nil, err
		}
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)), sdkmetric.WithResource(res))
		shutdowns = append(shutdowns, provider.Shutdown)
		metrics = behemothotel.NewMetrics(provider)
	}

	obs.tel = telemetry.New(logger, nil, metrics, opts...)
	return obs, nil
}

func envSet(names ...string) bool {
	for _, name := range names {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}
