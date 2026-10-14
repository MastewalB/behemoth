package behemothotel

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// WithTraceIDs returns a Logger that adds telemetry.FieldTraceID and
// telemetry.FieldSpanID to every line written while a span is active, and
// passes the line on to logger. A log line can then be found from its
// trace, and the trace from the line.
//
// It decorates any Logger: the slog-backed one for stdout, or one over an
// OpenTelemetry logs bridge when logs are exported too. Pass the result to
// telemetry.New, which adds redaction and the request ID around it.
func WithTraceIDs(logger telemetry.Logger) telemetry.Logger {
	switch logger.(type) {
	case nil, telemetry.NoOpLogger:
		return telemetry.NoOpLogger{}
	}
	return &traceLogger{inner: logger}
}

type traceLogger struct {
	inner telemetry.Logger
}

// with returns fields plus the IDs of the span on ctx, in a new map. A line
// that sets either key itself keeps its own value.
func (l *traceLogger) with(ctx context.Context, fields behemoth.M) behemoth.M {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return fields
	}
	out := make(behemoth.M, len(fields)+2)
	out[telemetry.FieldTraceID] = sc.TraceID().String()
	out[telemetry.FieldSpanID] = sc.SpanID().String()
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func (l *traceLogger) Debug(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Debug(ctx, msg, l.with(ctx, fields))
}
func (l *traceLogger) Info(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Info(ctx, msg, l.with(ctx, fields))
}
func (l *traceLogger) Warn(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Warn(ctx, msg, l.with(ctx, fields))
}
func (l *traceLogger) Error(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Error(ctx, msg, l.with(ctx, fields))
}
