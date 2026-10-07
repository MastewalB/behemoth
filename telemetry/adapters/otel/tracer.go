package behemothotel

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// NewTracer returns a telemetry.Tracer that records behemoth's spans with
// provider. A nil provider means the global one (otel.GetTracerProvider).
//
// Spans are started from the context behemoth is given, so they are
// children of whatever span the application's HTTP middleware put there.
func NewTracer(provider trace.TracerProvider) telemetry.Tracer {
	if provider == nil {
		provider = otel.GetTracerProvider()
	}
	return &tracer{tracer: provider.Tracer(scopeName)}
}

type tracer struct {
	tracer trace.Tracer
}

func (t *tracer) Start(ctx context.Context, name string, attrs behemoth.M) (context.Context, telemetry.Span) {
	ctx, s := t.tracer.Start(ctx, name, trace.WithAttributes(attributes(attrs)...))
	return ctx, span{span: s}
}

type span struct {
	span trace.Span
}

func (s span) SetAttributes(attrs behemoth.M) {
	s.span.SetAttributes(attributes(attrs)...)
}

// RecordError adds err as a span event and sets the span's status to Error.
// behemoth calls it for failures of the system only (telemetry.FinishSpan),
// so a refused request does not show as a failed span.
func (s span) RecordError(err error) {
	if err == nil {
		return
	}
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
}

func (s span) End() { s.span.End() }
