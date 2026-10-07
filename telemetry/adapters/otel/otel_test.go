package behemothotel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	behemothotel "github.com/MastewalB/behemoth/telemetry/adapters/otel"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracer(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	tel := telemetry.New(nil, nil, nil, telemetry.WithTracer(behemothotel.NewTracer(provider)))

	// The application's own span is the parent, as with HTTP middleware.
	ctx, appSpan := provider.Tracer("app").Start(context.Background(), "GET /api/auth/sign-in/email")

	ctx, request := tel.StartSpan(ctx, telemetry.SpanRequest, behemoth.M{
		telemetry.AttrMethod: "POST", telemetry.AttrRoute: "/api/auth/sign-in/email",
	})
	_, lookup := tel.StartSpan(ctx, telemetry.SpanStorePrefix+"find_one", behemoth.M{telemetry.AttrEntity: "users"})
	telemetry.FinishSpan(lookup, behemotherr.NewNotFound("Store.FindUser", "user", nil))
	_, insert := tel.StartSpan(ctx, telemetry.SpanStorePrefix+"create", nil)
	telemetry.FinishSpan(insert, behemotherr.NewDatabaseError("Store.Create", errors.New("connection refused")))
	request.SetAttributes(behemoth.M{telemetry.AttrStatus: 500, "ok": false, "ratio": 0.5})
	request.End()
	appSpan.End()

	ended := recorder.Ended()
	if len(ended) != 4 {
		t.Fatalf("ended spans = %d, want 4", len(ended))
	}
	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range ended {
		byName[s.Name()] = s
	}
	req := byName[telemetry.SpanRequest]
	if req.Parent().SpanID() != appSpan.SpanContext().SpanID() {
		t.Error("behemoth's request span is not a child of the application's span")
	}
	if req.InstrumentationScope().Name != "github.com/MastewalB/behemoth" {
		t.Errorf("scope = %q", req.InstrumentationScope().Name)
	}
	attrs := attribute.NewSet(req.Attributes()...)
	for _, want := range []attribute.KeyValue{
		attribute.String(telemetry.AttrMethod, "POST"),
		attribute.Int(telemetry.AttrStatus, 500),
		attribute.Bool("ok", false),
		attribute.Float64("ratio", 0.5),
	} {
		if got, ok := attrs.Value(want.Key); !ok || got != want.Value {
			t.Errorf("attribute %s = %v, want %v", want.Key, got.Emit(), want.Value.Emit())
		}
	}

	// A lookup that found nothing is not an error status; a database
	// failure is.
	notFound := byName[telemetry.SpanStorePrefix+"find_one"]
	if notFound.Parent().SpanID() != req.SpanContext().SpanID() || notFound.Status().Code == codes.Error {
		t.Errorf("not-found span: parent ok = %v, status %v", notFound.Parent().SpanID() == req.SpanContext().SpanID(), notFound.Status())
	}
	failed := byName[telemetry.SpanStorePrefix+"create"]
	if failed.Status().Code != codes.Error || len(failed.Events()) != 1 {
		t.Errorf("failed span: status %v, events %d; want Error and the recorded error", failed.Status(), len(failed.Events()))
	}
}

func TestMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	tel := telemetry.New(nil, nil, behemothotel.NewMetrics(provider))
	ctx := context.Background()

	failure := behemoth.M{telemetry.AttrOutcome: "failure", telemetry.AttrReason: "invalidCredentials"}
	tel.Count(ctx, telemetry.MetricSignIn, failure)
	tel.Count(ctx, telemetry.MetricSignIn, failure)
	tel.Count(ctx, telemetry.MetricSignIn, behemoth.M{telemetry.AttrOutcome: "success"})
	tel.Metrics.Histogram(ctx, telemetry.MetricStoreDuration, 0.25, behemoth.M{telemetry.AttrOp: "find_one", telemetry.AttrEntity: "users"})

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &collected); err != nil {
		t.Fatal(err)
	}
	if len(collected.ScopeMetrics) != 1 || collected.ScopeMetrics[0].Scope.Name != "github.com/MastewalB/behemoth" {
		t.Fatalf("scopes = %+v", collected.ScopeMetrics)
	}
	found := map[string]metricdata.Metrics{}
	for _, m := range collected.ScopeMetrics[0].Metrics {
		found[m.Name] = m
	}

	sum, ok := found[telemetry.MetricSignIn].Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 2 {
		t.Fatalf("sign-in counter = %+v, want two series", found[telemetry.MetricSignIn])
	}
	for _, dp := range sum.DataPoints {
		outcome, _ := dp.Attributes.Value(telemetry.AttrOutcome)
		if want := map[string]int64{"failure": 2, "success": 1}[outcome.AsString()]; dp.Value != want {
			t.Errorf("sign-ins with outcome %q = %d, want %d", outcome.AsString(), dp.Value, want)
		}
	}

	duration := found[telemetry.MetricStoreDuration]
	hist, ok := duration.Data.(metricdata.Histogram[float64])
	if !ok || len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 || hist.DataPoints[0].Sum != 0.25 {
		t.Fatalf("store duration = %+v", duration)
	}
	if duration.Unit != "s" {
		t.Errorf("duration unit = %q, want s", duration.Unit)
	}
}

func TestWithTraceIDs(t *testing.T) {
	provider := sdktrace.NewTracerProvider()
	rec := &telemetrytest.Logger{}
	tel := telemetry.New(behemothotel.WithTraceIDs(rec), nil, nil, telemetry.WithTracer(behemothotel.NewTracer(provider)))

	tel.Logger.Info(context.Background(), "outside a span", nil)
	ctx, span := tel.StartSpan(context.Background(), telemetry.SpanRequest, nil)
	tel.Logger.Warn(ctx, "inside a span", behemoth.M{"rule": "signin", "password": "hunter2"})
	span.End()

	entries := rec.Entries()
	if _, set := entries[0].Fields[telemetry.FieldTraceID]; set {
		t.Errorf("a line outside a span has a trace id: %v", entries[0].Fields)
	}
	fields := entries[1].Fields
	traceID, _ := fields[telemetry.FieldTraceID].(string)
	spanID, _ := fields[telemetry.FieldSpanID].(string)
	if len(traceID) != 32 || len(spanID) != 16 {
		t.Errorf("trace_id %q, span_id %q; want 32 and 16 hex characters", traceID, spanID)
	}
	// The line's own fields are kept, and redaction still applies.
	if fields["rule"] != "signin" || fields["password"] != telemetry.Redacted {
		t.Errorf("fields = %v", fields)
	}

	if _, ok := behemothotel.WithTraceIDs(nil).(telemetry.NoOpLogger); !ok {
		t.Error("WithTraceIDs(nil) is not a no-op logger")
	}
}
