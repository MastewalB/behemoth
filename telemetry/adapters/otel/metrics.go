package behemothotel

import (
	"context"
	"strings"
	"sync"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// NewMetrics returns a telemetry.Metrics that records behemoth's
// measurements with provider. A nil provider means the global one
// (otel.GetMeterProvider).
//
// A counter becomes an Int64Counter and a histogram a Float64Histogram, each
// created the first time its name is used. A histogram whose name ends in
// ".duration" gets the unit "s", which is what behemoth records durations
// in.
func NewMetrics(provider metric.MeterProvider) telemetry.Metrics {
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	return &metrics{meter: provider.Meter(scopeName)}
}

type metrics struct {
	meter metric.Meter

	mu         sync.RWMutex
	counters   map[string]metric.Int64Counter
	histograms map[string]metric.Float64Histogram
}

func (m *metrics) Counter(ctx context.Context, name string, delta int64, attrs behemoth.M) {
	if c := m.counter(name); c != nil {
		c.Add(ctx, delta, metric.WithAttributes(attributes(attrs)...))
	}
}

func (m *metrics) Histogram(ctx context.Context, name string, value float64, attrs behemoth.M) {
	if h := m.histogram(name); h != nil {
		h.Record(ctx, value, metric.WithAttributes(attributes(attrs)...))
	}
}

// counter returns the instrument for name, creating it on first use. An
// instrument that can't be created is reported to OpenTelemetry's error
// handler once and its measurements are dropped.
func (m *metrics) counter(name string) metric.Int64Counter {
	m.mu.RLock()
	c, ok := m.counters[name]
	m.mu.RUnlock()
	if ok {
		return c
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.counters[name]; ok {
		return c
	}
	c, err := m.meter.Int64Counter(name)
	if err != nil {
		otel.Handle(err)
		c = nil
	}
	if m.counters == nil {
		m.counters = map[string]metric.Int64Counter{}
	}
	m.counters[name] = c
	return c
}

func (m *metrics) histogram(name string) metric.Float64Histogram {
	m.mu.RLock()
	h, ok := m.histograms[name]
	m.mu.RUnlock()
	if ok {
		return h
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.histograms[name]; ok {
		return h
	}
	var opts []metric.Float64HistogramOption
	if strings.HasSuffix(name, ".duration") {
		opts = append(opts, metric.WithUnit("s"))
	}
	h, err := m.meter.Float64Histogram(name, opts...)
	if err != nil {
		otel.Handle(err)
		h = nil
	}
	if m.histograms == nil {
		m.histograms = map[string]metric.Float64Histogram{}
	}
	m.histograms[name] = h
	return h
}
