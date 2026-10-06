package telemetry

import "github.com/MastewalB/behemoth"

// Metrics is the sink for counters and gauges.
//
// Deferred: no component reports a metric yet. The interface changes in the
// metrics phase of docs/internal/telemetry/plan.md (a context, histograms).
type Metrics interface {
	Counter(name string, tags behemoth.M)
	Gauge(name string, value float64, tags behemoth.M)
}

// NoOpMetrics drops every measurement. New uses it when no sink is given.
type NoOpMetrics struct{}

func (NoOpMetrics) Counter(string, behemoth.M)        {}
func (NoOpMetrics) Gauge(string, float64, behemoth.M) {}
