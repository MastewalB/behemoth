// Package telemetrytest provides in-memory telemetry sinks for tests. They
// keep what was logged, audited and measured so a test can assert on it.
// behemoth's own tests use them, and an application's tests can too.
package telemetrytest

import (
	"context"
	"log/slog"
	"sync"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/telemetry"
)

// Recorder holds the sinks behind a Telemetry built by New.
type Recorder struct {
	Logger  *Logger
	Audit   *AuditRecorder
	Metrics *Metrics
}

// New returns a Telemetry that records into the returned Recorder. The
// logger goes through telemetry.New like an application's does, so recorded
// lines are redacted and carry the request ID.
func New(opts ...telemetry.Option) (*telemetry.Telemetry, *Recorder) {
	rec := &Recorder{Logger: &Logger{}, Audit: &AuditRecorder{}, Metrics: &Metrics{}}
	return telemetry.New(rec.Logger, rec.Audit, rec.Metrics, opts...), rec
}

// LogEntry is one recorded log line.
type LogEntry struct {
	Level   slog.Level
	Message string
	Fields  behemoth.M
}

// Logger is a telemetry.Logger that keeps every line.
type Logger struct {
	mu      sync.Mutex
	entries []LogEntry
}

var _ telemetry.Logger = (*Logger)(nil)

func (l *Logger) add(level slog.Level, msg string, fields behemoth.M) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, LogEntry{Level: level, Message: msg, Fields: fields})
}

func (l *Logger) Debug(_ context.Context, msg string, fields behemoth.M) {
	l.add(slog.LevelDebug, msg, fields)
}
func (l *Logger) Info(_ context.Context, msg string, fields behemoth.M) {
	l.add(slog.LevelInfo, msg, fields)
}
func (l *Logger) Warn(_ context.Context, msg string, fields behemoth.M) {
	l.add(slog.LevelWarn, msg, fields)
}
func (l *Logger) Error(_ context.Context, msg string, fields behemoth.M) {
	l.add(slog.LevelError, msg, fields)
}

// Entries returns a copy of the recorded lines, oldest first.
func (l *Logger) Entries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LogEntry(nil), l.entries...)
}

// At returns the recorded lines of one level, oldest first.
func (l *Logger) At(level slog.Level) []LogEntry {
	var out []LogEntry
	for _, e := range l.Entries() {
		if e.Level == level {
			out = append(out, e)
		}
	}
	return out
}

// Reset forgets every recorded line.
func (l *Logger) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = nil
}

// AuditRecorder is a telemetry.AuditRecorder that keeps every event. Err,
// when set, is returned by Record instead of recording, to test how a caller
// handles a failed audit write.
type AuditRecorder struct {
	Err error

	mu     sync.Mutex
	events []telemetry.AuditEvent
}

var _ telemetry.AuditRecorder = (*AuditRecorder)(nil)

func (a *AuditRecorder) Record(_ context.Context, event telemetry.AuditEvent) error {
	if a.Err != nil {
		return a.Err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

// OfType returns the recorded events of one type, oldest first.
func (a *AuditRecorder) OfType(eventType string) []telemetry.AuditEvent {
	var out []telemetry.AuditEvent
	for _, e := range a.Events() {
		if e.Type == eventType {
			out = append(out, e)
		}
	}
	return out
}

// Events returns a copy of the recorded events, oldest first.
func (a *AuditRecorder) Events() []telemetry.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]telemetry.AuditEvent(nil), a.events...)
}

// Sample is one recorded measurement. Value is 1 for a counter.
type Sample struct {
	Name  string
	Value float64
	Tags  behemoth.M
}

// Metrics is a telemetry.Metrics that keeps every measurement.
type Metrics struct {
	mu       sync.Mutex
	counters []Sample
	gauges   []Sample
}

var _ telemetry.Metrics = (*Metrics)(nil)

func (m *Metrics) Counter(name string, tags behemoth.M) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters = append(m.counters, Sample{Name: name, Value: 1, Tags: tags})
}

func (m *Metrics) Gauge(name string, value float64, tags behemoth.M) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges = append(m.gauges, Sample{Name: name, Value: value, Tags: tags})
}

// Counters returns a copy of the recorded counter increments, oldest first.
func (m *Metrics) Counters() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sample(nil), m.counters...)
}

// Gauges returns a copy of the recorded gauge values, oldest first.
func (m *Metrics) Gauges() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sample(nil), m.gauges...)
}
