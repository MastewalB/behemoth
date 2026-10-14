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
	Tracer  *Tracer
}

// New returns a Telemetry that records into the returned Recorder. The
// logger goes through telemetry.New like an application's does, so recorded
// lines are redacted and carry the request ID.
func New(opts ...telemetry.Option) (*telemetry.Telemetry, *Recorder) {
	rec := &Recorder{Logger: &Logger{}, Audit: &AuditRecorder{}, Metrics: &Metrics{}, Tracer: &Tracer{}}
	opts = append([]telemetry.Option{telemetry.WithTracer(rec.Tracer)}, opts...)
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

// Sample is one recorded measurement: a counter's delta or a histogram's
// observation.
type Sample struct {
	Name  string
	Value float64
	Attrs behemoth.M
}

// Metrics is a telemetry.Metrics that keeps every measurement.
type Metrics struct {
	mu         sync.Mutex
	counters   []Sample
	histograms []Sample
}

var _ telemetry.Metrics = (*Metrics)(nil)

func (m *Metrics) Counter(_ context.Context, name string, delta int64, attrs behemoth.M) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters = append(m.counters, Sample{Name: name, Value: float64(delta), Attrs: attrs})
}

func (m *Metrics) Histogram(_ context.Context, name string, value float64, attrs behemoth.M) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.histograms = append(m.histograms, Sample{Name: name, Value: value, Attrs: attrs})
}

// Counters returns a copy of the recorded counter increments, oldest first.
func (m *Metrics) Counters() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sample(nil), m.counters...)
}

// Histograms returns a copy of the recorded observations, oldest first.
func (m *Metrics) Histograms() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sample(nil), m.histograms...)
}

// Count returns the total of the counter name over the increments whose
// attributes include every pair in attrs. A nil attrs totals all of them.
func (m *Metrics) Count(name string, attrs behemoth.M) int64 {
	var total int64
	for _, s := range m.Counters() {
		if s.Name == name && includes(s.Attrs, attrs) {
			total += int64(s.Value)
		}
	}
	return total
}

// Observations returns the observations of the histogram name whose
// attributes include every pair in attrs, oldest first.
func (m *Metrics) Observations(name string, attrs behemoth.M) []Sample {
	var out []Sample
	for _, s := range m.Histograms() {
		if s.Name == name && includes(s.Attrs, attrs) {
			out = append(out, s)
		}
	}
	return out
}

func includes(have, want behemoth.M) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// Span is one recorded span. Its fields are read through the methods below
// once the code under test has finished.
type Span struct {
	Name   string
	Parent *Span // the span on the context this one was started from; nil for a root

	mu    sync.Mutex
	attrs behemoth.M
	err   error
	ended int
}

var _ telemetry.Span = (*Span)(nil)

func (s *Span) SetAttributes(attrs behemoth.M) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range attrs {
		s.attrs[k] = v
	}
}

func (s *Span) RecordError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *Span) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended++
}

// Attrs returns a copy of the span's attributes.
func (s *Span) Attrs() behemoth.M {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(behemoth.M, len(s.attrs))
	for k, v := range s.attrs {
		out[k] = v
	}
	return out
}

// Err returns the error the span was marked as failed with, or nil.
func (s *Span) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Ended reports how many times End was called. Anything but 1 is a bug in
// the code that started the span.
func (s *Span) Ended() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

// Tracer is a telemetry.Tracer that keeps every span, with its parent.
type Tracer struct {
	mu    sync.Mutex
	spans []*Span
}

var _ telemetry.Tracer = (*Tracer)(nil)

type parentKey struct{}

func (t *Tracer) Start(ctx context.Context, name string, attrs behemoth.M) (context.Context, telemetry.Span) {
	span := &Span{Name: name, attrs: behemoth.M{}}
	span.Parent, _ = ctx.Value(parentKey{}).(*Span)
	span.SetAttributes(attrs)
	t.mu.Lock()
	t.spans = append(t.spans, span)
	t.mu.Unlock()
	return context.WithValue(ctx, parentKey{}, span), span
}

// Spans returns the recorded spans in the order they were started.
func (t *Tracer) Spans() []*Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*Span(nil), t.spans...)
}

// Named returns the recorded spans with the given name, in start order.
func (t *Tracer) Named(name string) []*Span {
	var out []*Span
	for _, s := range t.Spans() {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}
