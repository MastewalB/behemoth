// Package telemetry defines behemoth's logging, audit and metrics
// interfaces, the names they share (field keys), and the helpers components
// use with them: named loggers, error fields, redaction and the request ID.
//
// It is a thin layer in the way the errors package is: behemoth owns the
// interfaces and the names, and a backend does the work. The slog-backed
// Logger in this package covers stdout; other backends live in their own
// modules. Every component receives a *Telemetry built by New.
//
// Tracing follows the same shape: Tracer and Span are defined here, and the
// OpenTelemetry adapter records the spans.
package telemetry

// Telemetry groups the sinks a component reports to. Build it with New, which
// fills every nil field with a no-op, so code holding a *Telemetry never
// checks its fields for nil.
//
// Components record audit events with RecordAudit, not with Audit.Record:
// it normalizes the event and logs a failed write.
type Telemetry struct {
	Logger  Logger
	Audit   AuditRecorder
	Metrics Metrics
	// Tracer is set with the WithTracer option. Components start spans with
	// StartSpan.
	Tracer Tracer
}

// Option changes how New builds a Telemetry.
type Option func(*options)

type options struct {
	allowEmails bool
	extraKeys   []string
	tracer      Tracer
}

// WithEmailsInLogs lets email addresses through to the log backend. Without
// it, the value of a field whose key is or ends with "email" is redacted.
// Audit events are not affected: they keep the email either way.
func WithEmailsInLogs() Option {
	return func(o *options) { o.allowEmails = true }
}

// WithRedactedKeys adds keys to the ones whose values are redacted in log
// fields. Like the built-in keys they match case-insensitively, as the whole
// key or as its suffix.
func WithRedactedKeys(keys ...string) Option {
	return func(o *options) { o.extraKeys = append(o.extraKeys, keys...) }
}

// New returns a Telemetry with a no-op in place of every nil argument.
//
// A nil audit recorder means "not chosen": Boot then records to the
// audit_log table. Pass NoOpAuditRecorder{} to turn auditing off.
//
// The logger is wrapped so that every line is redacted (see Redact) and
// carries the request ID found on its context, whichever backend is behind
// it. A logger New has already wrapped is used as it is, with the options it
// was wrapped with.
func New(logger Logger, audit AuditRecorder, metrics Metrics, opts ...Option) *Telemetry {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if audit == nil {
		audit = unsetAuditRecorder{}
	}
	if metrics == nil {
		metrics = NoOpMetrics{}
	}
	if o.tracer == nil {
		o.tracer = NoOpTracer{}
	}
	return &Telemetry{Logger: guard(logger, newRedactor(o)), Audit: audit, Metrics: metrics, Tracer: o.tracer}
}

// Named returns a copy of t whose Logger adds component to every line (see
// the Named function). The audit recorder and metrics sink are shared with
// t. A component's constructor calls it once and keeps the result.
func (t *Telemetry) Named(component string) *Telemetry {
	named := *t
	named.Logger = Named(t.Logger, component)
	return &named
}

// OrDefault returns a Telemetry that is safe to use whatever t is: no-ops
// for a nil t, and for a t built as a struct literal, its fields passed
// through New. Constructors that accept an optional *Telemetry call it.
func OrDefault(t *Telemetry) *Telemetry {
	if t == nil {
		return New(nil, nil, nil)
	}
	if t.Tracer == nil {
		return New(t.Logger, t.Audit, t.Metrics)
	}
	return New(t.Logger, t.Audit, t.Metrics, WithTracer(t.Tracer))
}
