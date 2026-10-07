package telemetry

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
)

// Metrics is the sink for measurements. It has the two instruments behemoth
// needs: a counter for things that happen and a histogram for how long they
// take. A backend (the OpenTelemetry adapter, or the application's own)
// maps them onto its instruments.
//
// attrs may be nil. Their values are bounded: a route is its pattern, an
// error is its category, and no attribute holds a user id, a session id, an
// IP address or an email. A backend can therefore use every attribute as a
// label without its series growing with traffic.
//
// ctx is the context of the work being measured, so a backend can link a
// measurement to the trace it belongs to.
type Metrics interface {
	// Counter adds delta to the counter name.
	Counter(ctx context.Context, name string, delta int64, attrs behemoth.M)
	// Histogram records one observation of name. Durations are in seconds.
	Histogram(ctx context.Context, name string, value float64, attrs behemoth.M)
}

// NoOpMetrics drops every measurement. New uses it when no sink is given.
type NoOpMetrics struct{}

func (NoOpMetrics) Counter(context.Context, string, int64, behemoth.M)     {}
func (NoOpMetrics) Histogram(context.Context, string, float64, behemoth.M) {}

// Metric names. Like the Field keys and the audit event types they are part
// of behemoth's public contract: dashboards and alerts are built on them.
// docs/api/telemetry.md lists each with its attributes.
const (
	MetricHTTPRequests = "behemoth.http.requests" // counter: one per request to a behemoth route
	MetricHTTPDuration = "behemoth.http.duration" // histogram, seconds

	MetricSignIn = "behemoth.auth.sign_in" // counter: finished and refused sign-ins
	MetricSignUp = "behemoth.auth.sign_up" // counter: finished and refused sign-ups

	MetricSessionCreated   = "behemoth.session.created"   // counter
	MetricSessionRevoked   = "behemoth.session.revoked"   // counter
	MetricSessionValidated = "behemoth.session.validated" // counter: session lookups by token

	MetricTokenIssued   = "behemoth.token.issued"   // counter
	MetricTokenConsumed = "behemoth.token.consumed" // counter
	MetricTokenFailed   = "behemoth.token.failed"   // counter

	MetricRateLimitChecks = "behemoth.ratelimit.checks" // counter: one per rule evaluated

	MetricHookDuration = "behemoth.hook.duration" // histogram, seconds: one per handler call
	MetricHookErrors   = "behemoth.hook.errors"   // counter: handler calls that returned an error or panicked

	MetricStoreDuration = "behemoth.store.duration" // histogram, seconds: one per database operation
	MetricStoreErrors   = "behemoth.store.errors"   // counter: database operations that returned an error

	MetricAuditRecordFailures = "behemoth.audit.record_failures" // counter: audit events that could not be stored
)

// Attribute keys of the metrics above.
const (
	AttrMethod        = "method"         // HTTP method
	AttrRoute         = "route"          // a route's pattern, never the request path
	AttrStatus        = "status"         // HTTP status code
	AttrOutcome       = "outcome"        // "success" or "failure"
	AttrReason        = "reason"         // a failure's code, e.g. "invalidCredentials"
	AttrKind          = "kind"           // a token kind
	AttrCache         = "cache"          // "hit" or "miss"
	AttrRule          = "rule"           // a rate-limit rule's name
	AttrResult        = "result"         // "allowed", "limited" or "error"
	AttrPoint         = "point"          // a hook point
	AttrPhase         = "phase"          // a hook phase
	AttrPlugin        = "plugin"         // the owner of a hook handler
	AttrOp            = "op"             // a database operation, e.g. "find_one"
	AttrEntity        = "entity"         // a table's canonical name
	AttrErrorCategory = "error_category" // DomainError.Category, or "unknown"
	AttrType          = "type"           // an audit event type
)

// MetricsEnabled reports whether measurements go anywhere. A call site on a
// hot path checks it before it builds attributes or reads the clock, so an
// application without a metrics sink pays nothing there.
func (t *Telemetry) MetricsEnabled() bool {
	if t == nil || t.Metrics == nil {
		return false
	}
	_, off := t.Metrics.(NoOpMetrics)
	return !off
}

// Count adds one to the counter name.
func (t *Telemetry) Count(ctx context.Context, name string, attrs behemoth.M) {
	t.Metrics.Counter(ctx, name, 1, attrs)
}

// ObserveSince records the time passed since start, in seconds, in the
// histogram name.
func (t *Telemetry) ObserveSince(ctx context.Context, name string, start time.Time, attrs behemoth.M) {
	t.Metrics.Histogram(ctx, name, time.Since(start).Seconds(), attrs)
}
