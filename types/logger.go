package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
)

// Logger is the logging interface plugins use. It is intentionally minimal —
// plugins should not be coupled to any specific library.
// The behemoth user wires in their preferred logger via CoreOptions.
//
// Fields are key-value pairs: logger.Info("user created", "id", u.ID, "email", u.Email)
type Logger interface {
	Debug(ctx context.Context, msg string, fields behemoth.M)
	Info(ctx context.Context, msg string, fields behemoth.M)
	Warn(ctx context.Context, msg string, fields behemoth.M)
	Error(ctx context.Context, msg string, fields behemoth.M)
}

type AuditEvent struct {
	Type      string
	ActorID   any // who did it, nullable for system-initiated events
	SubjectID any // who/what it was done to
	Metadata  behemoth.M
	Timestamp time.Time
	// RequestID
}

type AuditFilter struct{}

type AuditRecorder interface {
	Record(ctx context.Context, event AuditEvent) error
	Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error)
}

type AuditLogEntry struct {
	ID        string
	Type      string
	ActorID   string
	SubjectID string
	Metadata  behemoth.M
	RequestID string
	CreatedAt time.Time
}

func (al *AuditLogEntry) SchemaName() string     { return "audit_log" }
func (al *AuditLogEntry) PrimaryKeyName() string { return "id" }
func (al *AuditLogEntry) PrimaryKeyField() any   { return al.ID }
func (al *AuditLogEntry) New() behemoth.Model    { return &AuditLogEntry{} }

type dbAuditRecorder struct{ db behemoth.Database }

func (r *dbAuditRecorder) Record(ctx context.Context, event AuditEvent) error {
	entry := auditEntryFromEvent(event)
	return r.db.Create(ctx, entry) // Create only
}

func auditEntryFromEvent(_ AuditEvent) *AuditLogEntry {
	return &AuditLogEntry{}
}

type AuditSpec struct {
	Type string // audit event Type; defaults to the HookPoint string if empty
}

type Metrics interface {
	Counter(name string, tags behemoth.M)
	Gauge(name string, value float64, tags behemoth.M)
}

type Telemetry struct {
	Logger  Logger
	Audit   AuditRecorder
	Metrics Metrics
}

// noopLogger is used when the caller does not provide a logger.
// And to make sure that Plugins always get a valid Logger.
type NoOpLogger struct{}

func (NoOpLogger) Debug(_ context.Context, _ string, _ behemoth.M) {}
func (NoOpLogger) Info(_ context.Context, _ string, _ behemoth.M)  {}
func (NoOpLogger) Warn(_ context.Context, _ string, _ behemoth.M)  {}
func (NoOpLogger) Error(_ context.Context, _ string, _ behemoth.M) {}

type noopAuditRecorder struct{}

func (noopAuditRecorder) Record(ctx context.Context, event AuditEvent) error { return nil }
func (noopAuditRecorder) Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	return nil, nil
}

type noopMetrics struct{}

func (noopMetrics) Counter(name string, tags behemoth.M)              {}
func (noopMetrics) Gauge(name string, value float64, tags behemoth.M) {}

// NewTelemetry fills in a no-op for any field left nil
// The point of this constructor is that a *Telemetry, once built, is never
// nil-checked anywhere else in the system
func NewTelemetry(logger Logger, audit AuditRecorder, metrics Metrics) *Telemetry {
	if logger == nil {
		logger = NoOpLogger{}
	}
	if audit == nil {
		audit = noopAuditRecorder{}
	}
	if metrics == nil {
		metrics = noopMetrics{}
	}
	return &Telemetry{Logger: logger, Audit: audit, Metrics: metrics}
}
