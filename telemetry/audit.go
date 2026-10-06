package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/MastewalB/behemoth"
)

// AuditOutcome says how the audited action ended.
type AuditOutcome string

const (
	OutcomeSuccess AuditOutcome = "success"
	OutcomeFailure AuditOutcome = "failure" // attempted and rejected: a wrong password, an expired token
	OutcomeDenied  AuditOutcome = "denied"  // stopped before it was attempted: a rate limit
)

// ActorType says what kind of actor ActorID names.
type ActorType string

const (
	ActorUser      ActorType = "user"      // ActorID is a user id
	ActorAnonymous ActorType = "anonymous" // a request with no authenticated user
	ActorSystem    ActorType = "system"    // behemoth itself or code outside a request: a job, a CLI, a migration
)

// Audit event types behemoth records that are not named after a hook point.
// Events recorded for a hook point declared with an AuditSpec are named
// after the point ("auth.signIn.failed") unless the spec says otherwise. The
// types are part of behemoth's public contract, like the Field keys.
const (
	AuditUserCreated       = "user.created"
	AuditUserUpdated       = "user.updated"
	AuditRateLimitExceeded = "ratelimit.exceeded"
	AuditMigrationApplied  = "migration.applied"
	AuditSecretRotated     = "crypto.secret.rotated"
)

// AuditEvent is one recorded action: who did what to whom, how it ended,
// and when. Where a log line is for whoever operates the system, an audit
// event is the record of an action on an account, kept and queried.
type AuditEvent struct {
	// ID identifies a stored event. A recorder assigns it; Record ignores
	// the value it is given.
	ID   string
	Type string

	Outcome AuditOutcome // "" is recorded as OutcomeSuccess

	// ActorType and ActorID say who did it. An empty ActorType is derived
	// by NormalizeAuditEvent.
	ActorType ActorType
	ActorID   string

	// SubjectType and SubjectID say what it was done to: SubjectType is the
	// table's canonical name ("users", "sessions", "tokens") for a row.
	SubjectType string
	SubjectID   string

	SessionID string
	RequestID string // "" is filled from the context
	IPAddress string
	UserAgent string

	// Metadata holds what is specific to the event type: a failure code, a
	// token kind. It is redacted like log fields, except that email
	// addresses are kept.
	Metadata  behemoth.M
	Timestamp time.Time // zero is recorded as the current time
}

// AuditRecorder stores audit events. It is the write side only, because a
// sink such as a log stream can record an event and cannot query one; see
// AuditReader.
type AuditRecorder interface {
	Record(ctx context.Context, event AuditEvent) error
}

// TxAuditRecorder is an AuditRecorder that can write an event through a
// database transaction, so the event commits or rolls back with the write it
// describes. The hook dispatcher uses RecordTx for audited data points and
// passes the adapter bound to the write's transaction. The database recorder
// (store.AuditRecorder) implements it.
type TxAuditRecorder interface {
	AuditRecorder
	RecordTx(ctx context.Context, tx behemoth.Database, event AuditEvent) error
}

// AuditReader reads recorded events back.
type AuditReader interface {
	Query(ctx context.Context, filter AuditFilter) (AuditPage, error)
}

// AuditFilter selects events. Every field that is set must match; the zero
// value selects everything.
type AuditFilter struct {
	Types       []string // any of these types
	Outcome     AuditOutcome
	ActorID     string
	SubjectType string
	SubjectID   string
	SessionID   string
	RequestID   string
	From        time.Time // recorded at or after From
	To          time.Time // recorded before To

	// Limit is the page size. Zero means DefaultAuditPageSize; values above
	// MaxAuditPageSize are lowered to it.
	Limit int
	// Cursor continues a query: the NextCursor of the page before. The
	// other fields must be the same as in that query.
	Cursor string
}

const (
	DefaultAuditPageSize = 50
	MaxAuditPageSize     = 500
)

// AuditPage is one page of a query, newest event first.
type AuditPage struct {
	Events []AuditEvent
	// NextCursor is the AuditFilter.Cursor of the next page, or "" when
	// this is the last one.
	NextCursor string
}

// NoOpAuditRecorder drops every event. Passing it to New turns auditing
// off: without it, Boot records to the audit_log table.
type NoOpAuditRecorder struct{}

func (NoOpAuditRecorder) Record(context.Context, AuditEvent) error { return nil }

// unsetAuditRecorder is what New puts in place of a nil recorder. It drops
// events like NoOpAuditRecorder, and tells Boot that the application chose
// no recorder, so the default one applies.
type unsetAuditRecorder struct{ NoOpAuditRecorder }

// AuditConfigured reports whether t was given an audit recorder. Boot uses
// the database recorder when it was not.
func (t *Telemetry) AuditConfigured() bool {
	_, unset := t.Audit.(unsetAuditRecorder)
	return t.Audit != nil && !unset
}

// NormalizeAuditEvent returns event as a recorder should store it:
//
//   - Timestamp: the current time in UTC when zero.
//   - RequestID: the context's request ID when empty.
//   - Outcome: OutcomeSuccess when empty.
//   - ActorType, when empty: ActorUser if ActorID is set, ActorAnonymous
//     for an event recorded while handling a request, ActorSystem otherwise.
//   - Metadata: a redacted copy (see Redact). Email addresses are kept.
//
// RecordAudit calls it. Code that hands an event to a recorder itself, like
// the dispatcher's in-transaction path, calls it first.
func NormalizeAuditEvent(ctx context.Context, event AuditEvent) AuditEvent {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.RequestID == "" {
		event.RequestID = RequestIDFrom(ctx)
	}
	if event.Outcome == "" {
		event.Outcome = OutcomeSuccess
	}
	if event.ActorType == "" {
		switch {
		case event.ActorID != "":
			event.ActorType = ActorUser
		case event.RequestID != "":
			event.ActorType = ActorAnonymous
		default:
			event.ActorType = ActorSystem
		}
	}
	event.Metadata = auditRedactor.redact(event.Metadata)
	return event
}

var auditRedactor = newRedactor(options{allowEmails: true})

// RecordAudit normalizes event and records it, best effort: a failed write
// is logged at Error and returned, and the caller carries on. Components
// record through it, so no audit failure is dropped silently.
func (t *Telemetry) RecordAudit(ctx context.Context, event AuditEvent) error {
	event = NormalizeAuditEvent(ctx, event)
	err := t.Audit.Record(ctx, event)
	if err != nil {
		t.Logger.Error(ctx, "audit event could not be recorded", ErrorFields(err, behemoth.M{"audit_type": event.Type}))
	}
	return err
}

// MultiRecorder returns an AuditRecorder that records each event to every
// one of recorders, for example the database and a log stream a SIEM reads.
// A failing recorder does not stop the others; their errors are joined.
//
// The dispatcher looks inside it (Recorders), so a database recorder in the
// list still writes audited data points in their transaction.
func MultiRecorder(recorders ...AuditRecorder) AuditRecorder {
	return multiRecorder(recorders)
}

type multiRecorder []AuditRecorder

func (m multiRecorder) Record(ctx context.Context, event AuditEvent) error {
	var errs []error
	for _, r := range m {
		if err := r.Record(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Recorders returns the recorders m fans out to.
func (m multiRecorder) Recorders() []AuditRecorder { return m }

// SplitAuditRecorders flattens r (a MultiRecorder, possibly nested) and
// separates the recorders that can write in a transaction from the rest.
func SplitAuditRecorders(r AuditRecorder) (inTx []TxAuditRecorder, rest []AuditRecorder) {
	if multi, ok := r.(interface{ Recorders() []AuditRecorder }); ok {
		for _, child := range multi.Recorders() {
			t, o := SplitAuditRecorders(child)
			inTx, rest = append(inTx, t...), append(rest, o...)
		}
		return inTx, rest
	}
	if tx, ok := r.(TxAuditRecorder); ok {
		return []TxAuditRecorder{tx}, nil
	}
	if r != nil {
		rest = []AuditRecorder{r}
	}
	return nil, rest
}
