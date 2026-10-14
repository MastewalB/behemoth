package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/google/uuid"
)

// newAuditID returns a UUIDv7. Its leading bits are the time, and ids made
// by one process only increase, so sorting the audit log by id sorts it by
// the order events were recorded. QueryAuditEvents pages on that.
func newAuditID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString() // no clock or entropy: still unique, order lost
	}
	return id.String()
}

// RecordAuditEvent inserts event into the audit log, assigning its id. The
// event is stored as given: callers normalize it first
// (telemetry.NormalizeAuditEvent), which telemetry.Telemetry.RecordAudit
// does for them. A zero Timestamp is replaced by the store's clock.
//
// On a Store bound to a transaction the row commits or rolls back with it.
// The table fires no data hooks. There is no operation to change or remove
// one event; PurgeAuditEvents removes old ones in bulk.
func (s *Store) RecordAuditEvent(ctx context.Context, event telemetry.AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = s.now()
	}
	return s.db.Create(ctx, &models.AuditLog{
		ID:          newAuditID(),
		EventType:   event.Type,
		Outcome:     string(event.Outcome),
		ActorType:   string(event.ActorType),
		ActorID:     event.ActorID,
		SubjectType: event.SubjectType,
		SubjectID:   event.SubjectID,
		SessionID:   event.SessionID,
		RequestID:   event.RequestID,
		IPAddress:   event.IPAddress,
		UserAgent:   event.UserAgent,
		Metadata:    event.Metadata,
		CreatedAt:   event.Timestamp.UTC(),
	})
}

// QueryAuditEvents returns one page of the events matching filter, newest
// first. Pass the page's NextCursor as filter.Cursor, with the other fields
// unchanged, to read the next one.
//
// Paging is by id and not by offset, so events recorded while a caller pages
// don't shift the pages: they are newer than the first page and are not
// returned.
func (s *Store) QueryAuditEvents(ctx context.Context, filter telemetry.AuditFilter) (telemetry.AuditPage, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = telemetry.DefaultAuditPageSize
	}
	limit = min(limit, telemetry.MaxAuditPageSize)

	var conds []clause.Condition
	add := func(field string, op clause.Operator, value any) {
		conds = append(conds, clause.Condition{Field: field, Operator: op, Value: value})
	}
	switch len(filter.Types) {
	case 0:
	case 1:
		add(models.AuditLogEventType, clause.OpEqual, filter.Types[0])
	default:
		types := make([]any, len(filter.Types))
		for i, t := range filter.Types {
			types[i] = t
		}
		add(models.AuditLogEventType, clause.OpIn, types)
	}
	for _, f := range []struct{ field, value string }{
		{models.AuditLogOutcome, string(filter.Outcome)},
		{models.AuditLogActorID, filter.ActorID},
		{models.AuditLogSubjectType, filter.SubjectType},
		{models.AuditLogSubjectID, filter.SubjectID},
		{models.AuditLogSessionID, filter.SessionID},
		{models.AuditLogRequestID, filter.RequestID},
	} {
		if f.value != "" {
			add(f.field, clause.OpEqual, f.value)
		}
	}
	if !filter.From.IsZero() {
		add(models.AuditLogCreatedAt, clause.OpGreaterEq, filter.From.UTC())
	}
	if !filter.To.IsZero() {
		add(models.AuditLogCreatedAt, clause.OpLessThan, filter.To.UTC())
	}
	if filter.Cursor != "" {
		add(models.AuditLogID, clause.OpLessThan, filter.Cursor)
	}

	// One row more than the page, to learn whether another page follows.
	found, err := s.db.FindMany(ctx, &models.AuditLog{}, clause.Expression{Conditions: conds, Logic: clause.OpAnd},
		&behemoth.QueryOptions{Limit: limit + 1, OrderBy: behemoth.Order{Field: models.AuditLogID, Direction: behemoth.Desc}})
	if err != nil {
		return telemetry.AuditPage{}, err
	}
	var page telemetry.AuditPage
	for i, f := range found {
		row, ok := f.(*models.AuditLog)
		if !ok {
			return telemetry.AuditPage{}, fmt.Errorf("store: unexpected %T in audit_log", f)
		}
		if i == limit {
			page.NextCursor = page.Events[limit-1].ID
			break
		}
		page.Events = append(page.Events, telemetry.AuditEvent{
			ID:          row.ID,
			Type:        row.EventType,
			Outcome:     telemetry.AuditOutcome(row.Outcome),
			ActorType:   telemetry.ActorType(row.ActorType),
			ActorID:     row.ActorID,
			SubjectType: row.SubjectType,
			SubjectID:   row.SubjectID,
			SessionID:   row.SessionID,
			RequestID:   row.RequestID,
			IPAddress:   row.IPAddress,
			UserAgent:   row.UserAgent,
			Metadata:    row.Metadata,
			Timestamp:   row.CreatedAt,
		})
	}
	return page, nil
}

// PurgeAuditEvents deletes the events recorded before the given time. It is
// the retention tool: behemoth never deletes audit events by itself, so the
// application calls it from its own scheduled job.
func (s *Store) PurgeAuditEvents(ctx context.Context, before time.Time) error {
	return s.db.DeleteMany(ctx, &models.AuditLog{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.AuditLogCreatedAt, Operator: clause.OpLessThan, Value: before.UTC()},
	}})
}

// AuditRecorder is the audit recorder backed by the audit_log table. Boot
// uses it when the application chose no recorder. It writes through the
// Store it was built from, and for audited data points through the
// transaction of the write (RecordTx).
type AuditRecorder struct {
	st *Store
}

var (
	_ telemetry.TxAuditRecorder = (*AuditRecorder)(nil)
	_ telemetry.AuditReader     = (*AuditRecorder)(nil)
)

// NewAuditRecorder returns the database audit recorder over st. To also
// send events elsewhere, combine it with telemetry.MultiRecorder.
func NewAuditRecorder(st *Store) *AuditRecorder { return &AuditRecorder{st: st} }

// Record implements [telemetry.AuditRecorder].
func (r *AuditRecorder) Record(ctx context.Context, event telemetry.AuditEvent) error {
	return r.st.RecordAuditEvent(ctx, event)
}

// RecordTx implements [telemetry.TxAuditRecorder]: the row is inserted
// through tx, the adapter bound to a transaction.
func (r *AuditRecorder) RecordTx(ctx context.Context, tx behemoth.Database, event telemetry.AuditEvent) error {
	bound := *r.st
	bound.db, bound.inTx = tx, true
	return bound.RecordAuditEvent(ctx, event)
}

// Query implements [telemetry.AuditReader].
func (r *AuditRecorder) Query(ctx context.Context, filter telemetry.AuditFilter) (telemetry.AuditPage, error) {
	return r.st.QueryAuditEvents(ctx, filter)
}
