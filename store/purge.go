package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-behemoth/behemoth/models"
)

// PurgeOptions holds the cutoffs of Purge. A zero cutoff leaves its table
// alone.
type PurgeOptions struct {
	// SessionsBefore removes the sessions that expired before it, as
	// PurgeExpiredSessions does.
	SessionsBefore time.Time
	// TokensBefore removes the tokens that expired before it, and those with
	// no expiry that were consumed or revoked before it, as
	// PurgeExpiredTokens does.
	TokensBefore time.Time
	// AuditEventsBefore removes the audit events recorded before it, as
	// PurgeAuditEvents does.
	AuditEventsBefore time.Time
}

// Purge runs each of the store's purges once. The sessions, tokens and audit
// events go up to the cutoffs in opts. The expired rate-limit counters,
// one-time codes and value reservations always go: they take no cutoff,
// because an expired row of theirs already acts as a missing one. A purge
// that fails does not stop the others, and the error joins the failures,
// each naming its table.
//
// Purge only deletes rows, so it is safe to run from several processes at
// once. Behemoth does not schedule it: the application runs it from its own
// scheduler or from a job, such as a Kubernetes CronJob.
func (s *Store) Purge(ctx context.Context, opts PurgeOptions) error {
	var failed []error
	note := func(table string, err error) {
		if err != nil {
			failed = append(failed, fmt.Errorf("store: purge %s: %w", table, err))
		}
	}
	if !opts.SessionsBefore.IsZero() {
		note(models.SessionTable, s.PurgeExpiredSessions(ctx, opts.SessionsBefore))
	}
	if !opts.TokensBefore.IsZero() {
		note(models.TokenTable, s.PurgeExpiredTokens(ctx, opts.TokensBefore))
	}
	if !opts.AuditEventsBefore.IsZero() {
		note(models.AuditLogTable, s.PurgeAuditEvents(ctx, opts.AuditEventsBefore))
	}
	note(models.RateLimitTable, s.PurgeExpiredRateLimits(ctx))
	note(models.VerificationCodeTable, s.PurgeExpiredVerificationCodes(ctx))
	note(models.ReservedValueTable, s.PurgeExpiredReservedValues(ctx))
	return errors.Join(failed...)
}
