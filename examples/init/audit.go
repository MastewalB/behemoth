package main

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/telemetry"
)

// audit prints the newest audit events from behemoth's audit_log table,
// newest first. With an email it prints the events about that user: their
// creation, their sign-ins, and the sign-ins that failed for their account.
//
// It reads through the store (QueryAuditEvents). An application would put
// the same call behind a route of its own, with its own access check.
func audit(ctx context.Context, email string, limit int) error {
	obs, err := newObservability(ctx)
	if err != nil {
		return err
	}
	defer obs.shutdown(ctx)
	ac, _, sqlDB, err := boot(ctx, nil, obs.tel)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	filter := telemetry.AuditFilter{Limit: limit}
	if email != "" {
		user, err := ac.Store.FindUserByEmail(ctx, email)
		if err != nil {
			return fmt.Errorf("user %s: %w", email, err)
		}
		filter.SubjectType, filter.SubjectID = models.UserTable, user.ID
	}
	page, err := ac.Store.QueryAuditEvents(ctx, filter)
	if err != nil {
		return err
	}
	for _, e := range page.Events {
		actor := string(e.ActorType)
		if e.ActorID != "" {
			actor += ":" + e.ActorID
		}
		line := fmt.Sprintf("%s  %-26s %-8s actor=%-46s subject=%s:%s ip=%s",
			e.Timestamp.Format("2006-01-02 15:04:05Z"), e.Type, e.Outcome, actor, e.SubjectType, e.SubjectID, e.IPAddress)
		if len(e.Metadata) > 0 {
			line += fmt.Sprintf(" %v", e.Metadata)
		}
		fmt.Println(line)
	}
	if page.NextCursor != "" {
		fmt.Println("... older events exist; raise -n to see more")
	}
	return nil
}
