package adapters

import (
	"context"
	"database/sql"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/telemetry"
)

// LogQueries returns a Querier that writes the text of each statement to
// logger at Debug before running it on db. The SQL adapters run their
// statements through it, so query logging is one behavior shared by all of
// them. component names the adapter in the line ("storage.postgres").
//
// Only the statement is logged. Its arguments hold password hashes, token
// hashes and personal data, and are left out.
//
// A nil or no-op logger returns db itself, so an adapter without a logger
// pays nothing per statement.
func LogQueries(db Querier, logger telemetry.Logger, component string) Querier {
	switch logger.(type) {
	case nil, telemetry.NoOpLogger:
		return db
	}
	return &loggingQuerier{db: db, logger: logger, component: component}
}

type loggingQuerier struct {
	db        Querier
	logger    telemetry.Logger
	component string
}

func (l *loggingQuerier) log(ctx context.Context, query string) {
	l.logger.Debug(ctx, "sql statement", behemoth.M{
		telemetry.FieldComponent: l.component,
		telemetry.FieldStatement: query,
	})
}

func (l *loggingQuerier) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	l.log(ctx, query)
	return l.db.ExecContext(ctx, query, args...)
}

func (l *loggingQuerier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	l.log(ctx, query)
	return l.db.QueryContext(ctx, query, args...)
}

func (l *loggingQuerier) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	l.log(ctx, query)
	return l.db.QueryRowContext(ctx, query, args...)
}
