package adapters

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
)

// countingQuerier counts the statements that reach the database.
type countingQuerier struct{ calls int }

func (q *countingQuerier) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	q.calls++
	return nil, nil
}
func (q *countingQuerier) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	q.calls++
	return nil, nil
}
func (q *countingQuerier) QueryRowContext(context.Context, string, ...any) *sql.Row {
	q.calls++
	return nil
}

func TestLogQueries(t *testing.T) {
	db := &countingQuerier{}

	// Without a logger the Querier is returned as it is.
	if got := LogQueries(db, nil, "storage.test"); got != Querier(db) {
		t.Error("LogQueries(nil logger) wrapped the Querier")
	}
	if got := LogQueries(db, telemetry.NoOpLogger{}, "storage.test"); got != Querier(db) {
		t.Error("LogQueries(no-op logger) wrapped the Querier")
	}

	tel, rec := telemetrytest.New()
	q := LogQueries(db, tel.Logger, "storage.test")
	ctx := context.Background()
	q.ExecContext(ctx, "INSERT INTO users (email, password_hash) VALUES (?, ?)", "ada@example.com", "$argon2id$secret")
	q.QueryContext(ctx, "SELECT id FROM users WHERE email = ?", "ada@example.com")
	q.QueryRowContext(ctx, "SELECT COUNT(*) FROM users")

	if db.calls != 3 {
		t.Errorf("statements run = %d, want 3", db.calls)
	}
	lines := rec.Logger.At(slog.LevelDebug)
	if len(lines) != 3 || len(rec.Logger.Entries()) != 3 {
		t.Fatalf("lines = %v, want 3 debug lines", rec.Logger.Entries())
	}
	first := lines[0].Fields
	if first[telemetry.FieldStatement] != "INSERT INTO users (email, password_hash) VALUES (?, ?)" ||
		first[telemetry.FieldComponent] != "storage.test" {
		t.Errorf("fields = %v", first)
	}
	// The statement and the component are all a line holds: no arguments.
	for _, line := range lines {
		if len(line.Fields) != 2 {
			t.Errorf("a line has fields beyond statement and component: %v", line.Fields)
		}
	}
}
