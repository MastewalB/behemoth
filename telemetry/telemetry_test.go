package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
)

func TestNewFillsNoOps(t *testing.T) {
	tel := telemetry.New(nil, nil, nil)
	if tel.Logger == nil || tel.Audit == nil || tel.Metrics == nil {
		t.Fatalf("New left a nil sink: %+v", tel)
	}
	// None of these may panic.
	tel.Logger.Error(context.Background(), "x", nil)
	if err := tel.Audit.Record(context.Background(), telemetry.AuditEvent{}); err != nil {
		t.Errorf("no-op Record = %v", err)
	}
	tel.Metrics.Counter("x", nil)
}

func TestOrDefault(t *testing.T) {
	if tel := telemetry.OrDefault(nil); tel == nil || tel.Logger == nil {
		t.Fatal("OrDefault(nil) is not usable")
	}

	// A struct literal with one field set gets no-ops for the rest, and its
	// logger is redacted like one passed to New.
	rec := &telemetrytest.Logger{}
	tel := telemetry.OrDefault(&telemetry.Telemetry{Logger: rec})
	if tel.Audit == nil || tel.Metrics == nil {
		t.Fatal("OrDefault left a nil sink")
	}
	tel.Logger.Info(context.Background(), "x", behemoth.M{"password": "hunter2"})
	if got := rec.Entries()[0].Fields["password"]; got != telemetry.Redacted {
		t.Errorf("password = %v, want it redacted", got)
	}
}

func TestLoggerRedacts(t *testing.T) {
	tel, rec := telemetrytest.New()
	fields := behemoth.M{
		"password":      "hunter2",
		"newPassword":   "hunter3",
		"refresh_token": "abc",
		"passwordHash":  "$argon2id$...",
		"Authorization": "Bearer abc",
		"email":         "ada@example.com",
		"tokenID":       "tok_1", // an identifier, not a secret
		"user_id":       "u1",
		"nested":        behemoth.M{"secret": "s", "kind": "reset"},
	}
	tel.Logger.Info(context.Background(), "x", fields)

	got := rec.Logger.Entries()[0].Fields
	for _, k := range []string{"password", "newPassword", "refresh_token", "passwordHash", "Authorization", "email"} {
		if got[k] != telemetry.Redacted {
			t.Errorf("%s = %v, want it redacted", k, got[k])
		}
	}
	if got["tokenID"] != "tok_1" || got["user_id"] != "u1" {
		t.Errorf("identifiers were changed: %v", got)
	}
	nested := got["nested"].(behemoth.M)
	if nested["secret"] != telemetry.Redacted || nested["kind"] != "reset" {
		t.Errorf("nested = %v, want only secret redacted", nested)
	}
	if fields["password"] != "hunter2" || fields["nested"].(behemoth.M)["secret"] != "s" {
		t.Error("the caller's map was modified")
	}
}

func TestRedactionOptions(t *testing.T) {
	tel, rec := telemetrytest.New(telemetry.WithEmailsInLogs(), telemetry.WithRedactedKeys("API_Key"))
	tel.Logger.Info(context.Background(), "x", behemoth.M{"email": "ada@example.com", "api_key": "k", "password": "p"})

	got := rec.Logger.Entries()[0].Fields
	if got["email"] != "ada@example.com" {
		t.Errorf("email = %v, want it kept with WithEmailsInLogs", got["email"])
	}
	if got["api_key"] != telemetry.Redacted || got["password"] != telemetry.Redacted {
		t.Errorf("api_key, password = %v, %v; want both redacted", got["api_key"], got["password"])
	}
}

func TestLoggerAddsRequestID(t *testing.T) {
	tel, rec := telemetrytest.New()
	ctx := telemetry.ContextWithRequestID(context.Background(), "req-1")

	tel.Logger.Warn(ctx, "from a request", nil)
	tel.Logger.Warn(context.Background(), "from a job", nil)
	tel.Logger.Warn(ctx, "explicit", behemoth.M{telemetry.FieldRequestID: "other"})

	entries := rec.Logger.Entries()
	if got := entries[0].Fields[telemetry.FieldRequestID]; got != "req-1" {
		t.Errorf("request_id = %v, want req-1", got)
	}
	if _, set := entries[1].Fields[telemetry.FieldRequestID]; set {
		t.Errorf("a line outside a request has a request_id: %v", entries[1].Fields)
	}
	if got := entries[2].Fields[telemetry.FieldRequestID]; got != "other" {
		t.Errorf("request_id = %v, want the line's own value kept", got)
	}
}

func TestNamed(t *testing.T) {
	tel, rec := telemetrytest.New()
	log := telemetry.Named(tel.Logger, "session")

	fields := behemoth.M{"password": "p"}
	log.Info(context.Background(), "a", fields)
	log.Info(context.Background(), "b", behemoth.M{telemetry.FieldComponent: "override"})
	log.Info(context.Background(), "c", nil)

	entries := rec.Logger.Entries()
	if entries[0].Fields[telemetry.FieldComponent] != "session" || entries[0].Fields["password"] != telemetry.Redacted {
		t.Errorf("fields = %v, want component=session and password redacted", entries[0].Fields)
	}
	if entries[1].Fields[telemetry.FieldComponent] != "override" {
		t.Errorf("component = %v, want the line's own value kept", entries[1].Fields[telemetry.FieldComponent])
	}
	if entries[2].Fields[telemetry.FieldComponent] != "session" {
		t.Errorf("a nil-fields line lost its component: %v", entries[2].Fields)
	}
	if _, set := fields[telemetry.FieldComponent]; set {
		t.Error("the caller's map was modified")
	}

	if _, ok := telemetry.Named(nil, "x").(telemetry.NoOpLogger); !ok {
		t.Error("Named(nil) is not a no-op logger")
	}
}

func TestErrorFields(t *testing.T) {
	if got := telemetry.ErrorFields(nil); len(got) != 0 {
		t.Errorf("ErrorFields(nil) = %v, want empty", got)
	}

	plain := telemetry.ErrorFields(errors.New("boom"))
	if plain[telemetry.FieldError] != "boom" || plain[telemetry.FieldErrorCode] != behemotherr.ErrorCodeUnknown {
		t.Errorf("plain error fields = %v", plain)
	}
	if _, set := plain[telemetry.FieldErrorCategory]; set {
		t.Errorf("a plain error has a category: %v", plain)
	}

	// A DomainError is found through wrapping.
	wrapped := fmt.Errorf("sign-in: %w", behemotherr.NewNotFound("Store.FindUser", "user", nil))
	got := telemetry.ErrorFields(wrapped)
	want := behemoth.M{
		telemetry.FieldError:         wrapped.Error(),
		telemetry.FieldErrorCode:     "user_not_found",
		telemetry.FieldErrorCategory: string(behemotherr.CategoryNotFound),
		telemetry.FieldOp:            "Store.FindUser",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestRequestID(t *testing.T) {
	if got := telemetry.RequestIDFrom(context.Background()); got != "" {
		t.Errorf("RequestIDFrom(empty ctx) = %q", got)
	}
	a, b := telemetry.NewRequestID(), telemetry.NewRequestID()
	if len(a) != 32 || a == b || !telemetry.ValidRequestID(a) {
		t.Errorf("NewRequestID gave %q and %q", a, b)
	}

	for id, want := range map[string]bool{
		"abc-123_DEF.4":          true,
		"":                       false,
		"has space":              false,
		"line\nbreak":            false,
		"tab\t":                  false,
		"non-ascii-é":            false,
		strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false,
	} {
		if got := telemetry.ValidRequestID(id); got != want {
			t.Errorf("ValidRequestID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	tel := telemetry.New(telemetry.NewJSONLogger(&buf, slog.LevelInfo), nil, nil)
	ctx := telemetry.ContextWithRequestID(context.Background(), "req-1")

	tel.Logger.Debug(ctx, "below the level", nil)
	if buf.Len() != 0 {
		t.Fatalf("a debug line was written at level info: %s", buf.String())
	}

	fields := telemetry.ErrorFields(behemotherr.NewInternalError("Boot", errors.New("boom")))
	fields["token"] = "abc"
	telemetry.Named(tel.Logger, "router").Error(ctx, "request failed", fields)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("output is not one JSON line: %v\n%s", err, buf.String())
	}
	want := map[string]any{
		"level":                      "ERROR",
		"msg":                        "request failed",
		telemetry.FieldComponent:     "router",
		telemetry.FieldRequestID:     "req-1",
		telemetry.FieldErrorCode:     "internal_error",
		telemetry.FieldErrorCategory: "internal",
		"token":                      telemetry.Redacted,
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v", k, line[k], v)
		}
	}
}

func TestRecorderSinks(t *testing.T) {
	tel, rec := telemetrytest.New()

	tel.Logger.Warn(context.Background(), "w", nil)
	tel.Logger.Error(context.Background(), "e", nil)
	if n := len(rec.Logger.At(slog.LevelError)); n != 1 {
		t.Errorf("error lines = %d, want 1", n)
	}
	rec.Logger.Reset()
	if n := len(rec.Logger.Entries()); n != 0 {
		t.Errorf("entries after Reset = %d", n)
	}

	if err := tel.Audit.Record(context.Background(), telemetry.AuditEvent{Type: "auth.signIn.failed"}); err != nil {
		t.Fatal(err)
	}
	if events := rec.Audit.Events(); len(events) != 1 || events[0].Type != "auth.signIn.failed" {
		t.Errorf("events = %v", events)
	}
	rec.Audit.Err = errors.New("db down")
	if err := tel.Audit.Record(context.Background(), telemetry.AuditEvent{}); err == nil {
		t.Error("Record did not return Err")
	}

	tel.Metrics.Counter("c", nil)
	tel.Metrics.Gauge("g", 2.5, nil)
	if len(rec.Metrics.Counters()) != 1 || rec.Metrics.Gauges()[0].Value != 2.5 {
		t.Errorf("counters = %v, gauges = %v", rec.Metrics.Counters(), rec.Metrics.Gauges())
	}
}

func TestAuditConfigured(t *testing.T) {
	if telemetry.New(nil, nil, nil).AuditConfigured() {
		t.Error("a nil recorder counts as configured")
	}
	if telemetry.OrDefault(&telemetry.Telemetry{}).AuditConfigured() {
		t.Error("a struct literal without a recorder counts as configured")
	}
	// Turning auditing off is a choice, and survives OrDefault.
	off := telemetry.OrDefault(telemetry.New(nil, telemetry.NoOpAuditRecorder{}, nil))
	if !off.AuditConfigured() {
		t.Error("NoOpAuditRecorder does not count as configured")
	}
}

func TestNormalizeAuditEvent(t *testing.T) {
	inRequest := telemetry.ContextWithRequestID(context.Background(), "req-1")

	got := telemetry.NormalizeAuditEvent(inRequest, telemetry.AuditEvent{
		Type:     "auth.signIn.failed",
		Metadata: behemoth.M{"email": "ada@example.com", "password": "hunter2", "code": "invalidCredentials"},
	})
	if got.Timestamp.IsZero() || got.RequestID != "req-1" || got.Outcome != telemetry.OutcomeSuccess {
		t.Errorf("defaults not applied: %+v", got)
	}
	if got.ActorType != telemetry.ActorAnonymous {
		t.Errorf("actor type = %q, want anonymous for a request without an actor", got.ActorType)
	}
	// Emails stay in audit metadata; secrets do not.
	if got.Metadata["email"] != "ada@example.com" || got.Metadata["password"] != telemetry.Redacted {
		t.Errorf("metadata = %v", got.Metadata)
	}

	if got := telemetry.NormalizeAuditEvent(context.Background(), telemetry.AuditEvent{}); got.ActorType != telemetry.ActorSystem {
		t.Errorf("actor type = %q, want system outside a request", got.ActorType)
	}
	if got := telemetry.NormalizeAuditEvent(inRequest, telemetry.AuditEvent{ActorID: "u1"}); got.ActorType != telemetry.ActorUser {
		t.Errorf("actor type = %q, want user when there is an actor id", got.ActorType)
	}
	// What the caller set is kept.
	kept := telemetry.NormalizeAuditEvent(inRequest, telemetry.AuditEvent{
		Outcome: telemetry.OutcomeDenied, ActorType: telemetry.ActorSystem, RequestID: "other",
	})
	if kept.Outcome != telemetry.OutcomeDenied || kept.ActorType != telemetry.ActorSystem || kept.RequestID != "other" {
		t.Errorf("explicit values were overwritten: %+v", kept)
	}
}

func TestRecordAuditLogsAFailedWrite(t *testing.T) {
	tel, rec := telemetrytest.New()
	if err := tel.RecordAudit(context.Background(), telemetry.AuditEvent{Type: "x"}); err != nil {
		t.Fatal(err)
	}
	if events := rec.Audit.Events(); len(events) != 1 || events[0].Outcome != telemetry.OutcomeSuccess {
		t.Fatalf("events = %+v, want one normalized event", events)
	}

	rec.Audit.Err = errors.New("db down")
	if err := tel.RecordAudit(context.Background(), telemetry.AuditEvent{Type: "ratelimit.exceeded"}); err == nil {
		t.Error("RecordAudit did not return the recorder's error")
	}
	lines := rec.Logger.At(slog.LevelError)
	if len(lines) != 1 || lines[0].Fields["audit_type"] != "ratelimit.exceeded" || lines[0].Fields[telemetry.FieldError] != "db down" {
		t.Errorf("error lines = %+v, want one naming the event type", lines)
	}
}

// txRecorder can write in a transaction; it records which path was used.
type txRecorder struct{ direct, inTx int }

func (r *txRecorder) Record(context.Context, telemetry.AuditEvent) error { r.direct++; return nil }
func (r *txRecorder) RecordTx(context.Context, behemoth.Database, telemetry.AuditEvent) error {
	r.inTx++
	return nil
}

func TestMultiRecorder(t *testing.T) {
	a, b := &telemetrytest.AuditRecorder{}, &telemetrytest.AuditRecorder{}
	failing := &telemetrytest.AuditRecorder{Err: errors.New("sink down")}
	multi := telemetry.MultiRecorder(a, failing, b)

	err := multi.Record(context.Background(), telemetry.AuditEvent{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "sink down") {
		t.Errorf("Record = %v, want the failing recorder's error", err)
	}
	if len(a.Events()) != 1 || len(b.Events()) != 1 {
		t.Error("a failing recorder stopped the others")
	}

	// Recorders that can write in a transaction are found inside a
	// MultiRecorder, however deeply nested.
	db := &txRecorder{}
	inTx, rest := telemetry.SplitAuditRecorders(telemetry.MultiRecorder(a, telemetry.MultiRecorder(db, b)))
	if len(inTx) != 1 || inTx[0] != telemetry.TxAuditRecorder(db) || len(rest) != 2 {
		t.Errorf("split = %d in-transaction, %d other; want 1 and 2", len(inTx), len(rest))
	}
	if inTx, rest := telemetry.SplitAuditRecorders(a); len(inTx) != 0 || len(rest) != 1 {
		t.Errorf("a plain recorder split into %d and %d", len(inTx), len(rest))
	}
}
