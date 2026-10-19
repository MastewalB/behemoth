package messaging

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/telemetry/telemetrytest"
)

// Send waits for the sender and returns its error. Without a sender both
// ways of sending are a configuration error.
func TestMailerSendWaits(t *testing.T) {
	ctx := context.Background()
	none := NewMailer(core.MailConfig{}, nil)
	if none.Configured() {
		t.Error("a mailer without a sender says it is configured")
	}
	for name, err := range map[string]error{
		"Send":      none.Send(ctx, core.MailMessage{}),
		"SendAsync": none.SendAsync(ctx, core.MailMessage{}),
	} {
		if !errs.IsCategory(err, errs.CategoryConfiguration) {
			t.Errorf("%s without a sender returned %v, want a configuration error", name, err)
		}
	}

	down := errors.New("smtp down")
	var got []core.MailMessage
	tel, rec := telemetrytest.New()
	m := NewMailer(core.MailConfig{Sender: core.MailSenderFunc(func(_ context.Context, msg core.MailMessage) error {
		got = append(got, msg)
		if msg.To == "fail@example.com" {
			return down
		}
		return nil
	})}, tel)
	if !m.Configured() {
		t.Error("a mailer with a sender says it is not configured")
	}
	if err := m.Send(ctx, core.MailMessage{Kind: core.MailMagicLink, To: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Send(ctx, core.MailMessage{Kind: core.MailMagicLink, To: "fail@example.com"}); !errors.Is(err, down) {
		t.Errorf("Send returned %v, want the sender's error", err)
	}
	if len(got) != 2 {
		t.Errorf("the sender got %d messages, want 2", len(got))
	}
	for result, want := range map[string]int64{"sent": 1, "error": 1} {
		if n := rec.Metrics.Count(telemetry.MetricMailSent, behemoth.M{telemetry.AttrKind: "magic_link", telemetry.AttrResult: result}); n != want {
			t.Errorf("messages with result %q = %d, want %d", result, n, want)
		}
	}
}

// SendAsync returns before the sender does, runs the send without the
// caller's cancellation, logs a failure, refuses a message when the queue is
// full, and Close waits for what was queued.
func TestMailerSendAsync(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var sent []string
	tel, rec := telemetrytest.New()
	m := NewMailer(core.MailConfig{
		Workers: 1, QueueSize: 2,
		Sender: core.MailSenderFunc(func(ctx context.Context, msg core.MailMessage) error {
			<-release
			if err := ctx.Err(); err != nil {
				return err
			}
			mu.Lock()
			sent = append(sent, msg.To)
			mu.Unlock()
			switch msg.To {
			case "fail@example.com":
				return errors.New("smtp down")
			case "panic@example.com":
				panic("boom")
			}
			return nil
		}),
	}, tel)

	// The request's context ends as soon as the message is queued.
	ctx, cancel := context.WithCancel(context.Background())
	msg := func(to string) core.MailMessage {
		return core.MailMessage{Kind: core.MailEmailVerification, To: to}
	}
	if err := m.SendAsync(ctx, msg("ada@example.com")); err != nil {
		t.Fatal(err)
	}
	cancel()

	// One message is with the worker, which is blocked; two more fit in the
	// queue. Wait for the worker to take the first one before filling it.
	deadline := time.Now().Add(5 * time.Second)
	for len(m.queue) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the worker did not pick the first message up")
		}
		time.Sleep(time.Millisecond)
	}
	for _, to := range []string{"fail@example.com", "panic@example.com"} {
		if err := m.SendAsync(context.Background(), msg(to)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.SendAsync(context.Background(), msg("late@example.com")); !errors.Is(err, ErrMailQueueFull) {
		t.Errorf("a send into a full queue returned %v, want ErrMailQueueFull", err)
	}

	close(release)
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := m.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := m.SendAsync(context.Background(), msg("after@example.com")); !errors.Is(err, ErrMailerClosed) {
		t.Errorf("a send after Close returned %v, want ErrMailerClosed", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"ada@example.com", "fail@example.com", "panic@example.com"}; len(sent) != len(want) || sent[0] != want[0] || sent[1] != want[1] || sent[2] != want[2] {
		t.Errorf("sent = %q, want %q: the queued messages, in order, although the caller's context was canceled", sent, want)
	}
	if lines := rec.Logger.At(slog.LevelError); len(lines) != 2 {
		t.Errorf("error lines = %d, want one for the failed send and one for the panic", len(lines))
	}
	for result, want := range map[string]int64{"sent": 1, "error": 2, "dropped": 1} {
		if n := rec.Metrics.Count(telemetry.MetricMailSent, behemoth.M{telemetry.AttrKind: "email_verification", telemetry.AttrResult: result}); n != want {
			t.Errorf("messages with result %q = %d, want %d", result, n, want)
		}
	}
}
