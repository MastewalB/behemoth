package messaging

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/telemetry"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
)

// The SMS sender shares the mailer's queue code; this covers what is its
// own: the configuration error, the metric and the separate channel.
func TestSMSSendsWaitingAndInBackground(t *testing.T) {
	ctx := context.Background()

	none := NewSMS(core.SMSConfig{}, nil)
	if none.Configured() {
		t.Error("an SMS sender without a Sender reports configured")
	}
	for name, err := range map[string]error{
		"Send":      none.Send(ctx, core.SMSMessage{}),
		"SendAsync": none.SendAsync(ctx, core.SMSMessage{}),
	} {
		if !errs.IsCategory(err, errs.CategoryConfiguration) {
			t.Errorf("%s without a sender: %v", name, err)
		}
	}

	tel, rec := telemetrytest.New()
	got := make(chan core.SMSMessage, 2)
	failing := errors.New("provider down")
	sms := NewSMS(core.SMSConfig{Sender: core.SMSSenderFunc(func(_ context.Context, msg core.SMSMessage) error {
		if msg.To == "" {
			return failing
		}
		got <- msg
		return nil
	})}, tel)

	if err := sms.Send(ctx, core.SMSMessage{Kind: core.SMSSignIn, To: "+14155550101", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if msg := <-got; msg.Code != "123456" {
		t.Errorf("the sender got %+v", msg)
	}
	if err := sms.Send(ctx, core.SMSMessage{Kind: core.SMSSignIn}); !errors.Is(err, failing) {
		t.Errorf("Send returns the sender's error, got %v", err)
	}

	if err := sms.SendAsync(ctx, core.SMSMessage{Kind: core.SMSPasswordReset, To: "+14155550102"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if msg.Kind != core.SMSPasswordReset {
			t.Errorf("the sender got %+v", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the background send did not run")
	}
	if err := sms.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sms.SendAsync(ctx, core.SMSMessage{To: "+14155550102"}); !errors.Is(err, ErrSMSClosed) {
		t.Errorf("SendAsync after Close: %v", err)
	}

	for result, want := range map[string]int{"sent": 1, "error": 1} {
		attrs := behemoth.M{telemetry.AttrKind: string(core.SMSSignIn), telemetry.AttrResult: result}
		if n := rec.Metrics.Count(telemetry.MetricSMSSent, attrs); n != int64(want) {
			t.Errorf("%s sign-in messages counted: %d, want %d", result, n, want)
		}
	}
}
