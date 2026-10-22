package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/core"
)

// counter is an AtomicIncrementer that counts in memory and reports the end
// of the window it is told to.
type counter struct {
	counts  map[string]int64
	resetAt time.Time
	err     error
	ttl     time.Duration
}

func (c *counter) Increment(_ context.Context, key string, ttl time.Duration) (int64, time.Time, error) {
	if c.err != nil {
		return 0, time.Time{}, c.err
	}
	c.counts[key]++
	c.ttl = ttl
	return c.counts[key], c.resetAt, nil
}

// The fixed window allows Max attempts per key and refuses the rest with the
// time left in the window, measured against the end the counter reports.
// Only the attempt counted Max+1 is the window's first refusal.
func TestFixedWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 12, 0, 50, 0, time.UTC)
	limit := core.Limit{Max: 3, Window: time.Minute}
	c := &counter{counts: map[string]int64{}, resetAt: now.Add(10 * time.Second)}
	l := NewFixedWindow(c).WithClock(func() time.Time { return now })

	for attempt := 1; attempt <= 3; attempt++ {
		d, err := l.Allow(ctx, "signin:203.0.113.7", limit)
		if err != nil || d != (core.LimitDecision{Allowed: true}) {
			t.Fatalf("attempt %d = (%+v, %v), want it allowed", attempt, d, err)
		}
	}
	if c.ttl != time.Minute {
		t.Errorf("the counter was given a window of %v, want the limit's", c.ttl)
	}
	d, err := l.Allow(ctx, "signin:203.0.113.7", limit)
	if err != nil || d.Allowed {
		t.Fatalf("attempt 4 = (%+v, %v), want it refused", d, err)
	}
	if !d.FirstRefusal {
		t.Error("attempt 4 is the window's first refusal")
	}
	if d.RetryAfter != 10*time.Second {
		t.Errorf("retry after = %v, want the 10s left in the window, not the whole minute", d.RetryAfter)
	}
	if c.counts["signin:203.0.113.7"] != 4 {
		t.Errorf("the refused attempt was not counted: %d", c.counts["signin:203.0.113.7"])
	}
	if d, _ := l.Allow(ctx, "signin:198.51.100.9", limit); !d.Allowed {
		t.Error("another key has its own count")
	}

	// A counter whose clock disagrees can't push the hint outside the window.
	// These refusals follow the first.
	c.resetAt = now.Add(time.Hour)
	if d, _ := l.Allow(ctx, "signin:203.0.113.7", limit); d.RetryAfter != time.Minute || d.FirstRefusal {
		t.Errorf("attempt 5 = %+v, want the hint capped at the window and not a first refusal", d)
	}
	c.resetAt = now.Add(-time.Second)
	if d, _ := l.Allow(ctx, "signin:203.0.113.7", limit); d.Allowed || d.RetryAfter != 0 || d.FirstRefusal {
		t.Errorf("a window that ended on the counter's side = %+v, want refused with no wait", d)
	}

	// The counter's failure is returned for the rate limiter's failure mode.
	c.err = errors.New("redis down")
	if d, err := l.Allow(ctx, "signin:203.0.113.7", limit); d.Allowed || !errors.Is(err, c.err) {
		t.Errorf("a failing counter = (%+v, %v), want its error", d, err)
	}
}
