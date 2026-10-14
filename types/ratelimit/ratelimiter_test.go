package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/types"
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
func TestFixedWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 12, 0, 50, 0, time.UTC)
	limit := types.Limit{Max: 3, Window: time.Minute}
	c := &counter{counts: map[string]int64{}, resetAt: now.Add(10 * time.Second)}
	l := NewFixedWindow(c).WithClock(func() time.Time { return now })

	for attempt := 1; attempt <= 3; attempt++ {
		allowed, retryAfter, err := l.Allow(ctx, "signin:203.0.113.7", limit)
		if err != nil || !allowed || retryAfter != 0 {
			t.Fatalf("attempt %d = (%v, %v, %v), want it allowed", attempt, allowed, retryAfter, err)
		}
	}
	if c.ttl != time.Minute {
		t.Errorf("the counter was given a window of %v, want the limit's", c.ttl)
	}
	allowed, retryAfter, err := l.Allow(ctx, "signin:203.0.113.7", limit)
	if err != nil || allowed {
		t.Fatalf("attempt 4 = (%v, %v), want it refused", allowed, err)
	}
	if retryAfter != 10*time.Second {
		t.Errorf("retry after = %v, want the 10s left in the window, not the whole minute", retryAfter)
	}
	if c.counts["signin:203.0.113.7"] != 4 {
		t.Errorf("the refused attempt was not counted: %d", c.counts["signin:203.0.113.7"])
	}
	if allowed, _, _ := l.Allow(ctx, "signin:198.51.100.9", limit); !allowed {
		t.Error("another key has its own count")
	}

	// A counter whose clock disagrees can't push the hint outside the window.
	c.resetAt = now.Add(time.Hour)
	if _, retryAfter, _ := l.Allow(ctx, "signin:203.0.113.7", limit); retryAfter != time.Minute {
		t.Errorf("retry after = %v, want it capped at the window", retryAfter)
	}
	c.resetAt = now.Add(-time.Second)
	if allowed, retryAfter, _ := l.Allow(ctx, "signin:203.0.113.7", limit); allowed || retryAfter != 0 {
		t.Errorf("a window that ended on the counter's side = (%v, %v), want refused with no wait", allowed, retryAfter)
	}

	// The counter's failure is returned for the rate limiter's failure mode.
	c.err = errors.New("redis down")
	if allowed, _, err := l.Allow(ctx, "signin:203.0.113.7", limit); allowed || !errors.Is(err, c.err) {
		t.Errorf("a failing counter = (%v, %v), want its error", allowed, err)
	}
}
