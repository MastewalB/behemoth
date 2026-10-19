// Package ratelimit enforces rate-limit rules: the catalog rules are declared
// in, the rate limiter that checks them, and the algorithms it counts with,
// implementations of core.Limiter. The rate limiter builds one limiter per
// algorithm over the counter storage it resolves, and picks one per rule by
// the rule's Algorithm.
package ratelimit

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/core"
)

// FixedWindow is the limiter of core.AlgorithmFixedWindow. It counts each
// attempt in a core.AtomicIncrementer (Redis, or the rate_limits table) and
// allows it while the count is at most Limit.Max.
//
// A refused attempt is counted too, so a client that keeps trying does not
// get through earlier; the window still ends when it was going to.
type FixedWindow struct {
	counter core.AtomicIncrementer
	now     func() time.Time
}

// NewFixedWindow returns a fixed-window limiter that counts in counter.
func NewFixedWindow(counter core.AtomicIncrementer) *FixedWindow {
	return &FixedWindow{counter: counter, now: time.Now}
}

// WithClock replaces the clock retry-after is measured with, for tests.
func (l *FixedWindow) WithClock(now func() time.Time) *FixedWindow {
	l.now = now
	return l
}

// Allow implements [core.Limiter]. retryAfter is the time left in the
// window, never more than the window itself: the counter's clock (the
// database's rows are stamped by another application server, Redis by its
// own) may not agree with this one.
func (l *FixedWindow) Allow(ctx context.Context, key string, limit core.Limit) (bool, time.Duration, error) {
	count, resetAt, err := l.counter.Increment(ctx, key, limit.Window)
	if err != nil {
		return false, 0, err
	}
	if count <= limit.Max {
		return true, 0, nil
	}
	retryAfter := min(max(resetAt.Sub(l.now()), 0), limit.Window)
	return false, retryAfter, nil
}

var _ core.Limiter = (*FixedWindow)(nil)
