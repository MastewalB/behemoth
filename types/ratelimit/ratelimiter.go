// Package ratelimit holds the rate-limiting algorithms: implementations of
// types.Limiter. Boot builds them, once it knows where counters are kept, and
// DefaultRateLimiter picks one per rule by the rule's Algorithm.
package ratelimit

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/types"
)

// FixedWindow is the limiter of types.AlgorithmFixedWindow. It counts each
// attempt in a types.AtomicIncrementer (Redis, or the rate_limits table) and
// allows it while the count is at most Limit.Max.
//
// A refused attempt is counted too, so a client that keeps trying does not
// get through earlier; the window still ends when it was going to.
type FixedWindow struct {
	counter types.AtomicIncrementer
	now     func() time.Time
}

// NewFixedWindow returns a fixed-window limiter that counts in counter.
func NewFixedWindow(counter types.AtomicIncrementer) *FixedWindow {
	return &FixedWindow{counter: counter, now: time.Now}
}

// WithClock replaces the clock retry-after is measured with, for tests.
func (l *FixedWindow) WithClock(now func() time.Time) *FixedWindow {
	l.now = now
	return l
}

// Allow implements [types.Limiter]. retryAfter is the time left in the
// window, never more than the window itself: the counter's clock (the
// database's rows are stamped by another application server, Redis by its
// own) may not agree with this one.
func (l *FixedWindow) Allow(ctx context.Context, key string, limit types.Limit) (bool, time.Duration, error) {
	count, resetAt, err := l.counter.Increment(ctx, key, limit.Window)
	if err != nil {
		return false, 0, err
	}
	if count <= limit.Max {
		return true, 0, nil
	}
	retryAfter := resetAt.Sub(l.now())
	if retryAfter < 0 {
		retryAfter = 0
	}
	if retryAfter > limit.Window {
		retryAfter = limit.Window
	}
	return false, retryAfter, nil
}

var _ types.Limiter = (*FixedWindow)(nil)
