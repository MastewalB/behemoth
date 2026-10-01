package ratelimit

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/types"
)

// IdentityLimiter allows every attempt and records nothing: the limiter to
// use until a real algorithm backs a rule.
type IdentityLimiter struct{}

func (IdentityLimiter) Allow(context.Context, string, types.Limit) (bool, time.Duration, error) {
	return true, 0, nil
}

var _ types.Limiter = IdentityLimiter{}
