package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
)

// rateLimitAttempts bounds how often IncrementRateLimit retries after losing
// a race for a key. Every lost race is another caller's successful
// increment, so a caller only runs out against that many concurrent winners.
const rateLimitAttempts = 32

// IncrementRateLimit counts one attempt against key and returns the count in
// the current window. The first attempt opens a window of ttl; once it has
// passed, the next attempt opens a new one, starting again at 1.
//
// It is atomic without a transaction or a database-specific upsert: each
// write is guarded on the count that was read, and UpdateOne re-checks its
// expression in the write itself (the behemoth.Database convention), so of
// several concurrent calls reading the same count one writes and the others
// read again. No two calls return the same count for one window.
func (s *Store) IncrementRateLimit(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	byKey := clause.Condition{Field: models.RateLimitKey, Operator: clause.OpEqual, Value: key}
	for range rateLimitAttempts {
		now := s.now()
		found, err := s.db.FindOne(ctx, &models.RateLimit{}, clause.Expression{Conditions: []clause.Condition{byKey}})
		if behemotherr.IsNotFound(err) {
			err = s.db.Create(ctx, &models.RateLimit{Key: key, Count: 1, ExpiresAt: now.Add(ttl)})
			if behemotherr.IsDuplicateKey(err) {
				continue // another call created it first
			}
			return 1, err
		}
		if err != nil {
			return 0, err
		}
		current, ok := found.(*models.RateLimit)
		if !ok {
			return 0, fmt.Errorf("store: unexpected %T in rate_limits", found)
		}

		unchanged := clause.Condition{Field: models.RateLimitCount, Operator: clause.OpEqual, Value: current.Count}
		next, guard, updates := current.Count+1, []clause.Condition{byKey, unchanged}, behemoth.M{}
		if !current.ExpiresAt.After(now) {
			// The window has passed: start a new one, unless another call
			// already did (its expires_at is in the future again).
			next = 1
			guard = append(guard, clause.Condition{Field: models.RateLimitExpiresAt, Operator: clause.OpLessEq, Value: now})
			updates[models.RateLimitExpiresAt] = now.Add(ttl)
		}
		updates[models.RateLimitCount] = next

		err = s.db.UpdateOne(ctx, &models.RateLimit{}, clause.Expression{Conditions: guard, Logic: clause.OpAnd}, updates)
		if behemotherr.IsNotFound(err) {
			continue // another call wrote first
		}
		if err != nil {
			return 0, err
		}
		return next, nil
	}
	return 0, fmt.Errorf("store: rate limit %q still contended after %d attempts", key, rateLimitAttempts)
}

// PurgeExpiredRateLimits deletes the counters whose window has passed. A
// counter is reused when its key is seen again, so this only reclaims keys
// that never come back.
func (s *Store) PurgeExpiredRateLimits(ctx context.Context) error {
	return s.db.DeleteMany(ctx, &models.RateLimit{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.RateLimitExpiresAt, Operator: clause.OpLessEq, Value: s.now()},
	}})
}
