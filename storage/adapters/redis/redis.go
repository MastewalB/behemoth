// Package redis provides RedisAdapter, a behemoth.KeyValueStorage backed by
// Redis. It lives in its own module, like the database adapters, so the core
// module does not depend on go-redis.
package redis

import (
	"context"
	"fmt"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/redis/go-redis/v9"
)

// RedisAdapter implements behemoth.KeyValueStorage on a Redis client.
//
// It also counts for the rate limiter (Increment, the
// types.AtomicIncrementer capability), so with Redis configured rate-limit
// counters are kept there and not in the database.
type RedisAdapter struct {
	redisClient *redis.Client
}

// NewRedisAdapter wraps client.
func NewRedisAdapter(client *redis.Client) *RedisAdapter {
	return &RedisAdapter{redisClient: client}
}

func (rkv *RedisAdapter) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", behemotherr.NewEmptyKey("Get", nil)
	}

	value, err := rkv.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", adapters.WrapWithCaller(err, EntityKVPair, handleRedisError)
	}
	return value, nil
}

func (rkv *RedisAdapter) Set(
	ctx context.Context,
	key string,
	value string,
	ttl int,
) error {
	if key == "" {
		return behemotherr.NewEmptyKey(adapters.OpSet, nil)
	}
	err := rkv.redisClient.Set(ctx, key, value, time.Duration(ttl*int(time.Second))).Err()

	return err
}

func (rkv *RedisAdapter) Delete(ctx context.Context, key string) error {
	if key == "" {
		return behemotherr.NewEmptyKey(adapters.OpDelete, nil)
	}

	err := rkv.redisClient.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	return nil
}

// rateLimitPrefix keeps counters apart from the other keys behemoth stores
// (session cache entries, tokens).
const rateLimitPrefix = "ratelimit:"

// incrementScript counts one attempt and returns the count and the key's
// remaining lifetime in milliseconds. It runs as one script so the expiry is
// set with the first increment: INCR followed by a separate EXPIRE would
// leave a counter that never resets if the process stopped in between. A
// counter found without an expiry is given one for the same reason.
var incrementScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if count == 1 or ttl < 0 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
	ttl = tonumber(ARGV[1])
end
return {count, ttl}
`)

// Increment implements the rate limiter's counter (types.AtomicIncrementer):
// it counts one attempt against key and returns the count in the current
// window and when the window ends. The first attempt opens a window of ttl,
// and Redis removes the key when it has passed.
//
// The end of the window is this process's clock plus the key's remaining
// lifetime, so it does not depend on the clocks of Redis and the application
// agreeing.
func (rkv *RedisAdapter) Increment(ctx context.Context, key string, ttl time.Duration) (int64, time.Time, error) {
	if key == "" {
		return 0, time.Time{}, behemotherr.NewEmptyKey("Increment", nil)
	}
	if ttl < time.Millisecond {
		return 0, time.Time{}, behemotherr.NewValidationError("Increment", EntityKVPair, fmt.Errorf("the window must be at least a millisecond, got %s", ttl))
	}
	res, err := incrementScript.Run(ctx, rkv.redisClient, []string{rateLimitPrefix + key}, ttl.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, time.Time{}, adapters.WrapWithCaller(err, EntityKVPair, handleRedisError)
	}
	if len(res) != 2 {
		return 0, time.Time{}, fmt.Errorf("redis: the increment script returned %d values, want 2", len(res))
	}
	return res[0], time.Now().Add(time.Duration(res[1]) * time.Millisecond), nil
}

// EntityKVPair is the entity name reported in errors about a key.
const EntityKVPair string = "Key-Value Pair"

func handleRedisError(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch err {
	case redis.Nil:
		return behemotherr.NewKeyNotFound(op, err)
		// case redis.

		// case behemotherr.ErrEmptyKey:
		// 	return behemotherr.NewEmptyKey(op, err)
	}
	return behemotherr.NewDatabaseError(op, err)
}
