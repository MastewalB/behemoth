package models

import (
	"context"
	"sync"
	"testing"
	"time"

	redisAdapter "github.com/MastewalB/behemoth/storage/adapters/redis"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Boot finds the Redis adapter's counter through this interface.
var _ types.AtomicIncrementer = (*redisAdapter.RedisAdapter)(nil)

func TestRedisStorage(t *testing.T) {
	ctx := context.Background()
	client, cleanup := testutils.SetupRedisClient(t, ctx)
	defer cleanup()

	kvAdapter := redisAdapter.NewRedisAdapter(client)
	suite := NewKeyValueStorageTestSuite(kvAdapter)
	suite.RunAllTests(t)
}

// The Redis adapter counts for the rate limiter: concurrent attempts each get
// their own count, the window's end is the key's expiry, and the count starts
// again when Redis has dropped the key.
func TestRedisIncrement(t *testing.T) {
	ctx := context.Background()
	client, cleanup := testutils.SetupRedisClient(t, ctx)
	defer cleanup()
	kv := redisAdapter.NewRedisAdapter(client)

	const calls = 20
	start := time.Now()
	counts := make(chan int64, calls)
	var wg sync.WaitGroup
	for range calls {
		wg.Go(func() {
			n, resetAt, err := kv.Increment(ctx, "signin:1.2.3.4", time.Minute)
			assert.NoError(t, err)
			assert.WithinDuration(t, start.Add(time.Minute), resetAt, 5*time.Second, "the end of the window the first attempt opened")
			counts <- n
		})
	}
	wg.Wait()
	close(counts)
	seen := map[int64]bool{}
	for n := range counts {
		seen[n] = true
	}
	assert.Len(t, seen, calls, "concurrent attempts each get their own count")
	assert.True(t, seen[1] && seen[calls], "counts run 1..%d: %v", calls, seen)

	other, _, err := kv.Increment(ctx, "signin:5.6.7.8", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, 1, other, "keys count independently")

	// The counter lives under its own prefix, with an expiry from the start.
	ttl, err := client.PTTL(ctx, "ratelimit:signin:1.2.3.4").Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, 50*time.Second)
	assert.LessOrEqual(t, ttl, time.Minute)
	_, err = kv.Get(ctx, "signin:1.2.3.4")
	assert.Error(t, err, "the plain key is not used")

	// A short window: the second attempt reports the time left, not a new
	// window, and the count starts again once the key has expired.
	n, first, err := kv.Increment(ctx, "short", 300*time.Millisecond)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	time.Sleep(100 * time.Millisecond)
	n, second, err := kv.Increment(ctx, "short", 300*time.Millisecond)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	assert.WithinDuration(t, first, second, 50*time.Millisecond, "the window's end does not move with later attempts")
	time.Sleep(350 * time.Millisecond)
	n, _, err = kv.Increment(ctx, "short", 300*time.Millisecond)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "a passed window starts again")

	// A counter that somehow has no expiry is given one, or it would never reset.
	require.NoError(t, client.Set(ctx, "ratelimit:stuck", "7", 0).Err())
	n, resetAt, err := kv.Increment(ctx, "stuck", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, 8, n)
	assert.WithinDuration(t, time.Now().Add(time.Minute), resetAt, 5*time.Second)

	_, _, err = kv.Increment(ctx, "", time.Minute)
	assert.Error(t, err, "an empty key")
	_, _, err = kv.Increment(ctx, "k", 0)
	assert.Error(t, err, "a window of no length")
}
