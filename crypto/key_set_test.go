package crypto_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSource is a KeySource whose keys and error a test sets, and which
// counts its calls.
type fakeSource struct {
	mu    sync.Mutex
	keys  []types.PublishedKey
	err   error
	calls int
}

func (s *fakeSource) Keys(ctx context.Context) ([]types.PublishedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.err != nil {
		return nil, s.err
	}
	return append([]types.PublishedKey(nil), s.keys...), nil
}

func (s *fakeSource) set(err error, kids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err, s.keys = err, nil
	for _, kid := range kids {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		s.keys = append(s.keys, types.PublishedKey{KID: kid, Algorithm: "EdDSA", Key: pub})
	}
}

func (s *fakeSource) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// keyClock is a clock a test moves by hand.
type keyClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *keyClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *keyClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.at = c.at.Add(d) }

func newCachedSet(t *testing.T, opts crypto.CacheOptions, kids ...string) (*crypto.CachedKeySet, *fakeSource, *keyClock) {
	t.Helper()
	src := &fakeSource{}
	src.set(nil, kids...)
	clock := &keyClock{at: time.Now()}
	opts.Now = clock.now
	set, err := crypto.NewCachedKeySet(src, opts)
	require.NoError(t, err)
	return set, src, clock
}

// The keys are fetched by the first call that needs one, and again once
// they are older than the TTL.
func TestCachedKeySetFetchesOnUseAndAfterTTL(t *testing.T) {
	ctx := context.Background()
	set, src, clock := newCachedSet(t, crypto.CacheOptions{}, "k1")
	assert.Zero(t, src.fetches(), "nothing is fetched before a key is needed")

	key, err := set.PublicKey(ctx, "k1")
	require.NoError(t, err)
	assert.Equal(t, "k1", key.KID)
	_, err = set.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, src.fetches())

	clock.add(crypto.DefaultKeySetTTL - time.Second)
	_, err = set.PublicKey(ctx, "k1")
	require.NoError(t, err)
	assert.Equal(t, 1, src.fetches(), "within the TTL")

	src.set(nil, "k2")
	clock.add(time.Second)
	keys, err := set.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, src.fetches(), "after the TTL")
	require.Len(t, keys, 1)
	assert.Equal(t, "k2", keys[0].KID)

	keys[0].KID = "changed"
	again, err := set.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, "k2", again[0].KID, "PublicKeys returns a copy")
}

// A kid the keys lack makes the set fetch them again, at most once per
// RefetchInterval. A kid they still lack is a refused token.
func TestCachedKeySetRefetchesForAnUnknownKID(t *testing.T) {
	ctx := context.Background()
	set, src, clock := newCachedSet(t, crypto.CacheOptions{}, "k1")
	_, err := set.PublicKey(ctx, "k1")
	require.NoError(t, err)

	src.set(nil, "k1", "k2")
	_, err = set.PublicKey(ctx, "k2")
	refused(t, err, behemotherr.ErrorCodeJWTUnknownKey, "within a minute of the last fetch")
	assert.Equal(t, 1, src.fetches())

	clock.add(crypto.DefaultKeyRefetchInterval)
	key, err := set.PublicKey(ctx, "k2")
	require.NoError(t, err, "the issuer's new key")
	assert.Equal(t, "k2", key.KID)
	assert.Equal(t, 2, src.fetches())

	for range 10 {
		_, err = set.PublicKey(ctx, "made-up")
		refused(t, err, behemotherr.ErrorCodeJWTUnknownKey)
	}
	assert.Equal(t, 2, src.fetches(), "made-up kids cause no fetch")
	clock.add(crypto.DefaultKeyRefetchInterval)
	_, err = set.PublicKey(ctx, "made-up")
	refused(t, err, behemotherr.ErrorCodeJWTUnknownKey, "still unknown once fetched again")
	assert.Equal(t, 3, src.fetches())
}

// While the source fails, keys keep being used for MaxStale past their
// TTL, and the source is asked once per RefetchInterval. Then the failure
// shows, as one of the system.
func TestCachedKeySetServesStaleKeysWhileTheSourceFails(t *testing.T) {
	ctx := context.Background()
	opts := crypto.CacheOptions{TTL: 10 * time.Minute, RefetchInterval: time.Minute, MaxStale: 30 * time.Minute}
	set, src, clock := newCachedSet(t, opts, "k1")
	_, err := set.PublicKey(ctx, "k1")
	require.NoError(t, err)

	down := errors.New("the issuer is down")
	src.set(down)
	clock.add(opts.TTL)
	_, err = set.PublicKey(ctx, "k1")
	require.NoError(t, err, "the keys of the last fetch")
	assert.Equal(t, 2, src.fetches())
	_, err = set.PublicKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, src.fetches(), "the next try waits for RefetchInterval")

	clock.add(opts.MaxStale - time.Second)
	_, err = set.PublicKey(ctx, "k1")
	require.NoError(t, err)
	assert.Equal(t, 3, src.fetches())

	clock.add(time.Minute)
	_, err = set.PublicKey(ctx, "k1")
	require.ErrorIs(t, err, down, "past MaxStale")
	assert.False(t, behemotherr.Is(err, behemotherr.CategoryToken))

	src.set(nil, "k1")
	_, err = set.PublicKey(ctx, "k1")
	require.ErrorIs(t, err, down, "within RefetchInterval of the failed fetch")
	clock.add(time.Minute)
	_, err = set.PublicKey(ctx, "k1")
	assert.NoError(t, err, "the source is back")

	strict, src2, clock2 := newCachedSet(t, crypto.CacheOptions{MaxStale: -1}, "k1")
	_, err = strict.PublicKey(ctx, "k1")
	require.NoError(t, err)
	src2.set(down)
	clock2.add(crypto.DefaultKeySetTTL)
	_, err = strict.PublicKey(ctx, "k1")
	assert.ErrorIs(t, err, down, "a negative MaxStale serves no stale key")
}

// A first fetch that fails is not repeated before RefetchInterval, so a
// source that is down is not asked by every request.
func TestCachedKeySetBacksOffAfterAFailure(t *testing.T) {
	ctx := context.Background()
	set, src, clock := newCachedSet(t, crypto.CacheOptions{})
	down := errors.New("the issuer is down")
	src.set(down)
	for range 5 {
		_, err := set.PublicKey(ctx, "k1")
		require.ErrorIs(t, err, down)
	}
	assert.Equal(t, 1, src.fetches())

	src.set(nil, "k1")
	clock.add(crypto.DefaultKeyRefetchInterval)
	_, err := set.PublicKey(ctx, "k1")
	assert.NoError(t, err)
	assert.Equal(t, 2, src.fetches())
}

// A caller whose context ends does not count as a failure of the source:
// the next call fetches at once.
func TestCachedKeySetIgnoresTheCallersCancellation(t *testing.T) {
	set, src, _ := newCachedSet(t, crypto.CacheOptions{}, "k1")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := set.PublicKey(canceled, "k1")
	require.ErrorIs(t, err, context.Canceled)

	_, err = set.PublicKey(context.Background(), "k1")
	assert.NoError(t, err)
	assert.Equal(t, 2, src.fetches())
}

// A fetch for an unknown kid that fails is a failure of the system. The
// keys the set has still work.
func TestCachedKeySetForcedFetchFailure(t *testing.T) {
	ctx := context.Background()
	set, src, clock := newCachedSet(t, crypto.CacheOptions{}, "k1")
	_, err := set.PublicKey(ctx, "k1")
	require.NoError(t, err)

	down := errors.New("the issuer is down")
	src.set(down)
	clock.add(crypto.DefaultKeyRefetchInterval)
	_, err = set.PublicKey(ctx, "k2")
	require.ErrorIs(t, err, down)
	assert.False(t, behemotherr.Is(err, behemotherr.CategoryToken), "not a refused token")
	_, err = set.PublicKey(ctx, "k3")
	require.ErrorIs(t, err, down, "within RefetchInterval of the failure: a new kid can't be told from a made-up one")
	assert.Equal(t, 2, src.fetches())
	_, err = set.PublicKey(ctx, "k1")
	assert.NoError(t, err)

	// Stale keys after a failed fetch at the end of the TTL: the same.
	stale, src2, clock2 := newCachedSet(t, crypto.CacheOptions{}, "k1")
	_, err = stale.PublicKey(ctx, "k1")
	require.NoError(t, err)
	src2.set(down)
	clock2.add(crypto.DefaultKeySetTTL)
	_, err = stale.PublicKey(ctx, "k1")
	require.NoError(t, err, "stale keys")
	_, err = stale.PublicKey(ctx, "k2")
	require.ErrorIs(t, err, down)
	assert.False(t, behemotherr.Is(err, behemotherr.CategoryToken))
}

// Concurrent calls share the fetches.
func TestCachedKeySetIsSafeForConcurrentUse(t *testing.T) {
	set, src, clock := newCachedSet(t, crypto.CacheOptions{}, "k1")
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if i%10 == 0 {
				clock.add(time.Second)
			}
			_, err := set.PublicKey(context.Background(), "k1")
			assert.NoError(t, err)
			_, err = set.PublicKeys(context.Background())
			assert.NoError(t, err)
		})
	}
	wg.Wait()
	assert.Equal(t, 1, src.fetches())
}

// A set without a source, or with a negative duration, can't work.
func TestNewCachedKeySetOptions(t *testing.T) {
	_, err := crypto.NewCachedKeySet(nil, crypto.CacheOptions{})
	assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
	for _, opts := range []crypto.CacheOptions{{TTL: -time.Second}, {RefetchInterval: -time.Second}} {
		_, err := crypto.NewCachedKeySet(&fakeSource{}, opts)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%+v: %v", opts, err)
	}
}
