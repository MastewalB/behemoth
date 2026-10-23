package crypto_test

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/telemetry"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pollInterval is short, so that a test sees many polls quickly. The tests
// wait for polls to happen, and never for a fixed number of them.
const pollInterval = time.Millisecond

// pollSource is a SecretSource whose test changes what it loads, or makes
// it fail. It counts its loads.
type pollSource struct {
	mu      sync.Mutex
	secrets map[int]string
	current int
	err     error
	loads   int
}

func newPollSource(secrets map[int]string, current int) *pollSource {
	return &pollSource{secrets: secrets, current: current}
}

func (s *pollSource) Load(context.Context) (map[int]string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.err != nil {
		return nil, 0, s.err
	}
	return maps.Clone(s.secrets), s.current, nil
}

func (s *pollSource) set(secrets map[int]string, current int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets, s.current, s.err = secrets, current, err
}

func (s *pollSource) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

// waitForLoads waits until src has been loaded n more times.
func (s *pollSource) waitForLoads(t *testing.T, n int) {
	t.Helper()
	target := s.loadCount() + n
	require.Eventually(t, func() bool { return s.loadCount() >= target }, 5*time.Second, pollInterval)
}

// update is one call of a watcher's callback.
type update struct {
	secrets map[int]string
	current int
}

// updates records the calls of a watcher's callback.
type updates struct {
	mu  sync.Mutex
	got []update
}

func (u *updates) record(secrets map[int]string, current int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.got = append(u.got, update{secrets, current})
}

func (u *updates) all() []update {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]update(nil), u.got...)
}

// The watcher loads its source every interval and reports each load, so a
// change reaches the callback within an interval.
func TestPollingWatcherReportsEachLoad(t *testing.T) {
	src := newPollSource(map[int]string{1: secretV1}, 1)
	var got updates
	require.NoError(t, crypto.NewPollingWatcher(src, pollInterval).Watch(t.Context(), got.record))

	require.Eventually(t, func() bool { return len(got.all()) >= 3 }, 5*time.Second, pollInterval)
	for _, u := range got.all() {
		assert.Equal(t, update{map[int]string{1: secretV1}, 1}, u)
	}

	src.set(map[int]string{1: secretV1, 2: secretV2}, 2, nil)
	require.Eventually(t, func() bool {
		all := got.all()
		return all[len(all)-1].current == 2
	}, 5*time.Second, pollInterval)
	all := got.all()
	assert.Equal(t, map[int]string{1: secretV1, 2: secretV2}, all[len(all)-1].secrets)
}

// A load that fails is not reported, and polling goes on: the next load
// that works is.
func TestPollingWatcherSkipsAFailedLoad(t *testing.T) {
	src := newPollSource(nil, 0)
	src.set(nil, 0, errors.New("vault sealed"))
	var got updates
	require.NoError(t, crypto.NewPollingWatcher(src, pollInterval).Watch(t.Context(), got.record))

	src.waitForLoads(t, 3)
	assert.Empty(t, got.all(), "a failed load reaches nobody")

	src.set(map[int]string{1: secretV1}, 1, nil)
	require.Eventually(t, func() bool { return len(got.all()) > 0 }, 5*time.Second, pollInterval)
	assert.Equal(t, update{map[int]string{1: secretV1}, 1}, got.all()[0])
}

// The goroutine Watch starts ends when its context is done: the source is
// no longer loaded.
func TestPollingWatcherStopsWithItsContext(t *testing.T) {
	src := newPollSource(map[int]string{1: secretV1}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var got updates
	require.NoError(t, crypto.NewPollingWatcher(src, pollInterval).Watch(ctx, got.record))
	src.waitForLoads(t, 2)

	cancel()
	time.Sleep(20 * pollInterval) // a tick already due may still load once
	stopped := src.loadCount()
	time.Sleep(50 * pollInterval)
	assert.Equal(t, stopped, src.loadCount(), "no load after the context is done")
}

// An interval that is not positive is a configuration error, and nothing
// starts. A ticker would panic on it, in a goroutine, which no caller could
// recover.
func TestPollingWatcherRefusesAnIntervalThatIsNotPositive(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		src := newPollSource(map[int]string{1: secretV1}, 1)
		err := crypto.NewPollingWatcher(src, interval).Watch(t.Context(), func(map[int]string, int) {})
		assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "interval %s: %v", interval, err)
		time.Sleep(10 * pollInterval)
		assert.Zero(t, src.loadCount(), "interval %s: nothing polls", interval)
	}
}

// A key manager over a polling watcher picks up a rotation within an
// interval, and keeps the old version. A poll that finds the same secrets
// is not a rotation: only the poll that found the new version is logged and
// audited.
func TestKeyManagerRotatesThroughAPollingWatcher(t *testing.T) {
	src := newPollSource(map[int]string{1: secretV1}, 1)
	tel, rec := telemetrytest.New()
	km, err := crypto.NewDefaultKeyManager(t.Context(), crypto.KeyManagerConfig{}, crypto.NewPollingWatcher(src, pollInterval), tel)
	require.NoError(t, err)
	old, err := km.GetByVersion(crypto.KeyPurposeTokenHash, 1)
	require.NoError(t, err)

	src.waitForLoads(t, 5)
	assert.Empty(t, rec.Audit.OfType(telemetry.AuditSecretRotated), "polls that found nothing new")
	assert.Equal(t, 1, km.CurrentVersion())

	src.set(map[int]string{1: secretV1, 2: secretV2}, 2, nil)
	require.Eventually(t, func() bool { return km.CurrentVersion() == 2 }, 5*time.Second, pollInterval)
	src.waitForLoads(t, 5)

	rotated := rec.Audit.OfType(telemetry.AuditSecretRotated)
	require.Len(t, rotated, 1, "one rotation, however many polls found it")
	assert.Equal(t, 2, rotated[0].Metadata["current_version"])
	applied := 0
	for _, line := range rec.Logger.Entries() {
		if line.Message == "secret rotation applied" {
			applied++
		}
	}
	assert.Equal(t, 1, applied)

	key, err := km.GetByVersion(crypto.KeyPurposeTokenHash, 1)
	require.NoError(t, err)
	assert.Equal(t, old, key, "the old version still verifies what it signed")
	assert.Equal(t, []int{1, 2}, km.Versions())
}
