package crypto

import (
	"context"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth/errs"
)

// PollingWatcher makes a SecretSource that can't report a change watchable:
// it loads the source again every interval. A key manager built over it
// picks up a rotation within one interval.
type PollingWatcher struct {
	SecretSource
	interval time.Duration
}

// NewPollingWatcher returns a watcher that loads source every interval.
func NewPollingWatcher(source SecretSource, interval time.Duration) *PollingWatcher {
	return &PollingWatcher{SecretSource: source, interval: interval}
}

// Watch starts polling in a goroutine that ends when ctx is done. It calls
// onUpdate with the result of every load, changed or not; the key manager
// ignores an update that changes nothing. A load that fails is skipped and
// tried again at the next tick.
//
// An interval that is not positive is a configuration error, and nothing is
// started.
func (p *PollingWatcher) Watch(ctx context.Context, onUpdate func(map[int]string, int)) error {
	if p.interval <= 0 {
		return errs.NewConfigurationError("PollingWatcher.Watch", fmt.Sprintf("the interval must be positive, not %s", p.interval), nil)
	}

	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				secrets, current, err := p.Load(ctx)
				if err != nil {
					continue
				}
				onUpdate(secrets, current)
			}
		}
	}()
	return nil
}

// A compile-time check to ensure that PollingWatcher implements WatchableSecretSource
var _ WatchableSecretSource = (*PollingWatcher)(nil)
