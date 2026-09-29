package crypto

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/types"
)

type PollingWatcher struct {
	types.SecretSource
	interval time.Duration
}

func NewPollingWatcher(source types.SecretSource, interval time.Duration) *PollingWatcher {
	return &PollingWatcher{SecretSource: source, interval: interval}
}

func (p *PollingWatcher) Watch(ctx context.Context, onUpdate func(map[int]string, int)) error {

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
var _ types.WatchableSecretSource = (*PollingWatcher)(nil)
