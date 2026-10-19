package crypto

import (
	"context"
	"time"
)

type PollingWatcher struct {
	SecretSource
	interval time.Duration
}

func NewPollingWatcher(source SecretSource, interval time.Duration) *PollingWatcher {
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
var _ WatchableSecretSource = (*PollingWatcher)(nil)
