package crypto

import (
	"context"

	"github.com/MastewalB/behemoth/types"
)

// StaticSecretSource serves a fixed set of hex-encoded secrets, keyed by
// version — e.g. read from environment variables at startup. It does not
// support hot rotation: rotating a secret requires a restart.
type StaticSecretSource struct {
	Secrets map[int]string
	Current int
}

func (s StaticSecretSource) Load(context.Context) (map[int]string, int, error) {
	return s.Secrets, s.Current, nil
}

var _ types.SecretSource = StaticSecretSource{}
