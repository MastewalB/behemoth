package models

import (
	"context"
	"testing"

	redisAdapter "github.com/MastewalB/behemoth/storage/adapters/redis"
	"github.com/MastewalB/behemoth/tests/testutils"
)

func TestRedisStorage(t *testing.T) {
	ctx := context.Background()
	client, cleanup := testutils.SetupRedisClient(t, ctx)
	defer cleanup()

	kvAdapter := redisAdapter.NewRedisAdapter(client)
	suite := NewKeyValueStorageTestSuite(kvAdapter)
	suite.RunAllTests(t)
}
