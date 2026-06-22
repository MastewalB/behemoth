package models

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
)

func TestRedisStorage(t *testing.T) {
	ctx := context.Background()
	client, cleanup := testutils.SetupRedisClient(t, ctx)
	defer cleanup()

	kvAdapter := adapters.NewRedisAdapter(client)
	suite := NewKeyValueStorageTestSuite(kvAdapter)
	suite.RunAllTests(t)
}
