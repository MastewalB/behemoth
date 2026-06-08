package models

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/storage/adapters"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestRedisStorage(t *testing.T) {
	client, cleanup := SetupRedisClient(t)
	defer cleanup()

	kvAdapter := adapters.NewRedisAdapter(client)
	suite := NewKeyValueStorageTestSuite(kvAdapter)
	suite.RunAllTests(t)
}

func SetupRedisClient(t *testing.T) (*goredis.Client, func()) {
	ctx := context.Background()

	redisContainer, err := redis.Run(ctx, "redis:7.4-alpine")
	assert.NoError(t, err)
	cleanup := func() { _ = redisContainer.Terminate(ctx) }

	connStr, err := redisContainer.ConnectionString(ctx)
	assert.NoError(t, err)

	opts, err := goredis.ParseURL(connStr)
	assert.NoError(t, err)

	client := goredis.NewClient(opts)

	return client, cleanup
}
