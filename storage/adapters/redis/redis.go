// Package redis provides RedisAdapter, a behemoth.KeyValueStorage backed by
// Redis. It lives in its own module, like the database adapters, so the core
// module does not depend on go-redis.
package redis

import (
	"context"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/redis/go-redis/v9"
)

// RedisAdapter implements behemoth.KeyValueStorage on a Redis client.
//
// It has no Increment method, so the rate limiter does not use it for
// counting and falls back to the database.
type RedisAdapter struct {
	redisClient *redis.Client
}

// NewRedisAdapter wraps client.
func NewRedisAdapter(client *redis.Client) *RedisAdapter {
	return &RedisAdapter{redisClient: client}
}

func (rkv *RedisAdapter) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", behemotherr.NewEmptyKey("Get", nil)
	}

	value, err := rkv.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", adapters.WrapWithCaller(err, EntityKVPair, handleRedisError)
	}
	return value, nil
}

func (rkv *RedisAdapter) Set(
	ctx context.Context,
	key string,
	value string,
	ttl int,
) error {
	if key == "" {
		return behemotherr.NewEmptyKey(adapters.OpSet, nil)
	}
	err := rkv.redisClient.Set(ctx, key, value, time.Duration(ttl*int(time.Second))).Err()

	return err
}

func (rkv *RedisAdapter) Delete(ctx context.Context, key string) error {
	if key == "" {
		return behemotherr.NewEmptyKey(adapters.OpDelete, nil)
	}

	err := rkv.redisClient.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	return nil
}

// EntityKVPair is the entity name reported in errors about a key.
const EntityKVPair string = "Key-Value Pair"

func handleRedisError(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch err {
	case redis.Nil:
		return behemotherr.NewKeyNotFound(op, err)
		// case redis.

		// case behemotherr.ErrEmptyKey:
		// 	return behemotherr.NewEmptyKey(op, err)
	}
	return behemotherr.NewDatabaseError(op, err)
}
