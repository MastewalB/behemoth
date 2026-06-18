package adapters

import (
	"context"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/redis/go-redis/v9"
)

type RedisAdapter struct {
	redisClient *redis.Client
}

func NewRedisAdapter(client *redis.Client) *RedisAdapter {
	return &RedisAdapter{redisClient: client}
}

func (rkv *RedisAdapter) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", behemotherr.ErrEmptyKey
	}

	value, err := rkv.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", WrapWithCaller(err, EntityKVPair, handleRedisError)
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
		return behemotherr.ErrEmptyKey
	}
	err := rkv.redisClient.Set(ctx, key, value, time.Duration(ttl*int(time.Second))).Err()

	return err
}

func (rkv *RedisAdapter) Delete(ctx context.Context, key string) error {
	if key == "" {
		return behemotherr.ErrEmptyKey
	}

	err := rkv.redisClient.Del(ctx, key).Err()
	if err != nil {
		return err
	}
	
	return nil
}

const EntityKVPair string = "Key-Value Pair"

func handleRedisError(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch err {
	case redis.Nil:
		return behemotherr.NewKeyNotFound(op, err)
		// case redis.

	case behemotherr.ErrEmptyKey:
		return behemotherr.NewEmptyKey(op, err)
	}
	return behemotherr.NewDatabaseError(op, err)
}
