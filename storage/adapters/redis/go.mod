module github.com/go-behemoth/behemoth/storage/adapters/redis

go 1.26.0

require (
	github.com/go-behemoth/behemoth v0.0.0
	github.com/redis/go-redis/v9 v9.20.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
)

replace github.com/go-behemoth/behemoth => ../../../
