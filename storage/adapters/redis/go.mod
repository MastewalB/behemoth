module github.com/MastewalB/behemoth/storage/adapters/redis

go 1.26.0

require (
	github.com/MastewalB/behemoth v0.0.0
	github.com/redis/go-redis/v9 v9.20.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
)

replace github.com/MastewalB/behemoth => ../../../
