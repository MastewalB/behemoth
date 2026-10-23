module github.com/MastewalB/behemoth/storage/adapters/sqlite

go 1.26.0

require (
	github.com/MastewalB/behemoth v0.0.0
	github.com/mattn/go-sqlite3 v1.14.52
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/MastewalB/behemoth => ../../../
