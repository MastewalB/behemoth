package types

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
)

type AuthContext struct {
	DB Database

	KV KeyValueStorage

	InternalAdapter adapters.InternalAdapter

	User behemoth.User

	PasswordOptions PasswordOptions

	SessionOptions SessionConfig

	Validator Validator
}

