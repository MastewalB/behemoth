package types

import (
	"context"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

type InternalAdapter interface {
	CreateUser(ctx context.Context, modelType behemoth.Model, user behemoth.M) (behemoth.User, error)
	FindUserByID(ctx context.Context, model behemoth.Model, id any) (behemoth.User, error)
	FindUserByEmail(ctx context.Context, model behemoth.Model, email string) (behemoth.User, error)
	UpdateUser(ctx context.Context, model behemoth.Model, updates behemoth.M) (behemoth.User, error)
	CreateSession(ctx context.Context, sessionData behemoth.M) (*models.Session, error)
	FindSession(ctx context.Context, tokenStr string) (*models.Session, error)
	DeleteSession(ctx context.Context, tokenStr string) error
}

type AuthContext struct {
	DB              behemoth.Database
	KV              behemoth.KeyValueStorage
	InternalAdapter InternalAdapter
	Crypto          Crypto
	User            behemoth.User
	PasswordOptions PasswordOptions
	SessionManager  SessionManager
	TokenManager    TokenManager
	Dispatcher      Dispatcher
	RateLimiter     RateLimiter
	Telemetry       Telemetry
	Validator       Validator
}
