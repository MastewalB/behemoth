package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/service"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/types"
)

type Behemoth[T behemoth.User] struct {
	DB               behemoth.Database
	EmailAndPassword *service.EmailAndPasswordService
	Transport        *behemoth.AuthTransportManager
}

// New creates a new Behemoth instance with the given config.
func New[T behemoth.User](cfg *behemoth.Config[T]) (*Behemoth[T], error) {
	var authContext types.AuthContext
	var database behemoth.Database
	var userModel behemoth.User
	var emailAndPasswordAuth *service.EmailAndPasswordService
	var transportManager *behemoth.AuthTransportManager

	if cfg.DatabaseConfig.UseDefaultUser {
		userModel = &models.User{}
		cfg.DatabaseConfig.UserModel = userModel
		cfg.DatabaseConfig.UserFactory = models.UserFactory
	} else {
		if cfg.DatabaseConfig.UserModel == nil {
			return nil, errors.New("user model is required. Set useDefaultUser to true to use the default user model")
		}
		userModel = cfg.DatabaseConfig.UserModel
	}

	if cfg.DatabaseConfig.DB == nil {
		return nil, errors.New("a database connection or a FindUserFn is required")
	} else {
		var err error
		fmt.Println("Initializing Database with config:", cfg.DatabaseConfig)
		database, err = InitDatabase(&cfg.DatabaseConfig)
		if err != nil {
			return nil, err
		}
	}

	if cfg.UseEmailAndPasswordAuth {
		emailAndPasswordAuth = service.NewEmailAndPasswordService(
			authContext,
		)
	}

	return &Behemoth[T]{
		DB:               database,
		EmailAndPassword: emailAndPasswordAuth,
		Transport:        transportManager,
	}, nil
}

func InitDatabase(
	cfg *behemoth.DatabaseConfig,
) (behemoth.Database, error) {
	switch cfg.Name {
	case behemoth.SQLite:
		return adapters.NewSQLiteAdapter(
			cfg.DB,
		), nil

	default:
		return nil, nil
	}
}

var DefalultSessionConfig = behemoth.SessionConfig{
	CookieName: "session_id",
	Expiry:     2 * time.Hour,
}
