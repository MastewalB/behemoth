package auth

import (
	"errors"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage/adapters"
)

type Behemoth[T behemoth.User] struct {
	DB       behemoth.Database
	Password *PasswordAuth
	// OAuth       *OAuthAuth[T]
	JWT *JWTService
	// Session     *SessionManager
	UseSessions bool
}

// New creates a new Behemoth instance with the given config.
func New[T behemoth.User](cfg *behemoth.Config[T]) (*Behemoth[T], error) {
	var database behemoth.Database
	var userModel behemoth.User
	var passwordAuth *PasswordAuth
	var jwtSvc *JWTService
	// var oauth *OAuthAuth[T]
	// var sessionMgr *SessionManager

	if cfg.DatabaseConfig.UseDefaultUser {
		userModel = &models.User{}
		cfg.DatabaseConfig.UserModel = userModel
		// cfg.DatabaseConfig.UserTable = "users"
		// cfg.DatabaseConfig.PrimaryKey = "email"
		// cfg.DatabaseConfig.FindUserFn = getFinderFn(cfg.DatabaseConfig.Name)
	} else {
		if cfg.DatabaseConfig.UserModel == nil {
			return nil, errors.New("user model is required. Set useDefaultUser to true to use the default user model")
		}
		userModel = cfg.DatabaseConfig.UserModel
	}

	if cfg.UseSessions {
		var sessionConfig *behemoth.SessionConfig = cfg.Session
		if sessionConfig == nil {
			sessionConfig = &behemoth.DefalultSessionConfig
			cfg.Session = sessionConfig
		}
	}

	if cfg.DatabaseConfig.DB == nil {
		return nil, errors.New("a database connection or a FindUserFn is required")
		// if cfg.DatabaseConfig.FindUserFn == nil {
		// }
	} else {
		var err error
		var sessionFactory behemoth.SessionFactory
		if cfg.Session != nil {
			sessionFactory = cfg.Session.Factory
		}
		fmt.Println("Initializing Database with config:", cfg.DatabaseConfig)
		database, err = InitDatabase(&cfg.DatabaseConfig, sessionFactory)
		if err != nil {
			return nil, err
		}
	}

	// if cfg.Session != nil {
	// 	sessionMgr = NewSessionManager(
	// 		database,
	// 		cfg.Session.Expiry,
	// 		cfg.Session.CookieName,
	// 		cfg.Session.Factory,
	// 	)
	// 	log.Println("Session manager initialized", sessionMgr.cookieName)
	// }

	if cfg.JWT != nil {
		jwtSvc = NewJWTService(*cfg.JWT)
	}

	if cfg.Password != nil {
		passwordAuth = NewPasswordAuth(
			*cfg.Password,
			jwtSvc,
			cfg.DatabaseConfig.UseDefaultUser,
			userModel,
			database,
		)
	}

	// if len(cfg.OAuthProviders) > 0 {
	// 	oauth = NewOAuthAuth(
	// 		cfg.OAuthProviders,
	// 		jwtSvc,
	// 		cfg.DatabaseConfig.UseDefaultUser,
	// 		userModel,
	// 		database,
	// 	)
	// }

	return &Behemoth[T]{
		DB:       database,
		Password: passwordAuth,
		// OAuth:       oauth,
		JWT: jwtSvc,
		// Session:     sessionMgr,
		UseSessions: cfg.UseSessions,
	}, nil
}

func InitDatabase(
	cfg *behemoth.DatabaseConfig,
	sessionFactory behemoth.SessionFactory,
) (behemoth.Database, error) {
	switch cfg.Name {
	case behemoth.SQLite:
		return adapters.NewSQLiteAdapter(
			cfg.DB,
		), nil
	// case behemoth.Postgres:
	// 	return storage.NewPostgres(
	// 		cfg.DB,
	// 		cfg.UserTable,
	// 		cfg.PrimaryKey,
	// 		sessionFactory,
	// 		cfg.FindUserFn,
	// 	)
	default:
		return nil, nil
	}
}

// func getFinderFn(dbName behemoth.DatabaseName) behemoth.FindUserFn {
// 	switch dbName {
// 	case behemoth.SQLite:
// 		return behemoth.FindUserByEmailSQLite
// 	case behemoth.Postgres:
// 		return behemoth.FindUserByEmailPG
// 	default:
// 		return nil
// 	}
// }
