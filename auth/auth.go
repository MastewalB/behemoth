package auth

import (
	"errors"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
)

type Behemoth[T behemoth.User] struct {
	DB          behemoth.Database[T]
	Password    *PasswordAuth[T]
	OAuth       *OAuthAuth[T]
	JWT         *JWTService
	Session     *SessionManager
	UseSessions bool
}

// New creates a new Behemoth instance with the given config.
func New[T behemoth.User](cfg *behemoth.Config[T]) (*Behemoth[T], error) {
	var database behemoth.Database[T]
	var userModel behemoth.User
	var passwordAuth *PasswordAuth[T]
	var jwtSvc *JWTService
	var oauth *OAuthAuth[T]
	var sessionMgr *SessionManager

	if cfg.DatabaseConfig.UseDefaultUser {
		userModel = &models.User{}
		cfg.DatabaseConfig.UserModel = userModel
		cfg.DatabaseConfig.UserTable = "users"
		cfg.DatabaseConfig.PrimaryKey = "email"
		cfg.DatabaseConfig.FindUserFn = getFinderFn(cfg.DatabaseConfig.Name)
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
		sessionMgr = NewSessionManager(
			database,
			sessionConfig.Expiry,
			sessionConfig.CookieName,
			sessionConfig.Factory,
		)
	}

	if cfg.DatabaseConfig.DB == nil {
		if cfg.DatabaseConfig.FindUserFn == nil {
			return nil, errors.New("a database connection or a FindUserFn is required")
		}
	} else {
		var err error
		var sessionFactory behemoth.SessionFactory
		if sessionMgr != nil {
			sessionFactory = sessionMgr.sessionFactory
		}
		database, err = InitDatabase(&cfg.DatabaseConfig, sessionFactory)
		if err != nil {
			return nil, err
		}
	}

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

	if len(cfg.OAuthProviders) > 0 {
		oauth = NewOAuthAuth(
			cfg.OAuthProviders,
			jwtSvc,
			cfg.DatabaseConfig.UseDefaultUser,
			userModel,
			database,
		)
	}

	return &Behemoth[T]{
		DB:          database,
		Password:    passwordAuth,
		OAuth:       oauth,
		JWT:         jwtSvc,
		Session:     sessionMgr,
		UseSessions: cfg.UseSessions,
	}, nil
}

func InitDatabase[T behemoth.User](
	cfg *behemoth.DatabaseConfig[T],
	sessionFactory behemoth.SessionFactory,
	) (behemoth.Database[T], error) {
	switch cfg.Name {
	case behemoth.SQLite:
		return storage.NewSQLite[T](
			cfg.DB,
			cfg.UserTable,
			cfg.PrimaryKey,
			sessionFactory,
			cfg.FindUserFn,
		)
	case behemoth.Postgres:
		return storage.NewPostgres[T](
			cfg.DB,
			cfg.UserTable,
			cfg.PrimaryKey,
			sessionFactory,
			cfg.FindUserFn,
		)
	default:
		return nil, nil
	}
}

func getFinderFn(dbName behemoth.DatabaseName) behemoth.FindUserFn {
	switch dbName {
	case behemoth.SQLite:
		return behemoth.FindUserByEmailSQLite
	case behemoth.Postgres:
		return behemoth.FindUserByEmailPG
	default:
		return nil
	}
}
