package storage

import (
	"database/sql"
	"time"

	"github.com/MastewalB/behemoth/models"
)

type DatabaseProvider interface {
	FindUserByEmail(email string) (models.User, error)
	SaveUser(user *models.DefaultUser) error
	FindUserByID(id string) (models.User, error)
	WithTransaction(func(tx *sql.Tx) error) error
}

type DBConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}
