package store_test

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	bunAdapter "github.com/go-behemoth/behemoth/storage/adapters/bun"
	gormAdapter "github.com/go-behemoth/behemoth/storage/adapters/gorm"
	sqliteAdapter "github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// openForeignKeyDB opens a SQLite file with foreign keys on or off. The
// setting is in the DSN, so every connection of the pool has it.
func openForeignKeyDB(t *testing.T, foreignKeys bool) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "fk.db") + "?_busy_timeout=10000"
	if foreignKeys {
		dsn += "&_foreign_keys=on"
	}
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// The SQLite adapters report whether their connection enforces foreign keys,
// which Boot asks before it writes anything.
func TestSQLiteAdaptersCheckForeignKeys(t *testing.T) {
	ctx := context.Background()
	build := map[string]func(t *testing.T, db *sql.DB) behemoth.ForeignKeyChecker{
		"sqlite": func(t *testing.T, db *sql.DB) behemoth.ForeignKeyChecker {
			return sqliteAdapter.NewSQLiteAdapter(db, nil)
		},
		"bun": func(t *testing.T, db *sql.DB) behemoth.ForeignKeyChecker {
			return bunAdapter.NewBunAdapter(bun.NewDB(db, sqlitedialect.New()), nil)
		},
		"gorm": func(t *testing.T, db *sql.DB) behemoth.ForeignKeyChecker {
			g, err := gorm.Open(sqlite.Dialector{Conn: db}, &gorm.Config{})
			require.NoError(t, err)
			return gormAdapter.NewGormAdapter(g, nil)
		},
	}
	for name, newChecker := range build {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, newChecker(t, openForeignKeyDB(t, true)).CheckForeignKeys(ctx), "foreign keys on")

			err := newChecker(t, openForeignKeyDB(t, false)).CheckForeignKeys(ctx)
			require.Error(t, err, "foreign keys off")
			assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
			assert.Contains(t, err.Error(), "_foreign_keys=on", "the error says how to switch them on")
			assert.Contains(t, err.Error(), "BootConfig.AllowUnenforcedForeignKeys", "and how to start without them")
		})
	}
}

// Boot refuses a SQLite database without foreign keys, unless the
// application allows it, and then it says so in a warning.
func TestBootAndForeignKeys(t *testing.T) {
	ctx := context.Background()
	bootOn := func(t *testing.T, db *sql.DB, allow bool) (*telemetrytest.Recorder, error) {
		t.Helper()
		app, err := engine.Prepare(nil, engine.PrepareConfig{})
		require.NoError(t, err)
		createTables(t, sqliteAdapter.NewSQLiteDriver(db, app.Resolver), app.Schemas.All())
		tel, rec := telemetrytest.New()
		_, err = engine.Boot(ctx, app, sqliteAdapter.NewSQLiteAdapter(db, app.Resolver), engine.BootConfig{
			Crypto: crypto.Config{
				Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ab", 32)}, Current: 1},
			},
			Session:                    core.SessionConfig{ExpiresIn: time.Hour, PendingExpiresIn: 5 * time.Minute},
			Telemetry:                  tel,
			AllowUnenforcedForeignKeys: allow,
		})
		return rec, err
	}
	warnings := func(rec *telemetrytest.Recorder) (n int) {
		for _, e := range rec.Logger.At(slog.LevelWarn) {
			if strings.Contains(e.Message, "foreign keys are not enforced") {
				n++
			}
		}
		return n
	}

	t.Run("foreign keys on", func(t *testing.T) {
		rec, err := bootOn(t, openForeignKeyDB(t, true), false)
		require.NoError(t, err)
		assert.Zero(t, warnings(rec))
	})
	t.Run("foreign keys off", func(t *testing.T) {
		_, err := bootOn(t, openForeignKeyDB(t, false), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database foreign key check failed")
		assert.Contains(t, err.Error(), "_foreign_keys=on")
	})
	t.Run("foreign keys off and allowed", func(t *testing.T) {
		rec, err := bootOn(t, openForeignKeyDB(t, false), true)
		require.NoError(t, err)
		assert.Equal(t, 1, warnings(rec), "Boot logs one warning")
	})
}
