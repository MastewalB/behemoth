package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	ginadapter "github.com/MastewalB/behemoth/plugins/adapters/gin"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	binit "github.com/MastewalB/behemoth/types/init"
	"github.com/gin-gonic/gin"
)

// serve is the full startup: Prepare, build the adapter with the prepared
// resolver, Boot onto the application's gin engine, then serve.
func serve(ctx context.Context) error {
	// The application owns its engine and its own routes; behemoth only adds
	// its routes to it, under Router.BasePath.
	engine := gin.New()
	engine.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "my app") })

	_, _, sqlDB, err := boot(ctx, ginadapter.New(engine))
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	return engine.Run(addr)
}

// boot runs Prepare and Boot. driver mounts behemoth's routes on the
// application's HTTP framework; nil boots without serving, which is what the
// signup command does. The returned *sql.DB is the caller's to close.
func boot(ctx context.Context, driver types.FrameworkDriver) (*types.AuthContext, *emailpassword.Plugin, *sql.DB, error) {
	// 1. Declarations: plugins, hooks, tokens, rate limits, schema -> resolver.
	all, ep := plugins()
	app, err := binit.Prepare(all, prepareConfig())
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Storage, bound to the resolver Prepare derived from the schema.
	sqlDB, err := openDB()
	if err != nil {
		return nil, nil, nil, err
	}
	db := postgres.NewPostgresAdapter(sqlDB, app.Resolver)

	// 3. Runtime: hook chains, rate limiter, session/token managers, plugin Init.
	cryptoCfg, err := cryptoConfig()
	if err != nil {
		sqlDB.Close()
		return nil, nil, nil, err
	}
	ac, err := binit.Boot(ctx, app, db, binit.BootConfig{
		Crypto: cryptoCfg,
		HTTP:   driver,
		// The application's hook handlers (hooks.go). The plugins registered
		// theirs in Register.
		Hooks: appHooks,
		Session: types.SessionConfig{
			ExpiresIn:         24 * time.Hour,
			PendingExpiresIn:  10 * time.Minute,
			CaptureIPAndAgent: true, // sessions record the client's address and user agent
			Transport:         types.TransportHeader,
		},
		// KV, Telemetry, RateLimit, Token and Router left at their defaults:
		// no KV store (sessions and rate limits use the DB), no-op
		// telemetry, routes under /api/auth.
	})
	if err != nil {
		sqlDB.Close()
		return nil, nil, nil, err
	}
	log.Printf("behemoth booted: plugins=%v, todos -> %s", app.Order, app.Resolver.Resolve("todos"))
	return ac, ep, sqlDB, nil
}

// cryptoConfig reads the master secret (hex, >= 32 bytes) from
// BEHEMOTH_SECRET. Without one it generates a throwaway secret, which is
// fine locally but invalidates every session and token on restart.
func cryptoConfig() (crypto.Config, error) {
	secret := os.Getenv("BEHEMOTH_SECRET")
	if secret == "" {
		b, err := crypto.NewRandomizer().SecureRandomBytes(32)
		if err != nil {
			return crypto.Config{}, err
		}
		secret = hex.EncodeToString(b)
		log.Print("BEHEMOTH_SECRET not set: using a random secret, sessions won't survive a restart")
	}

	return crypto.Config{
		Secrets:    crypto.StaticSecretSource{Secrets: map[int]string{1: secret}, Current: 1},
		KeyManager: crypto.KeyManagerConfig{Environment: types.EnvDev},
		Password:   nil, // crypto.DefaultParams
	}, nil
}
