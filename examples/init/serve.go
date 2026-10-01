package main

import (
	"context"
	"encoding/hex"
	"log"
	"net/http"
	"os"

	"github.com/MastewalB/behemoth/crypto"
	ginadapter "github.com/MastewalB/behemoth/plugins/adapters/gin"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	binit "github.com/MastewalB/behemoth/types/init"
	"github.com/gin-gonic/gin"
)

// serve is the full startup: Prepare, build the adapter with the prepared
// resolver, Boot onto the application's gin engine, then serve.
func serve(ctx context.Context) error {
	// 1. Declarations: plugins, hooks, tokens, rate limits, schema -> resolver.
	app, err := binit.Prepare(plugins(), prepareConfig())
	if err != nil {
		return err
	}

	// 2. Storage, bound to the resolver Prepare derived from the schema.
	sqlDB, err := openDB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	db := postgres.NewPostgresAdapter(sqlDB, app.Resolver)

	// 3. Runtime: hook chains, rate limiter, session/token managers, plugin Init.
	cryptoCfg, err := cryptoConfig()
	if err != nil {
		return err
	}
	// The application owns its engine and its own routes; behemoth only adds
	// its routes to it, under Router.BasePath.
	engine := gin.New()
	engine.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "my app") })

	_, err = binit.Boot(ctx, app, db, binit.BootConfig{
		Crypto: cryptoCfg,
		HTTP:   ginadapter.New(engine),
		// KV, Telemetry, RateLimit, Session, Token and Router left at their
		// defaults: no KV store (sessions and rate limits use the DB),
		// no-op telemetry, routes under /api/auth.
	})
	if err != nil {
		return err
	}
	log.Printf("behemoth booted: plugins=%v, todos -> %s", app.Order, app.Resolver.Resolve("todos"))

	// 4. Serve.
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	return engine.Run(addr)
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
