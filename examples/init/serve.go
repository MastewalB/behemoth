package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	ginadapter "github.com/MastewalB/behemoth/plugins/adapters/gin"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

// serve is the full startup: Prepare, build the adapter with the prepared
// resolver, Boot onto the application's gin engine, then serve.
func serve(ctx context.Context) error {
	// The application owns its engine and its own routes; behemoth only adds
	// its routes to it, under Router.BasePath.
	// Stop on Ctrl-C or SIGTERM, so the server can finish its requests and
	// the exporters can send what they still hold. A process that is killed
	// without this loses its last few seconds of traces and metrics.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	obs, err := newObservability(ctx)
	if err != nil {
		return err
	}

	engine := gin.New()
	if obs.tracerProvider != nil {
		// The application's own tracing middleware, registered before any
		// route. It continues the caller's trace or starts one, and puts the
		// span on the request's context. behemoth reads no trace headers:
		// its behemoth.request span is a child of this one because it is
		// started from that context.
		engine.Use(otelgin.Middleware("behemoth-example", otelgin.WithTracerProvider(obs.tracerProvider)))
	}
	engine.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "my app") })

	_, _, sqlDB, err := boot(ctx, ginadapter.New(engine), obs.tel)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{Addr: addr, Handler: engine}
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServe() }()
	log.Printf("listening on %s", addr)

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	// ctx is cancelled by now, so the shutdown gets a context of its own.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log.Print("shutting down")
	err = server.Shutdown(shutdownCtx)
	return errors.Join(err, obs.shutdown(shutdownCtx)) // flush traces and metrics last
}

// boot runs Prepare and Boot. driver mounts behemoth's routes on the
// application's HTTP framework; nil boots without serving, which is what the
// signup command does. The returned *sql.DB is the caller's to close.
//
// tel is the application's telemetry (telemetry.go). The same logger goes to
// the database adapter, so SQL statements are logged at debug with the
// request ID of the request that ran them.
func boot(ctx context.Context, driver types.FrameworkDriver, tel *telemetry.Telemetry) (*types.AuthContext, *emailpassword.Plugin, *sql.DB, error) {
	// 1. Declarations: plugins, hooks, tokens, rate limits, schema -> resolver.
	all, ep := plugins()
	app, err := bmth.Prepare(all, prepareConfig())
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Storage, bound to the resolver Prepare derived from the schema.
	sqlDB, err := openDB()
	if err != nil {
		return nil, nil, nil, err
	}
	db := postgres.NewPostgresAdapter(sqlDB, app.Resolver).WithLogger(tel.Logger)

	// 3. Runtime: hook chains, rate limiter, session/token managers, plugin Init.
	cryptoCfg, err := cryptoConfig()
	if err != nil {
		sqlDB.Close()
		return nil, nil, nil, err
	}
	ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
		Crypto:    cryptoCfg,
		HTTP:      driver,
		Telemetry: tel,
		// The application's hook handlers (hooks.go). The plugins registered
		// theirs in Register.
		Hooks: appHooks,
		Session: types.SessionConfig{
			ExpiresIn:         24 * time.Hour,
			PendingExpiresIn:  10 * time.Minute,
			CaptureIPAndAgent: true, // sessions record the client's address and user agent
			Transport:         types.TransportHeader,
		},
		// KV, RateLimit, Token and Router left at their defaults: no KV
		// store (sessions and rate limits use the DB), routes under
		// /api/auth.
	})
	if err != nil {
		sqlDB.Close()
		return nil, nil, nil, err
	}
	// Boot has logged its own summary line ("behemoth booted") through tel.
	log.Printf("schema resolver: todos -> %s", app.Resolver.Resolve("todos"))
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
