// Command cli is an application whose migrations are generated with the
// behemoth command line. It runs against PostgreSQL.
//
//	behemoth generate            # show the next migration
//	behemoth generate -confirm   # write it to ./migrations
//	psql "$DATABASE_URL" -f migrations/0001_create_accounts_and_6_more.sql
//	behemoth generate            # now answers "No schema changes detected."
//	go run .                     # Prepare + Boot, then serve HTTP
//
// "behemoth" is the launcher. Install it once, from the repository root:
//
//	go install ./cmd/behemoth
//
// Without it, the same commands are "go run ./cmd/behemoth generate".
//
// DATABASE_URL defaults to postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable
//
// The setup is in the auth package. This file and the command line both
// call auth.Prepare and auth.OpenDB, so the tables the migration creates are
// the ones the server reads. With the server running:
//
//	curl -X POST localhost:8080/api/auth/sign-up/email \
//	  -d '{"email":"ada@example.com","password":"correct horse battery"}'
package main

import (
	"context"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/examples/cli/auth"
	"github.com/MastewalB/behemoth/plugins/adapters/nethttp"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
)

func main() {
	ctx := context.Background()

	// 1. Declarations. The command line starts from the same call.
	app, err := auth.Prepare()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Storage, bound to the resolver Prepare derived from the schema.
	sqlDB, err := auth.OpenDB(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()
	db := postgres.NewPostgresAdapter(sqlDB, app.Resolver)

	// 3. Runtime, with behemoth's routes on the application's mux.
	cryptoCfg, err := cryptoConfig()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	if _, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
		Crypto:  cryptoCfg,
		HTTP:    nethttp.New(mux),
		Session: types.SessionConfig{ExpiresIn: 24 * time.Hour, Transport: types.TransportHeader},
	}); err != nil {
		log.Fatal(err)
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// cryptoConfig reads the master secret (hex, at least 32 bytes) from
// BEHEMOTH_SECRET. Without one it generates a throwaway secret, which is
// fine locally but invalidates every session on restart.
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
	}, nil
}
