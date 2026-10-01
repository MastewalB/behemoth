// Command init walks through behemoth's initialization from the
// application's side, against PostgreSQL.
//
//	go run . migrate            # preview the next migration (Prepare only)
//	go run . migrate -confirm   # write it to ./migrations
//	go run . serve              # Prepare + Boot, then serve HTTP
//
// DATABASE_URL defaults to postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: init <migrate [-confirm] | serve>")
		os.Exit(2)
	}
	ctx := context.Background()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "migrate":
		fs := flag.NewFlagSet("migrate", flag.ExitOnError)
		confirm := fs.Bool("confirm", false, "write the generated migration to disk")
		fs.Parse(args)
		err = migrate(ctx, *confirm)
	case "serve":
		err = serve(ctx)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}
