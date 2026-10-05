// Command init walks through behemoth's initialization from the
// application's side, against PostgreSQL.
//
//	go run . migrate            # preview the next migration (Prepare only)
//	go run . migrate -confirm   # write it to ./migrations
//	go run . serve              # Prepare + Boot, then serve HTTP
//	go run . signup -email ada@example.com -password 'correct horse' [-invite WELCOME2026]
//	                            # Prepare + Boot, then sign up and sign in without HTTP
//
// DATABASE_URL defaults to postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable
//
// The example also shows hooks at work. The audit plugin (plugin.go) and the
// application (hooks.go) register handlers on the email/password flows and
// on the user write, and every handler logs a line (demo.go). With the
// server running, a sign-up through the route produces the same lines as the
// signup command, with "via http" instead of "via cli":
//
//	curl -X POST localhost:8080/api/auth/sign-up/email \
//	  -d '{"email":"ada@example.com","password":"correct horse","inviteCode":"WELCOME2026"}'
//	curl -X POST localhost:8080/api/auth/sign-in/email \
//	  -d '{"email":"ada@example.com","password":"correct horse"}'
//
// An unknown inviteCode is rejected by the application's hook with a 400 and
// its own message; a wrong password records a rejection in audit_events.
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
		fmt.Fprintln(os.Stderr, "usage: init <migrate [-confirm] | serve | signup -email E -password P [-invite CODE]>")
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
	case "signup":
		fs := flag.NewFlagSet("signup", flag.ExitOnError)
		email := fs.String("email", "", "the new user's email address")
		password := fs.String("password", "", "the new user's password")
		invite := fs.String("invite", "", "an invite code (optional)")
		fs.Parse(args)
		err = signup(ctx, *email, *password, *invite)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}
