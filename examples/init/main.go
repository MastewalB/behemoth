// Command init walks through behemoth's initialization from the
// application's side, against PostgreSQL.
//
//	go run . migrate            # preview the next migration (Prepare only)
//	go run . migrate -confirm   # write it to ./migrations
//	go run . serve              # Prepare + Boot, then serve HTTP
//	go run . signup -email ada@example.com -password 'correct horse' [-invite WELCOME2026]
//	                            # Prepare + Boot, then sign up and sign in without HTTP
//	go run . audit [-email ada@example.com] [-n 20]
//	                            # print the newest audit events, or those about one user
//
// DATABASE_URL defaults to postgres://postgres:postgres@localhost:5432/behemoth?sslmode=disable
//
// The example also shows hooks at work. The activity plugin (plugin.go) and the
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
// its own message; a wrong password records a rejection in activity_events.
//
// # Mailed links
//
// Two flows mail a link: sign-in by magic link (plugins/magiclink) and
// password reset (part of plugins/emailpassword). Behemoth sends no mail
// itself. It hands each message to the application's sender (mail.go), which
// here prints it, so the link shows up in the server's output:
//
//	curl -X POST localhost:8080/api/auth/sign-in/magic-link -d '{"email":"ada@example.com"}'
//	curl -X POST localhost:8080/api/auth/password-reset/request -d '{"email":"ada@example.com"}'
//
// Both answer 200 whether or not the address has an account, and only a
// known address is sent a link. Open the printed link in a browser. It is a
// page of the application (pages.go), which posts the token to behemoth:
// the magic link page signs the user in, and the reset page asks for a new
// password first. The same step with curl, with the token from the link:
//
//	curl -i -X POST localhost:8080/api/auth/magic-link/verify -d '{"token":"..."}'
//	curl -X POST localhost:8080/api/auth/password-reset/confirm \
//	  -d '{"token":"...","password":"a brand new staple"}'
//
// A link works once, and asking again replaces the earlier one. After a
// reset the old password and every session of the user stop working, and
// the sender is handed a "your password was changed" notice.
//
// APP_URL is the address the links point to (default http://localhost:8080).
//
// # Telemetry
//
// telemetry.go wires behemoth's logs, audit events, metrics and traces.
// With no extra configuration the example logs to stdout and records audit
// events in the audit_log table:
//
//	LOG_LEVEL=debug go run . serve   # also logs rejected requests and SQL statements
//	go run . audit -email ada@example.com
//
// Traces and metrics are exported over OTLP when an endpoint is set. To look
// at traces in Jaeger, which accepts OTLP directly:
//
//	docker run --rm -p 16686:16686 -p 4318:4318 jaegertracing/jaeger
//	OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces go run . serve
//
// then send a request and open http://localhost:16686 (service
// "behemoth-example"). A sign-up shows as one trace: the gin span, then
// behemoth.request with the password hash, the store operations inside
// their transaction, and each hook handler under its point.
//
// With an OpenTelemetry Collector, set OTEL_EXPORTER_OTLP_ENDPOINT instead
// and both traces and metrics go to it.
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
		fmt.Fprintln(os.Stderr, "usage: init <migrate [-confirm] | serve | signup -email E -password P [-invite CODE] | audit [-email E] [-n N]>")
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
	case "audit":
		fs := flag.NewFlagSet("audit", flag.ExitOnError)
		email := fs.String("email", "", "print the events about this user only")
		limit := fs.Int("n", 20, "how many events to print")
		fs.Parse(args)
		err = audit(ctx, *email, *limit)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}
