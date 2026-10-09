# Behemoth: Authentication Library for Go ( <img src="./docs/repairing-tools-svgrepo-com.svg" alt="Behemoth is currently under maintenance" width="20"> )

Behemoth adds authentication to a Go application through plugins. You pick the plugins and the database, and Behemoth sets up the tables, the routes, sessions, hooks and telemetry around them.

The project is under active development, and the API may still change.

## Features

- **Plugins.** Each plugin declares its routes, tables, hooks and rate limits. The first one, `emailpassword`, handles sign-up, sign-in and sign-out. `magiclink` signs a user in with a link sent by email, and `emailverification` confirms a user's address.
- **Migrations.** Behemoth builds a migration from the tables your plugins and your own schema declare, and writes it to a folder for you to review.
- **Hooks.** Run your code before or after a user is written, or around a whole flow such as sign-up. A handler can change data, stop an operation or react afterwards.
- **Sessions and tokens.** Sessions are stored in your database or a key-value store, and delivered as a cookie or a header.
- **Router adapters.** Mount the routes on `net/http`, Gin, Echo, chi or Fiber.
- **Telemetry.** Logs, audit events, metrics and traces, with an OpenTelemetry adapter.
- **Rate limiting** and **Argon2id password hashing** out of the box.

## Installation

```bash
go get github.com/MastewalB/behemoth
```

Database and router adapters are separate modules, so you only download what you use:

```bash
go get github.com/MastewalB/behemoth/storage/adapters/postgres
go get github.com/MastewalB/behemoth/plugins/adapters/gin
```

The adapter for the standard library's `http.ServeMux` has no dependency of its own, so it comes with Behemoth: import `github.com/MastewalB/behemoth/plugins/adapters/nethttp`.

## Quick start

Setup has two steps. `Prepare` collects the declarations of your plugins and schema. `Boot` connects them to a database and a router.

```go
import (
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	ginadapter "github.com/MastewalB/behemoth/plugins/adapters/gin"
)

plugin := emailpassword.New(emailpassword.Options{})

// 1. Declarations: plugins, hooks, schema.
app, err := bmth.Prepare([]types.Plugin{plugin}, bmth.PrepareConfig{})
if err != nil {
	log.Fatal(err)
}

// 2. Runtime: storage, routes, sessions.
db := postgres.NewPostgresAdapter(sqlDB, app.Resolver)
engine := gin.New()

ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	Crypto: cryptoCfg, // the master secret(s) every key is derived from
	HTTP:   ginadapter.New(engine),
	Session: types.SessionConfig{
		ExpiresIn: 24 * time.Hour,
		Transport: types.TransportHeader,
	},
})
if err != nil {
	log.Fatal(err)
}

engine.Run(":8080")
```

The routes are now live under `/api/auth`:

```bash
curl -X POST localhost:8080/api/auth/sign-up/email \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'
curl -X POST localhost:8080/api/auth/sign-in/email \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'
```

The sign-in response carries the session token where `Transport` says: here in the `Set-Auth-Token` header, which the client sends back as `Authorization: Bearer <token>`. The default is a cookie.

Without a router, call the same flows from code with `plugin.SignUp` and `plugin.SignIn`.

## Examples

[examples/init](./examples/init) is a complete application on PostgreSQL and Gin. It shows migrations, a custom plugin, hooks, and telemetry with OpenTelemetry.

```bash
cd examples/init
go run . migrate -confirm   # write the first migration to ./migrations
go run . serve              # Prepare + Boot, then serve HTTP
go run . signup -email ada@example.com -password 'correct horse'
```

`DATABASE_URL` defaults to a local PostgreSQL at `postgres://postgres:postgres@localhost:5432/behemoth`.

## Supported databases

| Kind | Options |
| --- | --- |
| `database/sql` | PostgreSQL, MySQL, SQLite, SQL Server |
| Document | MongoDB |
| ORM | Bun, GORM |
| Key-value (sessions, rate limits) | Redis |

Migrations can be generated for PostgreSQL, MySQL, SQLite and SQL Server. MongoDB has no migrations: the adapter creates the declared indexes (`EnsureIndexes`), and `Boot` checks them.

## Documentation

| Page | Covers |
| --- | --- |
| [Email and password](./docs/api/emailpassword.md) | The plugin's options, routes and hook points |
| [Magic link](./docs/api/magiclink.md) | Sign-in by emailed link: setup, sending the link, routes, redirects and rate limits |
| [Email verification](./docs/api/emailverification.md) | Confirming a user's address: when a link is sent, routes, requiring a verified email, and changing an address safely |
| [Mail](./docs/api/mail.md) | The mail sender plugins use, and waiting or background sends |
| [Router adapters](./docs/api/routers.md) | Mounting the routes on `net/http`, Gin, Echo, chi or Fiber, and what is specific to each |
| [Sessions](./docs/api/sessions.md) | Session settings, how the token travels (cookie, header, body), the sign-in response, protecting your own routes |
| [Hooks](./docs/api/hooks.md) | Hook points, handlers, ordering and failure behavior |
| [Telemetry](./docs/api/telemetry.md) | Loggers, audit, metrics, tracing and the OpenTelemetry adapter |
| [Core tables](./docs/api/core-tables.md) | Writing Behemoth's tables from a plugin |
| [MongoDB](./docs/api/mongodb.md) | What the server needs, and creating the indexes a schema declares |
| [Internal docs](./docs/internal) | How the system works, for contributors |

## Roadmap

Not built yet:

- Password reset, password change and email verification
- OAuth 2.0 providers (the `providers/` package predates the plugin system and is likely to move)

## Benchmarks

Not available yet.

## Contributing

Contributions are welcome. Open an issue to discuss a change before sending a large pull request.

1. Fork the repository and create a branch.
2. Format the code with `gofmt` and follow the Go Code Review Comments.
3. Add tests for your change and run `go test ./...`. The `tests` module and each adapter module have their own `go.mod`, so run their tests from their directories.
4. Update the docs in `docs/` together with the code.

## License

MIT. See [LICENSE.txt](./LICENSE.txt).
