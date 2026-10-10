# Command line

`behemoth generate` compares the tables your application declares with your database, and writes the migration that closes the gap.

```bash
behemoth generate            # show the next migration
behemoth generate -confirm   # write it to your migrations folder
```

`behemoth migrate` applies it, for applications that let Behemoth apply their migrations.

The command reads your plugins, your schema and your migration settings from your own code. You don't describe them a second time in a config file.

This is a first version, with a ready-made setup for PostgreSQL. The limits are listed at the end.

## Setup

The command needs two things from your application: what it declares, and how to reach its database. You give it both as functions.

### 1. Put your setup in a package

Create a file named `behemoth.go` in a package other than `main`, with these two functions:

```go
// internal/auth/behemoth.go
package auth

import (
	"context"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
)

// Prepare returns what the application declares. It opens no connection.
func Prepare() (*bmth.PreparedApp, error) {
	plugins := []types.Plugin{emailpassword.New(emailpassword.Options{})}
	return bmth.Prepare(plugins, bmth.PrepareConfig{
		Migration: core.MigrationConfig{FolderPath: "migrations"},
		Schema:    declareSchema, // your own tables, if you have any
	})
}

// MigrationBackend opens the database the command compares with.
func MigrationBackend(ctx context.Context, app *bmth.PreparedApp) (core.Backend, error) {
	db, err := OpenDB(ctx) // your own function: sql.Open and a ping
	if err != nil {
		return core.Backend{}, err
	}
	return postgres.MigrationBackend(db, app.Resolver), nil
}
```

Your server calls the same `Prepare` and passes its result to `Boot`:

```go
app, err := auth.Prepare()
// ...
db := postgres.NewPostgresAdapter(sqlDB, app.Resolver)
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{ /* ... */ })
```

Because both start from one function, the tables a migration creates are the tables your server reads. `MigrationBackend` is the only code you write for the command alone.

Keep `Prepare` free of connections and secrets. The command calls it before it opens the database, and `Boot`'s settings (crypto, sessions, mail) are not needed for a migration.

### 2. Install the launcher

```bash
go install github.com/MastewalB/behemoth/cmd/behemoth@latest
```

### 3. Run it where your application runs

```bash
cd my-app
behemoth generate
```

A relative `FolderPath` such as `"migrations"` is resolved against the directory you run the command in, as it is for your own binary. Run it from another directory and it starts a second migrations folder there.

## generate

```
$ behemoth generate
Migration 0001 ready (not yet written). Re-run with --confirm to write it to migrations.

0001, 22 operation(s):
  create table accounts
  add index idx_accounts_user_id on accounts
  add index uq_accounts_provider_account on accounts
  ...
  create table users
  add foreign key fk_accounts_user on accounts
  add foreign key fk_notes_user on notes
  add foreign key fk_sessions_user on sessions
```

Without `-confirm` the command writes nothing but the draft file described below. With `-confirm` it writes two more files to your migrations folder:

| File | Holds |
| --- | --- |
| `0001_create_accounts_and_6_more.json` | The migration as Behemoth records it. Keep it in the folder: the next migration's number comes from it. |
| `0001_create_accounts_and_6_more.sql` | The same migration as a script for your database. Apply this one with your own tool, such as `psql`, goose or golang-migrate. |

The name after the number says what the migration does. Behemoth derives it from the operations:

| Migration | Name |
| --- | --- |
| One operation | `0002_add_column_users_plan` |
| Several operations on one table | `0003_alter_notes` |
| New tables only | `0001_create_users_sessions_tokens`, or `0001_create_accounts_and_6_more` beyond three |
| Changes across tables | `0004_update_notes_users` |

Only the number identifies a migration. You can't choose the name yet.

`generate` never changes your database.

After you apply a script, run `behemoth generate` again. When the database matches your declarations it answers:

```
No schema changes detected.
```

### Questions and the draft file

Some differences have more than one answer. A column that got shorter in your declaration could be altered, which may reject existing rows, or left as it is. The command does not ask. It writes the question to `draft.json` in your migrations folder with a default answer, "Leave as-is", and tells you that it read an answer:

```
No schema changes detected.

1 answer(s) were read from migrations/draft.json. A new question starts with its default answer, which changes nothing. Edit the file and run the command again to choose another.
```

The file lists each question with its options. `chosen` is the position of the answer in `options`, counted from 0:

```json
{
  "entries": [
    {
      "id": "alter_column_users_plan",
      "table": "users",
      "description": "Column \"plan\"'s definition narrows (may reject or truncate existing data).",
      "options": ["Apply alter", "Leave as-is"],
      "chosen": 1
    }
  ]
}
```

Set `chosen` to `0` and run `behemoth generate` again to get the alter. So read the last lines of the output before you trust a "No schema changes detected".

## migrate

`migrate` is for an application whose `MigrationConfig.Path` is `core.PathManaged`. There Behemoth applies the migrations itself and keeps a record of them in two tables of its own.

```bash
behemoth generate -confirm   # write the next migration, for you to review
behemoth migrate             # show the migration that is waiting
behemoth migrate -confirm    # apply it
```

`generate` works as described above, with one difference: while a written migration is unapplied, it generates no further one and tells you to run `migrate` first.

The `.sql` is there for you to read. `migrate` applies the migration from the `.json`, so editing the script changes nothing, and running the script yourself leaves Behemoth's record without it: the next `migrate` would try to apply it again.

`migrate` never writes a migration. It applies the one that is waiting, and answers `Nothing to apply` when there is none.

On SQLite, MySQL and SQL Server some statements depend on the database as it is when they run. If the database changed since you generated, `migrate` applies nothing, writes the script again and asks you to review it and run `migrate` once more. On PostgreSQL the script depends on the migration alone, so this does not happen.

If your database already holds some of the declared tables when you start, the first migration `generate` writes is a baseline, `0000_baseline.json`. It describes those tables as they are. `migrate -confirm` records it without changing the database. If the database changes between the two, `migrate` refuses the baseline and asks you to generate and review it again.

On the default path, `migrate` ends with an error that names the path: you apply the files with your own tool.

## How the launcher finds your code

The launcher looks for a file named `behemoth.go` in the current directory and the directories below it. The package that file is in must export `Prepare` and `MigrationBackend`.

It does not look in directories whose name starts with `.` or `_`, in `testdata` and `vendor`, or in a directory that is another Go module.

If your setup is somewhere else, or the search finds more than one, name the directory:

```bash
behemoth -app ./internal/auth generate
BEHEMOTH_APP=./internal/auth behemoth generate
```

`-app` goes before the command.

The launcher then builds a small program inside your module and runs it:

```go
func main() { cli.Main(auth.Prepare, auth.MigrationBackend) }
```

Three things follow from that:

- **It needs the Go toolchain.** `go` must be on your `PATH`, as it is where you develop.
- **Your module decides the version.** The commands that run are those of the Behemoth version in your `go.mod`. Updating the launcher does not change them.
- **Nothing is written into your source tree.** The program is built in a temporary directory. It can still import a package under `internal/`.

## Without the launcher

Write the program yourself, once:

```go
// cmd/behemoth/main.go
package main

import (
	"github.com/MastewalB/behemoth/cli"

	"example.com/my-app/internal/auth"
)

func main() { cli.Main(auth.Prepare, auth.MigrationBackend) }
```

```bash
go run ./cmd/behemoth generate
```

Use this where there is no Go toolchain, by building the binary into your image, and in a module that vendors its dependencies. The launcher's program is not part of your code, so `go mod vendor` leaves the `cli` package out and the launcher's build fails there.

To offer the commands from your application's own binary, call `cli.Run` with the arguments and use its result as the exit code:

```go
if len(os.Args) > 1 && os.Args[1] == "behemoth" {
	os.Exit(cli.Run(ctx, os.Args[2:], os.Stdout, os.Stderr, auth.Prepare, auth.MigrationBackend))
}
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command ran. It found changes or it found none. |
| 1 | It failed: `Prepare` returned an error, the database could not be reached, or the migration could not be built. |
| 2 | Unknown command, unknown flag or an argument it did not expect. |

The launcher returns the command's own exit code. It returns 1 itself when it cannot find or build your setup.

## Other databases

`postgres.MigrationBackend` exists for PostgreSQL only so far. For MySQL, SQLite or SQL Server, fill `core.Backend` yourself from the module's driver. `generate` needs `Introspector`, and `Renderer` for the script. `migrate` also needs `Driver` and `DB`, the module's driver and its adapter:

```go
func MigrationBackend(ctx context.Context, app *bmth.PreparedApp) (core.Backend, error) {
	db, err := OpenDB(ctx)
	if err != nil {
		return core.Backend{}, err
	}
	driver := mysql.NewMySQLDriver(db, app.Resolver)
	return core.Backend{Introspector: driver, Renderer: driver, Close: db.Close}, nil
}
```

With GORM or Bun, take the `*sql.DB` your ORM holds and build the backend of the database underneath.

MongoDB has no migrations. See [MongoDB](./mongodb.md).

## Without the command line

`core.Generate` and `core.Migrate` are what the commands call. Use them from your own code, for example in a test that fails when a migration is missing:

```go
res, err := core.Generate(ctx, app.Migration, app.Declared(), backend, core.RunOptions{Confirm: false})
// res.Status is core.StatusNoChanges when the database matches
```

## Limits

- **No prompt.** Questions are answered in `draft.json`, as described above.
- **Vendored modules** need the hand-written program.
- **A moved file is forgotten.** Migration numbers come from the files in your migrations folder. If you move a generated `.json` out of it, the next migration gets its number again.

[examples/cli](../../examples/cli) is a complete application set up this way.
