// Package cli is behemoth's command line as a library.
//
// The commands need an application's declarations, which exist only as Go
// code in that application's build: its plugins' Declare methods and its own
// schema function. A prebuilt binary cannot load them, so the application
// links this package and hands it two functions:
//
//	func main() { cli.Main(auth.Prepare, auth.MigrationBackend) }
//
// The first returns the result of Prepare, the second opens the database.
// Everything else comes from those two: the migrations folder, the path, the
// resolver and the draft file.
//
// That main is written once by hand, or generated on each run by the
// launcher in cmd/behemoth, which is what makes "behemoth generate" work in
// an application's directory.
//
// The commands follow what a developer does. generate writes the next
// migration and never changes the database, on either path. migrate applies
// what generate wrote, on PathManaged, and refuses an application that
// applies its migrations with its own tool.
//
// Experimental: the command line is a first version. Only PostgreSQL has a
// ready-made setup (postgres.MigrationBackend); for MySQL, SQLite and SQL
// Server the application fills in migration.Backend itself. Its behavior can
// change between versions.
//
// Deferred: there is no prompt for the questions planning raises (they are
// answered in the draft file), no --previous override and no schema snapshot
// command. See docs/internal/migrations/cli.md.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/MastewalB/behemoth/engine"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/migration"
	"github.com/MastewalB/behemoth/telemetry"
)

// Exit codes of Run and Main.
const (
	ExitOK      = 0 // the command ran, whether or not it found changes
	ExitFailure = 1 // the command could not run or failed
	ExitUsage   = 2 // unknown command, unknown flag or stray argument
)

// program is the name the commands are documented under. It is the
// launcher's name, and reads the same when an application runs the commands
// from its own binary.
const program = "behemoth"

// PrepareFunc returns the application's declarations: engine.Prepare called
// with the plugins and the configuration the application boots with. It runs
// before any connection is opened, so it should need none, the same as
// Prepare itself.
type PrepareFunc func() (*engine.PreparedApp, error)

// BackendFunc opens the application's database and returns its migration
// backend, for example postgres.MigrationBackend(db, app.Resolver). The
// backend has to be built with app.Resolver. Its Close, when set, is called
// when the command ends.
type BackendFunc func(ctx context.Context, app *engine.PreparedApp) (migration.Backend, error)

// Main runs the command named by os.Args and exits the process with its
// exit code. An interrupt cancels the command's context.
func Main(prepare PrepareFunc, backend BackendFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := Run(ctx, os.Args[1:], os.Stdout, os.Stderr, prepare, backend)
	stop()
	os.Exit(code)
}

// Run runs one command and returns its exit code. args are the arguments
// after the program name. Results go to stdout; errors, usage and warnings
// go to stderr.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, prepare PrepareFunc, backend BackendFunc) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return ExitOK
	}
	// The commands are code in the process: they name themselves as the
	// caller of what they run.
	ctx = identity.WithCaller(ctx, identity.System(program))
	for _, cmd := range commands() {
		if cmd.name == args[0] {
			return cmd.exec(ctx, args[1:], stdout, stderr, prepare, backend)
		}
	}
	fmt.Fprintf(stderr, "%s: unknown command %q\n\n", program, args[0])
	usage(stderr)
	return ExitUsage
}

// command is one subcommand. Both have the same shape: a -confirm flag, the
// application's two functions, one call into core.
type command struct {
	name    string
	summary string
	confirm string // help text of -confirm

	// refuse returns why the command does not apply to an application on
	// path, or "". It is asked before the database is opened.
	refuse func(path migration.MigrationPath) string

	run func(context.Context, migration.MigrationConfig, migration.Declared, migration.Backend, migration.RunOptions) (*migration.RunResult, error)
}

func commands() []command {
	return []command{
		{
			name:    "generate",
			summary: "Show the next migration. With -confirm, write it to the migrations folder.",
			confirm: "write the migration to the migrations folder",
			refuse:  func(migration.MigrationPath) string { return "" },
			run:     migration.Generate,
		},
		{
			name:    "migrate",
			summary: "Show the migration that is waiting to be applied. With -confirm, apply it.",
			confirm: "apply the migration to the database",
			refuse: func(path migration.MigrationPath) string {
				if path == migration.PathManaged {
					return ""
				}
				return fmt.Sprintf("MigrationConfig.Path is %q: this application applies its migrations with its own tool, from the files \"%s generate\" writes. Set the path to %q to have %s apply them",
					path, program, migration.PathManaged, program)
			},
			run: migration.Migrate,
		},
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s <command> [-confirm]\n\nCommands:\n", program)
	for _, cmd := range commands() {
		fmt.Fprintf(w, "  %-9s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintf(w, "\ngenerate never changes the database. migrate does, and is for applications\nwhose MigrationConfig.Path is %q.\n", migration.PathManaged)
}

func (cmd command) exec(ctx context.Context, args []string, stdout, stderr io.Writer, prepare PrepareFunc, backend BackendFunc) int {
	name := program + " " + cmd.name

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	confirm := fs.Bool("confirm", false, cmd.confirm)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [-confirm]\n\n%s\n\nFlags:\n", name, cmd.summary)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage // Parse has printed the problem and the usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", name, fs.Arg(0))
		return ExitUsage
	}

	fail := func(err error) int {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return ExitFailure
	}
	if prepare == nil || backend == nil {
		return fail(errors.New("the command line needs both a PrepareFunc and a BackendFunc"))
	}

	app, err := prepare()
	if err != nil {
		return fail(err)
	}
	if app == nil {
		return fail(errors.New("the PrepareFunc returned no application"))
	}
	// Asked before the database is opened: the answer needs no connection.
	if reason := cmd.refuse(app.Migration.Path); reason != "" {
		return fail(errors.New(reason))
	}

	be, err := backend(ctx, app)
	if err != nil {
		return fail(err)
	}
	if be.Close != nil {
		defer be.Close()
	}

	res, err := cmd.run(ctx, app.Migration, app.Declared(), be, migration.RunOptions{
		Confirm: *confirm,
		// The managed path's warnings (a script that could not be written, a
		// driver that is not fully atomic) are lines on stderr. No audit
		// recorder is set, so an applied migration writes no audit event
		// here: the audit table may be the one this migration creates.
		Telemetry: telemetry.New(telemetry.NewTextLogger(stderr, slog.LevelWarn), nil, nil),
	})
	if err != nil {
		code := fail(err)
		if errs.IsCode(err, errs.CodeMigrationUnresolvedIssues) {
			fmt.Fprintf(stderr, "Answer the open questions in %s, then run the command again.\n", migration.DraftPath(app.Migration))
		}
		return code
	}

	report(ctx, stdout, app.Migration, res)
	return ExitOK
}

// report prints a run's outcome: core's message, the operations of the
// migration it concerns, and a pointer to the draft when answers were read
// from it.
func report(ctx context.Context, w io.Writer, cfg migration.MigrationConfig, res *migration.RunResult) {
	fmt.Fprintln(w, res.Message)

	if m := res.Migration; m != nil && len(m.Up) > 0 {
		fmt.Fprintf(w, "\n%s, %d operation(s):\n", m.ID, len(m.Up))
		for _, op := range m.Up {
			fmt.Fprintf(w, "  %s\n", describe(op))
		}
	}

	// Planning answers each new question with its default, which leaves the
	// change behind it out of the migration. This line is how the developer
	// learns that an answer exists. Showing the questions themselves needs
	// the draft's format, which core does not export yet.
	draft := migration.DraftPath(cfg)
	if answers, err := migration.NewFilePresenter(draft).Collect(ctx); err == nil && len(answers) > 0 {
		fmt.Fprintf(w, "\n%d answer(s) were read from %s. A new question starts with its default answer, which changes nothing. Edit the file and run the command again to choose another.\n",
			len(answers), draft)
	}
}

// describe is one operation as a line of the report.
func describe(op migration.SchemaOperation) string {
	switch op.Kind {
	case migration.OpCreateTable:
		return "create table " + op.Table
	case migration.OpDropTable:
		return "drop table " + op.Table
	case migration.OpAddColumn:
		return "add column " + op.Table + "." + columnName(op)
	case migration.OpAlterColumn:
		return "alter column " + op.Table + "." + columnName(op)
	case migration.OpDropColumn:
		return "drop column " + op.Table + "." + op.ColumnName
	case migration.OpRenameColumn:
		return "rename column " + op.Table + "." + op.ColumnName + " to " + op.NewColumnName
	case migration.OpAddIndex:
		if op.Index != nil {
			return "add index " + op.Index.Name + " on " + op.Table
		}
	case migration.OpDropIndex:
		return "drop index " + op.IndexName + " on " + op.Table
	case migration.OpAddForeignKey:
		if op.ForeignKey != nil {
			return "add foreign key " + op.ForeignKey.Name + " on " + op.Table
		}
	case migration.OpDropForeignKey:
		return "drop foreign key " + op.ForeignKeyName + " on " + op.Table
	}
	return string(op.Kind) + " " + op.Table
}

func columnName(op migration.SchemaOperation) string {
	if op.Column != nil {
		return op.Column.Name
	}
	return op.ColumnName
}
