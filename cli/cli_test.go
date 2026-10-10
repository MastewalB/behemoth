package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/MastewalB/behemoth/types/schema"
)

// note is an application table, declared the way an application does it:
// in a function only its own build contains.
type note struct{}

func (note) SchemaName() string     { return "notes" }
func (note) PrimaryKeyName() string { return "id" }
func (note) PrimaryKeyField() any   { return nil }
func (note) New() behemoth.Model    { return note{} }

func declareNotes(reg schema.Registry) error {
	return reg.Declare(note{}, schema.Table{Name: "notes", Columns: []schema.Column{
		{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
		{Name: "body", Type: schema.ColTypeText},
	}})
}

// liveTables is the database: the tables that exist, by canonical name.
type liveTables map[string]schema.Table

func (l liveTables) TableExists(_ context.Context, name string) (bool, error) {
	_, ok := l[name]
	return ok, nil
}

func (l liveTables) Introspect(_ context.Context, name string) (core.IntrospectedTable, error) {
	t, ok := l[name]
	return core.IntrospectedTable{Schema: t, Kind: core.ObjectTable, Exists: ok}, nil
}

type scriptRenderer struct{}

func (scriptRenderer) RenderMigration(context.Context, core.Migration) (string, error) {
	return "-- script\n", nil
}
func (scriptRenderer) FileExtension() string { return ".sql" }

// fixture is an application and its database, as the two functions the
// command line is given.
type fixture struct {
	dir     string // the migrations folder
	path    core.MigrationPath
	live    liveTables
	ledger  []core.MigrationLedgerEntry
	version string // the snapshot's, set by the last applied migration
	tables  map[string]schema.Table
	opened  int // calls to the BackendFunc
	closed  int // calls to the backend's Close
	prepErr error
	openErr error
}

func (f *fixture) prepare() (*bmth.PreparedApp, error) {
	if f.prepErr != nil {
		return nil, f.prepErr
	}
	return bmth.Prepare(nil, bmth.PrepareConfig{
		Migration: core.MigrationConfig{FolderPath: f.dir, Path: f.path},
		Schema:    declareNotes,
	})
}

func (f *fixture) backend(context.Context, *bmth.PreparedApp) (core.Backend, error) {
	f.opened++
	if f.openErr != nil {
		return core.Backend{}, f.openErr
	}
	return core.Backend{
		Introspector: fixtureIntrospector{f},
		Renderer:     scriptRenderer{},
		Driver:       fixtureDriver{f},
		DB:           fixtureLedger{f: f},
		Close:        func() error { f.closed++; return nil },
	}, nil
}

// fixtureIntrospector adds the ledger table to the live ones: like a real
// driver's, it exists once a migration has been recorded.
type fixtureIntrospector struct{ f *fixture }

func (i fixtureIntrospector) TableExists(ctx context.Context, name string) (bool, error) {
	if name == core.LedgerCanonicalName {
		return len(i.f.ledger) > 0, nil
	}
	return i.f.live.TableExists(ctx, name)
}

func (i fixtureIntrospector) Introspect(ctx context.Context, name string) (core.IntrospectedTable, error) {
	return i.f.live.Introspect(ctx, name)
}

// fixtureDriver applies a migration by taking the tables the runner
// projected for the snapshot as the live ones.
type fixtureDriver struct{ f *fixture }

func (d fixtureDriver) ApplyMigration(_ context.Context, req core.MigrationRequest) error {
	for name, table := range req.SnapshotUpdate.Tables {
		d.f.live[name] = table
	}
	return d.RecordBaseline(context.Background(), req)
}

func (d fixtureDriver) RecordBaseline(_ context.Context, req core.MigrationRequest) error {
	d.f.ledger = append(d.f.ledger, req.LedgerEntry)
	d.f.version, d.f.tables = req.SnapshotUpdate.Version, req.SnapshotUpdate.Tables
	return nil
}

func (fixtureDriver) AtomicityLevel() core.AtomicityLevel { return core.AtomicityFull }

// fixtureLedger is what the runner reads: the ledger and the snapshot. It
// never writes through the database, so the rest is left to the nil
// interface.
type fixtureLedger struct {
	behemoth.Database
	f *fixture
}

func (l fixtureLedger) FindMany(context.Context, behemoth.Model, clause.Expression, *behemoth.QueryOptions) ([]behemoth.Model, error) {
	out := make([]behemoth.Model, len(l.f.ledger))
	for i := range l.f.ledger {
		entry := l.f.ledger[i]
		out[i] = &entry
	}
	return out, nil
}

func (l fixtureLedger) FindOne(context.Context, behemoth.Model, clause.Expression) (behemoth.Model, error) {
	if l.f.version == "" {
		return nil, behemotherr.NewNotFound("fixtureLedger.FindOne", "schema_snapshot", nil)
	}
	return &core.SchemaSnapshot{Version: l.f.version, Tables: l.f.tables}, nil
}

// run runs the command line against f and returns its exit code and output.
func (f *fixture) run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut, f.prepare, f.backend)
	return code, out.String(), errOut.String()
}

func newFixture(t *testing.T) *fixture {
	return &fixture{dir: filepath.Join(t.TempDir(), "migrations"), live: liveTables{}}
}

func TestUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		"no command":      {nil, ExitUsage, "", "Usage: behemoth <command>"},
		"help":            {[]string{"help"}, ExitOK, "Usage: behemoth <command>", ""},
		"-h":              {[]string{"-h"}, ExitOK, "generate", ""},
		"unknown command": {[]string{"deploy"}, ExitUsage, "", `unknown command "deploy"`},
		"unknown flag":    {[]string{"generate", "-force"}, ExitUsage, "", "flag provided but not defined"},
		"stray argument":  {[]string{"generate", "now"}, ExitUsage, "", `unexpected argument "now"`},
		"command help":    {[]string{"generate", "-h"}, ExitOK, "", "Usage: behemoth generate [-confirm]"},
		"migrate help":    {[]string{"migrate", "-h"}, ExitOK, "", "Usage: behemoth migrate [-confirm]"},
	} {
		f := newFixture(t)
		code, stdout, stderr := f.run(tc.args...)
		if code != tc.code {
			t.Errorf("%s: exit code = %d, want %d", name, code, tc.code)
		}
		if !strings.Contains(stdout, tc.inStdout) || !strings.Contains(stderr, tc.inStderr) {
			t.Errorf("%s: stdout = %q, stderr = %q; want %q and %q in them", name, stdout, stderr, tc.inStdout, tc.inStderr)
		}
		if f.opened != 0 {
			t.Errorf("%s: the database was opened", name)
		}
	}
}

func TestGenerateShowsThenWrites(t *testing.T) {
	f := newFixture(t)

	// Without -confirm: the migration is shown and nothing is written. It
	// holds the application's own table, which only its build declares.
	code, stdout, stderr := f.run("generate")
	if code != ExitOK {
		t.Fatalf("preview: exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{"create table notes", "create table users", "0001"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("preview: stdout lacks %q:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "0001_create_accounts_and_6_more.json")); !os.IsNotExist(err) {
		t.Fatalf("preview wrote the migration (stat error: %v)", err)
	}

	// With -confirm: the migration and its script are written.
	code, stdout, stderr = f.run("generate", "-confirm")
	if code != ExitOK {
		t.Fatalf("confirm: exit code = %d, stderr = %q", code, stderr)
	}
	for _, file := range []string{"0001_create_accounts_and_6_more.json", "0001_create_accounts_and_6_more.sql"} {
		if _, err := os.Stat(filepath.Join(f.dir, file)); err != nil {
			t.Errorf("confirm: %s was not written: %v\nstdout: %s", file, err, stdout)
		}
	}

	if f.opened != 2 || f.closed != 2 {
		t.Errorf("opened = %d, closed = %d; want the backend closed after each of the two runs", f.opened, f.closed)
	}
}

func TestGenerateWithNothingToDo(t *testing.T) {
	f := newFixture(t)
	app, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range app.Schemas.All() {
		f.live[table.Name] = table // the database already matches the declaration
	}

	code, stdout, stderr := f.run("generate", "-confirm")
	if code != ExitOK || !strings.Contains(stdout, "No schema changes") {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q; want no changes", code, stdout, stderr)
	}
}

// A narrowing change raises a question, and planning answers a new question
// with "leave as-is". The command says that an answer was read, so a run
// that reports no changes is not taken for a database that matches.
func TestGenerateSaysWhenAnswersWereRead(t *testing.T) {
	f := newFixture(t)
	app, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range app.Schemas.All() {
		if table.Name == "notes" {
			// The live column is wider than the declared one.
			cols := append([]schema.Column(nil), table.Columns...)
			cols[0].Length += 10
			table.Columns = cols
		}
		f.live[table.Name] = table
	}

	code, stdout, stderr := f.run("generate")
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	draft := filepath.Join(f.dir, "draft.json")
	if !strings.Contains(stdout, "1 answer(s) were read from "+draft) {
		t.Errorf("stdout does not point at the draft:\n%s", stdout)
	}
}

// The managed path: generate writes and leaves the database alone, migrate
// applies what generate wrote.
func TestGenerateThenMigrateOnTheManagedPath(t *testing.T) {
	f := newFixture(t)
	f.path = core.PathManaged

	code, stdout, stderr := f.run("generate", "-confirm")
	if code != ExitOK || !strings.Contains(stdout, "create table notes") {
		t.Fatalf("generate -confirm: exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "0001_create_accounts_and_6_more.json")); err != nil {
		t.Fatalf("generate -confirm wrote no migration: %v", err)
	}
	if len(f.ledger) != 0 || len(f.live) != 0 {
		t.Fatalf("generate changed the database: ledger = %v, %d live table(s)", f.ledger, len(f.live))
	}

	// Without -confirm, migrate names the migration and applies nothing.
	code, stdout, stderr = f.run("migrate")
	if code != ExitOK || !strings.Contains(stdout, "0001") || len(f.ledger) != 0 {
		t.Fatalf("migrate: exit code = %d, stdout = %q, stderr = %q, ledger = %v", code, stdout, stderr, f.ledger)
	}

	code, stdout, stderr = f.run("migrate", "-confirm")
	if code != ExitOK || len(f.ledger) != 1 || f.ledger[0].ID != "0001" {
		t.Fatalf("migrate -confirm: exit code = %d, stdout = %q, stderr = %q, ledger = %v", code, stdout, stderr, f.ledger)
	}
	if _, ok := f.live["notes"]; !ok {
		t.Error("migrate -confirm did not create the application's table")
	}

	if code, stdout, _ = f.run("migrate", "-confirm"); code != ExitOK || !strings.Contains(stdout, "Nothing to apply") {
		t.Errorf("migrate again: exit code = %d, stdout = %q", code, stdout)
	}
}

// An application that applies its migrations with its own tool has nothing
// for migrate to do, and learns that before its database is opened.
func TestMigrateRefusesTheGenerateOnlyPath(t *testing.T) {
	f := newFixture(t)

	code, _, stderr := f.run("migrate", "-confirm")
	if code != ExitFailure || !strings.Contains(stderr, `MigrationConfig.Path is "generate_only"`) || !strings.Contains(stderr, "behemoth generate") {
		t.Errorf("exit code = %d, stderr = %q; want a failure that names the path and the other command", code, stderr)
	}
	if f.opened != 0 {
		t.Error("the database was opened for a command that could not run")
	}
}

func TestGenerateReportsFailures(t *testing.T) {
	f := newFixture(t)
	f.prepErr = errors.New("plugin \"x\" Declare failed")
	if code, _, stderr := f.run("generate"); code != ExitFailure || !strings.Contains(stderr, "Declare failed") {
		t.Errorf("failing Prepare: exit code = %d, stderr = %q", code, stderr)
	}

	f = newFixture(t)
	f.openErr = errors.New("connection refused")
	if code, _, stderr := f.run("generate"); code != ExitFailure || !strings.Contains(stderr, "connection refused") {
		t.Errorf("failing BackendFunc: exit code = %d, stderr = %q", code, stderr)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"generate"}, &out, &errOut, nil, nil); code != ExitFailure {
		t.Errorf("no functions: exit code = %d, want %d", code, ExitFailure)
	}
}

func TestDescribe(t *testing.T) {
	for want, op := range map[string]core.SchemaOperation{
		"create table users":             {Kind: core.OpCreateTable, Table: "users"},
		"add column users.plan":          {Kind: core.OpAddColumn, Table: "users", Column: &schema.Column{Name: "plan"}},
		"alter column users.name":        {Kind: core.OpAlterColumn, Table: "users", Column: &schema.Column{Name: "name"}},
		"drop column users.plan":         {Kind: core.OpDropColumn, Table: "users", ColumnName: "plan"},
		"rename column users.a to b":     {Kind: core.OpRenameColumn, Table: "users", ColumnName: "a", NewColumnName: "b"},
		"add index idx on users":         {Kind: core.OpAddIndex, Table: "users", Index: &schema.Index{Name: "idx"}},
		"drop index idx on users":        {Kind: core.OpDropIndex, Table: "users", IndexName: "idx"},
		"add foreign key fk on sessions": {Kind: core.OpAddForeignKey, Table: "sessions", ForeignKey: &schema.ForeignKey{Name: "fk"}},
		"drop foreign key fk on users":   {Kind: core.OpDropForeignKey, Table: "users", ForeignKeyName: "fk"},
		"drop table users":               {Kind: core.OpDropTable, Table: "users"},
		"add_index users":                {Kind: core.OpAddIndex, Table: "users"}, // a malformed operation still gets a line
	} {
		if got := describe(op); got != want {
			t.Errorf("describe(%s) = %q, want %q", op.Kind, got, want)
		}
	}
}
