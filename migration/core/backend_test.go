package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

var runUsers = schema.Table{Name: "users", Columns: []schema.Column{
	{Name: "id", Type: schema.ColTypeString, Length: 36, PrimaryKey: true},
	{Name: "email", Type: schema.ColTypeString, Length: 255},
}}

// scriptRenderer renders every migration as the same one-line script.
type scriptRenderer struct{}

func (scriptRenderer) RenderMigration(context.Context, Migration) (string, error) {
	return "-- script\n", nil
}
func (scriptRenderer) FileExtension() string { return ".sql" }

// memoryDatabase is a database held in memory, so Generate and Migrate can be driven down
// the managed path without one. It is the introspector, the schema driver
// and, through ledgerReader, the database the runner reads the ledger from.
type memoryDatabase struct {
	live     map[string]schema.Table // tables that exist, by canonical name
	ledger   []MigrationLedgerEntry
	snapshot *SchemaSnapshot
	applied  []string // IDs given to ApplyMigration, in order
	recorded []string // IDs given to RecordBaseline, in order
}

func newMemoryDatabase(live ...schema.Table) *memoryDatabase {
	db := &memoryDatabase{live: map[string]schema.Table{}}
	for _, t := range live {
		db.live[t.Name] = t
	}
	return db
}

func (db *memoryDatabase) backend() Backend {
	return Backend{Introspector: db, Renderer: liveRenderer{db}, Driver: db, DB: ledgerReader{db: db}}
}

// liveRenderer renders like a driver that derives statements from the live
// schema: the script names the tables that exist when it is rendered.
type liveRenderer struct{ db *memoryDatabase }

func (r liveRenderer) RenderMigration(_ context.Context, m Migration) (string, error) {
	live := make([]string, 0, len(r.db.live))
	for name := range r.db.live {
		live = append(live, name)
	}
	slices.Sort(live)
	return fmt.Sprintf("-- %s, %d operation(s), against %v\n", m.ID, len(m.Up), live), nil
}
func (liveRenderer) FileExtension() string { return ".sql" }

// TableExists implements [SchemaIntrospector]. Like a real driver, the
// bookkeeping tables appear with the first migration that is recorded.
func (db *memoryDatabase) TableExists(_ context.Context, name string) (bool, error) {
	if name == LedgerCanonicalName || name == SnapshotCanonicalName {
		return len(db.ledger) > 0, nil
	}
	_, ok := db.live[name]
	return ok, nil
}

// Introspect implements [SchemaIntrospector].
func (db *memoryDatabase) Introspect(_ context.Context, name string) (IntrospectedTable, error) {
	t, ok := db.live[name]
	return IntrospectedTable{Schema: t, Kind: ObjectTable, Exists: ok}, nil
}

// ApplyMigration implements [SchemaDriver]: the operations change the live
// tables, and the ledger row and the snapshot are stored with them.
//
// Like the drivers, it creates a table from its columns alone. An index or a
// foreign key exists only once its own operation has run.
func (db *memoryDatabase) ApplyMigration(_ context.Context, req MigrationRequest) error {
	ops := make([]SchemaOperation, len(req.Migration.Up))
	for i, op := range req.Migration.Up {
		if op.Kind == OpCreateTable && op.NewTable != nil {
			bare := *op.NewTable
			bare.Indexes, bare.ForeignKeys = nil, nil
			op.NewTable = &bare
		}
		ops[i] = op
	}
	next, err := applyOperationsToSnapshot(db.live, ops)
	if err != nil {
		return err
	}
	db.live = next
	db.applied = append(db.applied, req.Migration.ID)
	db.record(req)
	return nil
}

// RecordBaseline implements [SchemaDriver]: bookkeeping only.
func (db *memoryDatabase) RecordBaseline(_ context.Context, req MigrationRequest) error {
	db.recorded = append(db.recorded, req.Migration.ID)
	db.record(req)
	return nil
}

func (db *memoryDatabase) record(req MigrationRequest) {
	db.ledger = append(db.ledger, req.LedgerEntry)
	snapshot := req.SnapshotUpdate
	db.snapshot = &snapshot
}

// AtomicityLevel implements [SchemaDriver].
func (db *memoryDatabase) AtomicityLevel() AtomicityLevel { return AtomicityFull }

// ledgerReader is a memoryDatabase as a behemoth.Database. The runner only
// reads through it, so the write methods are left to the nil interface.
type ledgerReader struct {
	behemoth.Database
	db *memoryDatabase
}

func (r ledgerReader) FindMany(context.Context, behemoth.Model, clause.Expression, *behemoth.QueryOptions) ([]behemoth.Model, error) {
	out := make([]behemoth.Model, len(r.db.ledger))
	for i := range r.db.ledger {
		entry := r.db.ledger[i]
		out[i] = &entry
	}
	return out, nil
}

func (r ledgerReader) FindOne(context.Context, behemoth.Model, clause.Expression) (behemoth.Model, error) {
	if r.db.snapshot == nil {
		return nil, behemotherr.NewNotFound("memoryDatabase.FindOne", "schema_snapshot", nil)
	}
	snapshot := *r.db.snapshot
	return &snapshot, nil
}

func migrationFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.Name() != draftFileName {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestGenerateAndMigrateRejectAnIncompleteSetup(t *testing.T) {
	reg := declaredRegistry(t, runUsers)
	introspector := fakeIntrospector{}

	for name, tc := range map[string]struct {
		path     MigrationPath
		declared Declared
		backend  Backend
	}{
		"no declared schema":                   {PathGenerateOnly, Declared{}, Backend{Introspector: introspector}},
		"no introspector":                      {PathGenerateOnly, Declared{Schemas: reg}, Backend{}},
		"managed without a driver":             {PathManaged, Declared{Schemas: reg}, Backend{Introspector: introspector, DB: ledgerReader{}}},
		"managed without a database":           {PathManaged, Declared{Schemas: reg}, Backend{Introspector: introspector, Driver: newMemoryDatabase()}},
		"a path that is neither of the two":    {"sideways", Declared{Schemas: reg}, Backend{Introspector: introspector}},
		"managed, generate-only backend alone": {PathManaged, Declared{Schemas: reg}, Backend{Introspector: introspector, Renderer: scriptRenderer{}}},
	} {
		for entry, call := range map[string]func(context.Context, MigrationConfig, Declared, Backend, RunOptions) (*RunResult, error){
			"Generate": Generate, "Migrate": Migrate,
		} {
			dir := filepath.Join(t.TempDir(), "migrations")
			_, err := call(context.Background(), MigrationConfig{FolderPath: dir, Path: tc.path}, tc.declared, tc.backend, RunOptions{Confirm: true})
			if !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
				t.Errorf("%s, %s: err = %v, want a configuration error", entry, name, err)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Errorf("%s, %s: the migrations folder was created before the setup was checked", entry, name)
			}
		}
	}
}

// An application that asked for files only applies them with its own tool.
func TestMigrateRefusesTheGenerateOnlyPath(t *testing.T) {
	db := newMemoryDatabase()
	dir := filepath.Join(t.TempDir(), "migrations")
	_, err := Migrate(context.Background(), MigrationConfig{FolderPath: dir}, Declared{Schemas: declaredRegistry(t, runUsers)}, db.backend(), RunOptions{Confirm: true})
	if !behemotherr.Is(err, behemotherr.CategoryConfiguration) || len(db.applied) != 0 {
		t.Errorf("err = %v, applied = %v; want a configuration error and nothing applied", err, db.applied)
	}
}

// The entry points Generate and Migrate choose between used to trust the
// caller's choice:
// RunGenerateCLI on a managed configuration dereferenced the nil Runner.
func TestEntryPointsRejectAnotherPath(t *testing.T) {
	ctx := context.Background()
	declared := Declared{Schemas: declaredRegistry(t, runUsers)}
	dir := filepath.Join(t.TempDir(), "migrations")

	managed := NewMigrationConfig(MigrationConfig{FolderPath: dir, Path: PathManaged})
	_, err := RunGenerateCLI(ctx, managed, declared, GenerateDeps{
		Introspector: fakeIntrospector{},
		Presenter:    NewFilePresenter(DraftPath(managed)),
		Generator:    &DefaultMigrationGenerator{},
	}, true)
	if !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Errorf("RunGenerateCLI on a managed configuration: err = %v, want a configuration error", err)
	}

	db := newMemoryDatabase()
	generateOnly := NewMigrationConfig(MigrationConfig{FolderPath: dir})
	runner := NewMigrationRunner(ledgerReader{db: db}, db, generateOnly, nil)
	for name, call := range map[string]func(context.Context, MigrationConfig, Declared, MigrationDeps, bool) (*RunResult, error){
		"RunManagedGenerate": RunManagedGenerate, "RunManagedApply": RunManagedApply,
	} {
		_, err = call(ctx, generateOnly, declared, MigrationDeps{Introspector: db, Runner: runner}, true)
		if !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
			t.Errorf("%s on a generate-only configuration: err = %v, want a configuration error", name, err)
		}
	}
	if len(db.applied) > 0 {
		t.Errorf("applied %v for an application that asked for files only", db.applied)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Error("an entry point created the migrations folder before it refused")
	}
}

func TestGenerateOnThePathWithoutALedger(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "migrations")
	cfg := MigrationConfig{FolderPath: dir} // Path left empty: generate only, as NewMigrationConfig defaults it
	declared := Declared{Schemas: declaredRegistry(t, runUsers)}
	db := newMemoryDatabase()
	backend := Backend{Introspector: db, Renderer: scriptRenderer{}}

	// Without Confirm: the migration is reported and nothing is written.
	res, err := Generate(ctx, cfg, declared, backend, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusAwaitingConfirmation || res.Migration == nil || len(res.Migration.Up) != 1 {
		t.Fatalf("preview: status = %s, migration = %+v; want awaiting confirmation with one operation", res.Status, res.Migration)
	}
	if files := migrationFiles(t, dir); len(files) != 0 {
		t.Fatalf("preview wrote %v", files)
	}

	// With Confirm: the .json and the script are written.
	res, err = Generate(ctx, cfg, declared, backend, RunOptions{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusGenerated {
		t.Fatalf("confirm: status = %s, want %s", res.Status, StatusGenerated)
	}
	for _, name := range []string{"0001_create_users.json", "0001_create_users.sql"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("confirm: %s was not written: %v", name, err)
		}
	}

	// The application's own tool applies the script. Once the table is
	// live, there is nothing left to generate.
	db.live[runUsers.Name] = runUsers
	res, err = Generate(ctx, cfg, declared, backend, RunOptions{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNoChanges {
		t.Errorf("after applying: status = %s, want %s", res.Status, StatusNoChanges)
	}
}

// The tests below drive the managed path through Generate and Migrate. The
// runner they build reads the ledger through Backend.DB and records through
// Backend.Driver.

// managedRun is one application on the managed path and its database.
type managedRun struct {
	t        *testing.T
	cfg      MigrationConfig
	declared Declared
	db       *memoryDatabase
}

func (r managedRun) generate(confirm bool) *RunResult {
	r.t.Helper()
	res, err := Generate(context.Background(), r.cfg, r.declared, r.db.backend(), RunOptions{Confirm: confirm})
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func (r managedRun) migrate(confirm bool) *RunResult {
	r.t.Helper()
	res, err := Migrate(context.Background(), r.cfg, r.declared, r.db.backend(), RunOptions{Confirm: confirm})
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func newManagedRun(t *testing.T, db *memoryDatabase, tables ...schema.Table) managedRun {
	return managedRun{
		t:        t,
		cfg:      MigrationConfig{FolderPath: filepath.Join(t.TempDir(), "migrations"), Path: PathManaged},
		declared: Declared{Schemas: declaredRegistry(t, tables...)},
		db:       db,
	}
}

// A new database, from the first migration to a database that matches.
func TestManagedNewDatabase(t *testing.T) {
	db := newMemoryDatabase()
	r := newManagedRun(t, db, planAuthors, planBooks)

	// Nothing is written yet, so there is nothing to apply.
	if res := r.migrate(true); res.Status != StatusNoChanges {
		t.Fatalf("migrate before generate: status = %s, want %s", res.Status, StatusNoChanges)
	}

	// generate shows the migration, and writes it once confirmed. Neither
	// touches the database.
	if res := r.generate(false); res.Status != StatusAwaitingConfirmation || len(migrationFiles(t, r.cfg.FolderPath)) != 0 {
		t.Fatalf("generate: status = %s, files = %v; want a preview and no file", res.Status, migrationFiles(t, r.cfg.FolderPath))
	}
	if res := r.generate(true); res.Status != StatusGenerated {
		t.Fatalf("generate, confirmed: status = %s, want %s", res.Status, StatusGenerated)
	}
	// The script is written with the migration, for the review.
	if files := migrationFiles(t, r.cfg.FolderPath); !slices.Equal(files, []string{"0001_create_authors_books.json", "0001_create_authors_books.sql"}) || len(db.live) != 0 || len(db.applied) != 0 {
		t.Fatalf("after generate: files = %v, live tables = %d, applied = %v; want the migration, its script and an untouched database", files, len(db.live), db.applied)
	}

	// While it is unapplied, generate writes no second migration.
	if res := r.generate(true); res.Status != StatusAwaitingConfirmation || len(migrationFiles(t, r.cfg.FolderPath)) != 2 {
		t.Fatalf("generate with one pending: status = %s, files = %v; want it to wait", res.Status, migrationFiles(t, r.cfg.FolderPath))
	}

	// migrate shows what it would apply, and applies it once confirmed. The
	// ledger table does not exist before this.
	if res := r.migrate(false); res.Status != StatusAwaitingConfirmation || len(db.applied) != 0 {
		t.Fatalf("migrate: status = %s, applied = %v; want it to wait", res.Status, db.applied)
	}
	if res := r.migrate(true); res.Status != StatusApplied || !slices.Equal(db.applied, []string{"0001"}) {
		t.Fatalf("migrate, confirmed: status = %s, applied = %v; want 0001 applied", res.Status, db.applied)
	}
	if got := db.live[planBooks.Name]; len(got.Indexes) != 1 || len(got.ForeignKeys) != 1 {
		t.Errorf("books: %d index(es), %d foreign key(s); want one of each", len(got.Indexes), len(got.ForeignKeys))
	}

	// Both are done.
	if res := r.migrate(true); res.Status != StatusNoChanges {
		t.Errorf("migrate again: status = %s, want %s", res.Status, StatusNoChanges)
	}
	if res := r.generate(true); res.Status != StatusNoChanges {
		t.Errorf("generate again: status = %s, want %s", res.Status, StatusNoChanges)
	}
}

// A database that already holds a declared table: its first migration is a
// baseline, which is recorded and not executed.
func TestManagedExistingDatabase(t *testing.T) {
	db := newMemoryDatabase(runUsers)
	r := newManagedRun(t, db, runUsers)

	if res := r.generate(false); res.Status != StatusAwaitingConfirmation || !res.Migration.IsBaseline || len(migrationFiles(t, r.cfg.FolderPath)) != 0 {
		t.Fatalf("generate: status = %s, migration = %+v; want a baseline shown and not written", res.Status, res.Migration)
	}
	if res := r.generate(true); res.Status != StatusGenerated || !slices.Equal(migrationFiles(t, r.cfg.FolderPath), []string{"0000_baseline.json", "0000_baseline.sql"}) {
		t.Fatalf("generate, confirmed: status = %s, files = %v; want 0000_baseline.json and its script", res.Status, migrationFiles(t, r.cfg.FolderPath))
	}
	// Written and unchanged: generate has nothing more to do.
	if res := r.generate(true); res.Status != StatusAwaitingConfirmation {
		t.Fatalf("generate again: status = %s, want it to wait for migrate", res.Status)
	}

	if res := r.migrate(false); res.Status != StatusAwaitingConfirmation || len(db.recorded) != 0 {
		t.Fatalf("migrate: status = %s, recorded = %v; want it to wait", res.Status, db.recorded)
	}
	if res := r.migrate(true); res.Status != StatusApplied || !slices.Equal(db.recorded, []string{"0000"}) || len(db.applied) != 0 {
		t.Fatalf("migrate, confirmed: status = %s, recorded = %v, applied = %v; want the baseline recorded only", res.Status, db.recorded, db.applied)
	}
	if db.snapshot == nil || len(db.snapshot.Tables) != 1 {
		t.Errorf("snapshot = %+v, want the users table", db.snapshot)
	}

	// The baseline equals the declaration, so nothing follows it.
	if res := r.generate(true); res.Status != StatusNoChanges {
		t.Fatalf("generate after the baseline: status = %s, want %s", res.Status, StatusNoChanges)
	}

	// A change to the declaration becomes the migration after the baseline.
	wider := runUsers
	wider.Columns = append(append([]schema.Column(nil), runUsers.Columns...), schema.Column{Name: "nickname", Type: schema.ColTypeString, Length: 64, Nullable: true})
	r.declared = Declared{Schemas: declaredRegistry(t, wider)}
	res := r.generate(true)
	if res.Status != StatusGenerated || res.Migration.ID != "0001" || !slices.Equal(res.Migration.DependsOn, []string{"0000"}) {
		t.Fatalf("after a change: status = %s, migration %s depending on %v; want 0001 after 0000", res.Status, res.Migration.ID, res.Migration.DependsOn)
	}
	if res := r.migrate(true); res.Status != StatusApplied || !slices.Equal(db.applied, []string{"0001"}) || len(db.live[runUsers.Name].Columns) != 3 {
		t.Errorf("migrate: status = %s, applied = %v, columns = %d; want 0001 applied", res.Status, db.applied, len(db.live[runUsers.Name].Columns))
	}
}

// A baseline is a record of the database as it was reviewed. When the
// database changes before it is recorded, migrate refuses it and generate
// writes it again.
func TestManagedBaselineThatWentStale(t *testing.T) {
	db := newMemoryDatabase(runUsers)
	r := newManagedRun(t, db, runUsers)
	r.generate(true)

	live := db.live[runUsers.Name]
	live.Columns = append(append([]schema.Column(nil), live.Columns...), schema.Column{Name: "legacy", Type: schema.ColTypeText, Nullable: true})
	db.live[runUsers.Name] = live

	if res := r.migrate(true); res.Status != StatusAwaitingConfirmation || len(db.recorded) != 0 {
		t.Fatalf("migrate: status = %s, recorded = %v; want the stale baseline refused", res.Status, db.recorded)
	}
	if res := r.generate(true); res.Status != StatusGenerated {
		t.Fatalf("generate: status = %s, want the baseline written again", res.Status)
	}
	if res := r.migrate(true); res.Status != StatusApplied || len(db.snapshot.Tables[runUsers.Name].Columns) != 3 {
		t.Errorf("migrate: status = %s, snapshot columns = %d; want the new baseline with the live column", res.Status, len(db.snapshot.Tables[runUsers.Name].Columns))
	}
}

// What is reviewed is the script generate wrote. When the database changes
// before migrate runs, a driver that reads the live schema renders the same
// operations differently, so migrate writes the script again and applies
// nothing until it is run again.
func TestManagedScriptThatWentStale(t *testing.T) {
	db := newMemoryDatabase()
	r := newManagedRun(t, db, runUsers)
	r.generate(true)
	script := filepath.Join(r.cfg.FolderPath, "0001_create_users.sql")
	reviewed, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}

	db.live["legacy"] = schema.Table{Name: "legacy"} // someone changed the database

	res := r.migrate(true)
	rewritten, _ := os.ReadFile(script)
	if res.Status != StatusAwaitingConfirmation || len(db.applied) != 0 || string(rewritten) == string(reviewed) {
		t.Fatalf("migrate: status = %s, applied = %v, script rewritten = %t; want nothing applied and the script written again",
			res.Status, db.applied, string(rewritten) != string(reviewed))
	}

	// Reviewed again and unchanged since: it is applied.
	if res := r.migrate(true); res.Status != StatusApplied || !slices.Equal(db.applied, []string{"0001"}) {
		t.Errorf("migrate again: status = %s, applied = %v; want 0001 applied", res.Status, db.applied)
	}

	// A migration file without a script, as from before generate wrote
	// one, is applied and gets its script then.
	wider := runUsers
	wider.Columns = append(append([]schema.Column(nil), runUsers.Columns...), schema.Column{Name: "nickname", Type: schema.ColTypeString, Length: 64, Nullable: true})
	r.declared = Declared{Schemas: declaredRegistry(t, wider)}
	r.generate(true)
	second := filepath.Join(r.cfg.FolderPath, "0002_add_column_users_nickname.sql")
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if res := r.migrate(true); res.Status != StatusApplied {
		t.Fatalf("migrate without a script on disk: status = %s, want %s", res.Status, StatusApplied)
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("the script was not written at apply: %v", err)
	}
}

// Several files without a ledger are not what generate leaves behind, and
// both entry points refuse them.
func TestManagedRefusesSeveralFilesWithoutALedger(t *testing.T) {
	db := newMemoryDatabase()
	r := newManagedRun(t, db, runUsers)
	r.cfg = NewMigrationConfig(r.cfg)
	if err := EnsureMigrationFolder(r.cfg); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"0001", "0002"} {
		if err := writeMigrationFile(r.cfg, Migration{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	for name, call := range map[string]func(context.Context, MigrationConfig, Declared, Backend, RunOptions) (*RunResult, error){
		"Generate": Generate, "Migrate": Migrate,
	} {
		_, err := call(context.Background(), r.cfg, r.declared, db.backend(), RunOptions{Confirm: true})
		if !behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationUnappliedNoLedger) || len(db.applied) != 0 {
			t.Errorf("%s: err = %v, applied = %v; want the run refused", name, err, db.applied)
		}
	}
}
