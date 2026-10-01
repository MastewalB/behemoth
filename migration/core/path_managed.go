package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/schema"
)

type RunState string

const (
	StateFirstRunEmpty                   RunState = "first_run_empty"
	StateFirstRunAwaitingBaselineConfirm RunState = "first_run_awaiting_confirm"
	StateOngoing                         RunState = "ongoing"
)

type RunStatus string

const (
	StatusApplied              RunStatus = "applied"
	StatusAwaitingConfirmation RunStatus = "awaiting_confirmation"
	StatusNoChanges            RunStatus = "no_changes"
)

type RunResult struct {
	Status    RunStatus
	Migration *Migration
	Message   string // CLI-ready human text; not meant to be parsed
}

// RunMigration is the complete Path I entry point — handles BOTH greenfield
// (no baseline candidates, falls straight into RunGenerate) and brownfield
// (baseline runs first, then RunGenerate) cases. Superseded name for what
// was RunBaseline, since it's no longer baseline-specific.
func RunMigration(
	ctx context.Context,
	cfg MigrationConfig,
	declared Declared,
	deps MigrationDeps,
	confirmApply bool,
) (*RunResult, error) {
	if err := EnsureMigrationFolder(cfg); err != nil {
		return nil, err
	}
	state, disk, err := DetermineRunState(ctx, cfg, deps)
	if err != nil {
		return nil, err // both unhandled edge cases surface here, as a clear abort
	}

	switch state {
	case StateFirstRunEmpty:
		return runFirstTimeEmpty(ctx, cfg, declared, deps, confirmApply)
	case StateFirstRunAwaitingBaselineConfirm:
		return runFirstTimeAwaitingConfirm(ctx, cfg, declared, deps, disk[0], confirmApply)
	case StateOngoing:
		return runOngoing(ctx, cfg, declared, deps, confirmApply)
	default:
		return nil, behemotherr.NewInternalError("Migration.RunMigration", fmt.Errorf("unhandled run state %q", state))
	}
}

func buildBaselineMigrationOnly(ctx context.Context, candidates []BaselineCandidate, deps MigrationDeps) (*Migration, error) {
	report, err := RunIntrospection(ctx, registryFromCandidates(candidates), deps.Introspector, true)
	if err != nil {
		return nil, err
	}
	if err := RejectAmbiguousTypes(report); err != nil {
		return nil, err
	}
	tables := map[string]schema.Table{}
	for table, ti := range report.Tables {
		if ti.IncompatibleObject {
			return nil, behemotherr.NewMigrationError("Baseline.Build", behemotherr.ErrorCodeMigrationIncompatibleObject,
				fmt.Errorf("table %q exists live as a non-table object; resolve manually before baselining", table))
		}
		tables[table] = introspectedShape(ti)
	}
	m := BuildBaselineMigration(tables)
	return &m, nil
}

func runBaselinePhase(ctx context.Context, candidates []BaselineCandidate, cfg MigrationConfig, deps MigrationDeps) (*Migration, error) {

	m, err := buildBaselineMigrationOnly(ctx, candidates, deps)
	if err != nil {
		return nil, err
	}
	if err := writeMigrationFile(cfg, *m); err != nil {
		return nil, err
	}
	return m, nil
}

func runFirstTimeEmpty(
	ctx context.Context,
	cfg MigrationConfig,
	declared Declared,
	deps MigrationDeps,
	confirmApply bool,
) (*RunResult, error) {
	candidates, _, err := PartitionForBaseline(ctx, declared.Schemas, deps.Introspector)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		// Falls straight into ordinary generation instead of forcing an empty confirmation round-trip.
		return runOngoing(ctx, cfg, declared, deps, confirmApply)
	}

	baseline, err := runBaselinePhase(ctx, candidates, cfg, deps)
	if err != nil {
		return nil, err
	}
	return &RunResult{
		Status:    StatusAwaitingConfirmation,
		Migration: baseline,
		Message:   fmt.Sprintf("Baseline migration written to %s. Review it, then re-run with --confirm to record it.", migrationFilePath(cfg, *baseline)),
	}, nil
}

func runFirstTimeAwaitingConfirm(
	ctx context.Context,
	cfg MigrationConfig,
	declared Declared,
	deps MigrationDeps,
	existing Migration,
	confirmApply bool,
) (*RunResult, error) {
	candidates, _, err := PartitionForBaseline(ctx, declared.Schemas, deps.Introspector)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, behemotherr.NewMigrationError("Migration.RunFirstTime", behemotherr.ErrorCodeMigrationBaselineCandidatesVanished,
			fmt.Errorf("no baseline candidate tables found live, but %s is on disk awaiting confirmation — resolve manually", existing.ID))
	}

	regenerated, err := buildBaselineMigrationOnly(ctx, candidates, deps)
	if err != nil {
		return nil, err
	}

	if !migrationsEqual(existing, *regenerated) {
		// Live schema drifted since the draft was written — never apply a
		// stale review. Overwrite and require review again.
		if err := writeMigrationFile(cfg, *regenerated); err != nil {
			return nil, err
		}
		return &RunResult{
			Status:    StatusAwaitingConfirmation,
			Migration: regenerated,
			Message:   fmt.Sprintf("Live schema changed since the baseline draft was written. %s has been regenerated — please review again.", regenerated.ID),
		}, nil
	}

	if !confirmApply {
		return &RunResult{
			Status:    StatusAwaitingConfirmation,
			Migration: &existing,
			Message:   fmt.Sprintf("Baseline migration %s is unchanged and ready. Re-run with --confirm to apply.", existing.ID),
		}, nil
	}
	if err := applyWithDDL(ctx, cfg, deps, existing); err != nil {
		return nil, err
	}
	return &RunResult{
		Status:    StatusApplied,
		Migration: &existing,
		Message:   fmt.Sprintf("Baseline migration %s applied.", existing.ID),
	}, nil
}

func runOngoing(
	ctx context.Context,
	cfg MigrationConfig,
	declared Declared,
	deps MigrationDeps,
	confirmApply bool,
) (*RunResult, error) {
	disk, err := ReadDiskMigrations(cfg)
	if err != nil {
		return nil, err
	}

	// Reusing Runner.Pending (dependency-ordered, ledger-diffed) rather than
	// a naive "compare snapshot.Version to the last file" check — more
	// robust if history is ever non-linear, and avoids duplicating logic
	// Runner already owns correctly.
	pending, err := deps.Runner.Pending(ctx, disk)
	if err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		if len(pending) > 1 {
			// Should be structurally impossible through this entry point —
			// generation is gated (checkNoUnappliedMigrations) to refuse
			// producing a new file while one is pending. Surfaced rather
			// than silently assumed away if it ever happens anyway.
			return nil, behemotherr.NewMigrationError("Migration.RunOngoing", behemotherr.ErrorCodeMigrationMultipleUnapplied,
				fmt.Errorf("%d unapplied migrations found — expected at most one; resolve manually", len(pending)))
		}
		next := pending[0]
		if !confirmApply {
			return &RunResult{Status: StatusAwaitingConfirmation, Migration: &next,
				Message: fmt.Sprintf("Migration %s is pending review. Re-run with --confirm to apply.", next.ID)}, nil
		}
		if err := applyWithDDL(ctx, cfg, deps, next); err != nil {
			return nil, err
		}
		return &RunResult{
			Status:    StatusApplied,
			Migration: &next,
			Message:   fmt.Sprintf("Migration %s applied.", next.ID),
		}, nil
	}

	// Nothing pending — safe to generate a new one. Resolution's own
	// interactive review (renames, narrowing alters) still runs INSIDE
	// RunGenerate; that is a separate, inner confirmation layer from the
	// outer confirmApply gate this function enforces.
	m, err := RunGenerate(ctx, cfg, declared, deps.GenerateDeps, true)
	if err != nil {
		if behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationNothingToGenerate) {
			return &RunResult{Status: StatusNoChanges, Message: "No schema changes detected."}, nil
		}
		return nil, err
	}
	// [Design fork, resolved conservatively] confirmApply does NOT
	// short-circuit generate-then-apply in one call, even if it's already
	// true — a brand-new, unreviewed file always requires a separate
	// invocation before it can be applied, same as Branch A/B. This trades
	// a faster one-shot path for a strictly enforced "every file survives
	// at least one review round-trip" guarantee. Flagging in case a
	// single-shot mode is actually wanted — that would be a deliberate,
	// separate opt-in flag, not a side effect of confirmApply.
	return &RunResult{Status: StatusAwaitingConfirmation, Migration: m,
		Message: fmt.Sprintf("Migration %s written to %s. Review it, then re-run with --confirm to apply.", m.ID, migrationFilePath(cfg, *m))}, nil
}

// applyWithDDL applies m and writes its script next to its .json file.
//
// The script is rendered BEFORE Apply — some renderers derive statements from
// the live schema, which must still be in its pre-migration state — but only
// written AFTER Apply succeeds, so a script only ever exists for a migration
// that actually ran. Rendering and writing are both non-fatal: once Apply has
// committed, a missing script must not be reported as if the migration failed.
func applyWithDDL(ctx context.Context, cfg MigrationConfig, deps MigrationDeps, m Migration) error {
	ddl, renderErr := renderMigrationDDL(ctx, m, deps.GenerateDeps.Renderer)

	if err := deps.Runner.Apply(ctx, []Migration{m}); err != nil {
		return err
	}

	if renderErr != nil {
		warn(ctx, deps.Telemetry, "failed to render migration script", behemoth.M{"id": m.ID, "error": renderErr.Error()})
		return nil
	}
	if err := ddl.write(cfg, m); err != nil {
		warn(ctx, deps.Telemetry, "failed to write migration script", behemoth.M{"id": m.ID, "error": err.Error()})
	}
	return nil
}

func warn(ctx context.Context, tel *types.Telemetry, msg string, fields behemoth.M) {
	if tel != nil && tel.Logger != nil {
		tel.Logger.Warn(ctx, msg, fields)
	}
}

// DetermineRunState
func DetermineRunState(ctx context.Context, cfg MigrationConfig, deps MigrationDeps) (RunState, []Migration, error) {
	tableExists, err := deps.Introspector.TableExists(ctx, LedgerCanonicalName)
	if err != nil {
		return "", nil, err
	}

	disk, err := ReadDiskMigrations(cfg)
	if err != nil {
		return "", nil, err
	}

	switch {
	case !tableExists && len(disk) == 0:
		return StateFirstRunEmpty, disk, nil
	case !tableExists && len(disk) == 1 && disk[0].IsBaseline:
		return StateFirstRunAwaitingBaselineConfirm, disk, nil
	case !tableExists:
		// Edge case: "folder has multiple migration files but no table"
		// NOT handled. There is no safe way to guess whether these files
		// were partially applied by hand, generated by a different process,
		// or simply never run.
		return "", disk, behemotherr.NewMigrationError("Migration.DetermineRunState", behemotherr.ErrorCodeMigrationUnappliedNoLedger,
			fmt.Errorf("%d migration file(s) found in %q but no migrations table exists — cannot determine a safe starting point; resolve manually", len(disk), cfg.FolderPath))
	case len(disk) == 0:
		// Edge case: "table exists (with snapshot) but no folder"
		// NOT handled. The ledger/snapshot has real history the folder can't
		// reconstruct; regenerating from here risks silently redoing work.
		return "", disk, behemotherr.NewMigrationError("Migration.DetermineRunState", behemotherr.ErrorCodeMigrationLedgerWithoutFiles,
			fmt.Errorf("a migrations table exists but no migration files were found in %q — cannot reconstruct history; resolve manually", cfg.FolderPath))

	default:
		return StateOngoing, disk, nil
	}

}

func BuildBaselineMigration(tables map[string]schema.Table) Migration {
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names) // Required for Migration equality check performed later. A mere map-iteration order is non-deterministic

	var up []SchemaOperation

	for _, table := range names {
		ts := tables[table]
		bare := ts
		bare.ForeignKeys = nil // never inline, per checkNoInlineForeignKeys' invariant
		up = append(up, SchemaOperation{
			ID:        baselineTableID(table),
			Kind:      OpCreateTable,
			Table:     table,
			NewTable:  &bare,
			Confirmed: true,
		})

		for _, idx := range ts.Indexes {
			up = append(up, SchemaOperation{
				ID:        baselineIndexID(table, idx.Name),
				Kind:      OpAddIndex,
				Table:     table,
				Index:     &idx,
				Confirmed: true,
			})
		}

		for _, fk := range ts.ForeignKeys {
			up = append(up, SchemaOperation{
				ID:         baselineForeignKeyID(table, fk.Name),
				Kind:       OpAddForeignKey,
				Table:      table,
				ForeignKey: &fk,
				Confirmed:  true,
			})
		}
	}

	return Migration{
		ID:         "0000_baseline",
		Name:       "baseline",
		Up:         up,
		Down:       nil,
		IsBaseline: true,
		CreatedAt:  time.Now(),
	}
}

func ReadDiskMigrations(cfg MigrationConfig) ([]Migration, error) {
	entries, err := os.ReadDir(cfg.FolderPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, behemotherr.NewMigrationError("Migration.ReadDiskMigrations", behemotherr.ErrorCodeMigrationReadDirFailed, err)
	}

	var migrations []Migration
	for _, e := range entries {
		if e.IsDir() || !migrationFilePattern.MatchString(e.Name()) {
			continue // non-matching files ignored, same "unrelated file" rule used everywhere else in this pillar
		}
		b, err := os.ReadFile(filepath.Join(cfg.FolderPath, e.Name()))
		if err != nil {
			return nil, behemotherr.NewMigrationError("Migration.ReadDiskMigrations", behemotherr.ErrorCodeMigrationReadFileFailed, err)
		}
		var m Migration
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, behemotherr.NewMigrationError("Migration.ReadDiskMigrations", behemotherr.ErrorCodeMigrationUnmarshalFailed, fmt.Errorf("%s: %w", e.Name(), err))
		}
		migrations = append(migrations, m)
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].ID < migrations[j].ID })
	return migrations, nil
}

func migrationFilePath(cfg MigrationConfig, m Migration) string {
	return filepath.Join(cfg.FolderPath, m.ID+"_"+m.Name+".json")
}

func registryFromCandidates(candidates []BaselineCandidate) schema.Registry {
	r := &snapshotRegistry{tables: map[string]schema.Table{}}
	for _, c := range candidates {
		r.tables[c.Table] = c.Current
	}
	return r
}

func introspectedShape(ti TableIntrospection) schema.Table {
	var cols []schema.Column
	var indexes []schema.Index
	var fks []schema.ForeignKey

	// A matching column records its declaration, not the live column: the
	// two only match up to driver normalization (ColumnNormalizer), and every
	// later snapshot diff compares declarations with what is recorded here.
	// Recording the live shape would make a normalized column (e.g. a blob
	// read back as bytes) differ on every run after the baseline.
	for _, f := range ti.Columns {
		switch {
		case f.Kind == ColMatch && f.Declared != nil:
			cols = append(cols, *f.Declared)
		case f.Live != nil:
			cols = append(cols, *f.Live)
		}
	}

	for _, f := range ti.Indexes {
		if f.Live != nil {
			indexes = append(indexes, *f.Live)
		}
	}

	for _, f := range ti.ForeignKeys {
		if f.Live != nil {
			fks = append(fks, *f.Live)
		}
	}

	return schema.Table{
		Name:         ti.Table,
		PhysicalName: ti.Table,
		Columns:      cols,
		Indexes:      indexes,
		ForeignKeys:  fks,
	}
}

func migrationsEqual(a, b Migration) bool {
	ab, errA := json.Marshal(a.Up)
	bb, errB := json.Marshal(b.Up)
	return errA == nil && errB == nil && string(ab) == string(bb) // migration is built deterministically
}
