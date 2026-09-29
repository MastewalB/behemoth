package core

import (
	"context"
	"fmt"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

const StatusGenerated RunStatus = "generated" // Path II's terminal state - file written

// RunGenerateCLI is Path II's CLI-facing entry point.
// NOTE, unlike Path I's baseline branch: no regenerate-and-compare
// staleness check is needed here. Path I's baseline needed one because
// RecordBaseline permanently freezes introspected reality into history — a
// stale review would poison that history. Path II's ordinary generate has
// no such permanence: re-running it always reflects current live/canonical
// truth fresh, so a drift between the preview call and the confirm call
// self-corrects automatically rather than needing to be detected.
func RunGenerateCLI(ctx context.Context, cfg MigrationConfig, current SchemaRegistry, deps GenerateDeps, confirmWrite bool) (*RunResult, error) {
	m, err := buildMigrationPlan(ctx, cfg, current, deps, true)
	if err != nil {
		if behemotherr.IsCode(err, "nothing_to_generate") {
			return &RunResult{Status: StatusNoChanges, Message: "No schema changes detected."}, nil
		}
		return nil, err
	}

	if !confirmWrite {
		return &RunResult{
			Status:    StatusAwaitingConfirmation,
			Migration: m,
			Message:   fmt.Sprintf("Migration %s ready (not yet written). Re-run with --confirm to write it to %s.", m.ID, cfg.FolderPath),
		}, nil
	}
	if err := writeMigrationFile(cfg, *m); err != nil {
		return nil, err
	}
	return &RunResult{
		Status:    StatusGenerated,
		Migration: m,
		Message:   fmt.Sprintf("Migration %s written to %s. Hand off to your own migration tool for application.", m.ID, migrationFilePath(cfg, *m)),
	}, nil

}
