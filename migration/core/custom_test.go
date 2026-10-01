package core

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

func addIndexOp(id, table, index string) SchemaOperation {
	return SchemaOperation{ID: id, Kind: OpAddIndex, Table: table, Index: &schema.Index{Name: index, Columns: []string{"id"}}}
}

func TestValidateCustomMigrations(t *testing.T) {
	for name, tc := range map[string]struct {
		custom  []CustomMigration
		wantErr bool
	}{
		"none":           {nil, false},
		"valid":          {[]CustomMigration{{Name: "a", Up: []SchemaOperation{addIndexOp("a_1", "t", "i1")}}, {Name: "b"}}, false},
		"no name":        {[]CustomMigration{{Up: []SchemaOperation{addIndexOp("x", "t", "i")}}}, true},
		"duplicate name": {[]CustomMigration{{Name: "a"}, {Name: "a"}}, true},
		"op without ID":  {[]CustomMigration{{Name: "a", Up: []SchemaOperation{addIndexOp("", "t", "i")}}}, true},
		"op ID shared by two migrations": {[]CustomMigration{
			{Name: "a", Up: []SchemaOperation{addIndexOp("same", "t", "i1")}},
			{Name: "b", Up: []SchemaOperation{addIndexOp("same", "t", "i2")}},
		}, true},
		"op ID equals a migration name": {[]CustomMigration{
			{Name: "a", Up: []SchemaOperation{addIndexOp("b", "t", "i1")}},
			{Name: "b"},
		}, true},
	} {
		err := ValidateCustomMigrations(tc.custom)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", name, err, tc.wantErr)
		}
	}
}

func TestGenerateRejectsCustomCollidingWithGenerated(t *testing.T) {
	generated := addIndexOp(addIndexID("users", "idx_email"), "users", "idx_email")
	for name, custom := range map[string]CustomMigration{
		"operation ID": {Name: "custom", Up: []SchemaOperation{addIndexOp(generated.ID, "users", "idx_other")}},
		"name":         {Name: generated.ID},
	} {
		_, err := (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{
			Operations: []SchemaOperation{generated},
			Custom:     []CustomMigration{custom},
		}, "")
		if err == nil {
			t.Errorf("%s: expected a collision error", name)
		}
	}
}

func TestGenerateRecordsCustomNames(t *testing.T) {
	m, err := (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{Custom: []CustomMigration{
		{Name: "zeta", Up: []SchemaOperation{addIndexOp("zeta_1", "t", "i1")}},
		{Name: "alpha", Up: []SchemaOperation{addIndexOp("alpha_1", "t", "i2")}},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alpha", "zeta"}; !slices.Equal(m.Custom, want) {
		t.Errorf("Custom = %v, want %v", m.Custom, want)
	}
}

// snapshotRunner reports a snapshot always in step with the latest migration
// on disk, so planning sees no unapplied migrations and no schema drift.
type snapshotRunner struct{ cfg MigrationConfig }

func (r snapshotRunner) Pending(context.Context, []Migration) ([]Migration, error) { return nil, nil }
func (r snapshotRunner) Apply(context.Context, []Migration) error                  { return nil }
func (r snapshotRunner) LoadSnapshot(context.Context) (SchemaSnapshot, error) {
	latest, err := LatestMigrationID(r.cfg)
	return SchemaSnapshot{Version: latest, Tables: map[string]schema.Table{}}, err
}

func TestCustomMigrationEmittedOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := NewMigrationConfig(MigrationConfig{FolderPath: dir, Path: PathManaged})
	deps := GenerateDeps{
		Runner:    snapshotRunner{cfg: cfg},
		Presenter: NewFilePresenter(filepath.Join(dir, "draft.json")),
		Generator: &DefaultMigrationGenerator{},
	}
	reg := schema.NewRegistry()
	if err := reg.Freeze(); err != nil {
		t.Fatal(err)
	}
	backfill := CustomMigration{Name: "backfill", Up: []SchemaOperation{addIndexOp("backfill_1", "t", "i1")}}

	first, err := RunGenerate(ctx, cfg, Declared{Schemas: reg, Custom: []CustomMigration{backfill}}, deps, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first.Custom, []string{"backfill"}) || len(first.Up) != 1 {
		t.Fatalf("first migration: Custom = %v, Up = %d ops; want [backfill], 1 op", first.Custom, len(first.Up))
	}

	// Already on disk: not emitted again.
	_, err = RunGenerate(ctx, cfg, Declared{Schemas: reg, Custom: []CustomMigration{backfill}}, deps, false)
	if !behemotherr.IsCode(err, behemotherr.ErrorCodeMigrationNothingToGenerate) {
		t.Fatalf("second run: err = %v, want nothing to generate", err)
	}

	// A new custom migration alongside the emitted one: only the new one goes out.
	reindex := CustomMigration{Name: "reindex", Up: []SchemaOperation{addIndexOp("reindex_1", "t", "i2")}}
	third, err := RunGenerate(ctx, cfg, Declared{Schemas: reg, Custom: []CustomMigration{backfill, reindex}}, deps, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(third.Custom, []string{"reindex"}) || third.ID != "0002" {
		t.Errorf("third migration: ID = %s, Custom = %v; want 0002, [reindex]", third.ID, third.Custom)
	}
}

func TestGenerateDownIncludesCustomDown(t *testing.T) {
	drop := SchemaOperation{ID: "add_i1_down", Kind: OpDropIndex, Table: "t", IndexName: "i1"}
	m, err := (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{Custom: []CustomMigration{
		{Name: "add_i1", Up: []SchemaOperation{addIndexOp("add_i1_up", "t", "i1")}, Down: []SchemaOperation{drop}},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Down) != 1 || m.Down[0].ID != drop.ID {
		t.Errorf("Down = %+v, want [%s]", m.Down, drop.ID)
	}

	// Without an authored Down the whole migration is irreversible.
	m, err = (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{Custom: []CustomMigration{
		{Name: "add_i1", Up: []SchemaOperation{addIndexOp("add_i1_up", "t", "i1")}},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Down != nil {
		t.Errorf("Down = %+v, want nil", m.Down)
	}
}
