package core

import (
	"fmt"
	"sort"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

// Declared is everything an application declares for migrations to converge
// on: the tables in Schemas, plus hand-authored CustomMigrations.
type Declared struct {
	Schemas schema.Registry
	Custom  []CustomMigration
}

// ValidateCustomMigrations checks what can be checked without a plan: every
// migration is named, names are unique, and every operation has an ID that
// is unique across all custom migrations and distinct from every name.
// Collisions with generated operation IDs are only knowable per plan; see
// checkCustomCollisions.
func ValidateCustomMigrations(custom []CustomMigration) error {
	const op = "CustomMigration.Validate"
	names := map[string]bool{}
	for _, c := range custom {
		if c.Name == "" {
			return behemotherr.NewConfigurationError(op, "custom migration missing Name", nil)
		}
		if names[c.Name] {
			return behemotherr.NewConfigurationError(op, fmt.Sprintf("custom migration %q declared more than once", c.Name), nil)
		}
		names[c.Name] = true
	}

	opOwner := map[string]string{} // operation ID -> custom migration declaring it
	for _, c := range custom {
		for _, ops := range [][]SchemaOperation{c.Up, c.Down} {
			for _, o := range ops {
				if o.ID == "" {
					return behemotherr.NewConfigurationError(op, fmt.Sprintf("custom migration %q has an operation without an ID", c.Name), nil)
				}
				if names[o.ID] {
					return behemotherr.NewConfigurationError(op, fmt.Sprintf("custom migration %q: operation ID %q is also a custom migration name", c.Name, o.ID), nil)
				}
				if owner, dup := opOwner[o.ID]; dup && owner != c.Name {
					return behemotherr.NewConfigurationError(op, fmt.Sprintf("operation ID %q is used by both %q and %q", o.ID, owner, c.Name), nil)
				}
				opOwner[o.ID] = c.Name
			}
		}
	}
	return nil
}

// pendingCustomMigrations drops every custom migration already frozen into a
// migration on disk. A custom migration is emitted exactly once: its name is
// recorded in Migration.Custom, and from then on it is part of history —
// editing it in code changes nothing, and its name can never be reused.
func pendingCustomMigrations(cfg MigrationConfig, custom []CustomMigration) ([]CustomMigration, error) {
	if len(custom) == 0 {
		return nil, nil
	}
	disk, err := ReadDiskMigrations(cfg)
	if err != nil {
		return nil, err
	}
	emitted := map[string]bool{}
	for _, m := range disk {
		for _, name := range m.Custom {
			emitted[name] = true
		}
	}
	var pending []CustomMigration
	for _, c := range custom {
		if !emitted[c.Name] {
			pending = append(pending, c)
		}
	}
	return pending, nil
}

// checkCustomCollisions rejects a custom migration whose name or operation
// IDs match a generated operation in the same plan: once frozen, Up is one
// flat list, and Down, rendering and the runner all key on operation IDs.
func checkCustomCollisions(resolved *ResolvedOperationSet) error {
	generated := make(map[string]bool, len(resolved.Operations))
	for _, o := range resolved.Operations {
		generated[o.ID] = true
	}
	for _, c := range resolved.Custom {
		if generated[c.Name] {
			return behemotherr.NewConfigurationError("MigrationGenerator.Generate",
				fmt.Sprintf("custom migration name %q collides with a generated operation ID", c.Name), nil)
		}
		for _, ops := range [][]SchemaOperation{c.Up, c.Down} {
			for _, o := range ops {
				if generated[o.ID] {
					return behemotherr.NewConfigurationError("MigrationGenerator.Generate",
						fmt.Sprintf("custom migration %q: operation ID %q collides with a generated operation", c.Name, o.ID), nil)
				}
			}
		}
	}
	return nil
}

// customNames lists resolved's custom migrations by name, sorted so a
// regenerated migration compares equal to the one on disk.
func customNames(resolved *ResolvedOperationSet) []string {
	if len(resolved.Custom) == 0 {
		return nil
	}
	names := make([]string, len(resolved.Custom))
	for i, c := range resolved.Custom {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}
