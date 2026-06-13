package core

import "context"

type Migrator struct {
	driver     Driver
	migrations map[int]Migration
}

func NewMigrator(driver Driver) *Migrator {
	return &Migrator{
		driver:     driver,
		migrations: make(map[int]Migration),
	}
}

func (m *Migrator) AddMigration(migration Migration) {
	m.migrations[migration.Version] = migration
}

func (m *Migrator) AddMigrations(migrations ...Migration) {
	for _, migration := range migrations {
		m.migrations[migration.Version] = migration
	}
}

func (m *Migrator) Up(ctx context.Context) error {
	if err := m.ensureMigrationTable(ctx); err != nil {
		return err
	}

	currVersion, err := m.driver.Version(ctx)
	if err != nil {
		return err
	}

	latestVersion := m.getLatestVersion()

	for v := currVersion + 1; v <= latestVersion; v++ {
		if migration, ok := m.migrations[v]; ok {
			if err := migration.Up(ctx, m.driver); err != nil {
				return err
			}

			if err := m.driver.SetVersion(ctx, v); err != nil {
				return err
			}

		} else {
			return ErrMigrationNotFound
		}
	}

	return nil
}

// Down will migrate N steps down by applying all down migrations.
// If steps is -1 it applies the migrations all the way down.
func (m *Migrator) Down(ctx context.Context, steps int) error {
	if err := m.ensureMigrationTable(ctx); err != nil {
		return err
	}

	currVersion, err := m.driver.Version(ctx)
	if err != nil {
		return err
	}

	if steps == -1 {
		steps = len(m.migrations)
	}

	for i := 0; i < steps && currVersion > 0; i++ {
		if migration, ok := m.migrations[currVersion]; ok {
			if err := migration.Down(ctx, m.driver); err != nil {
				return err
			}

		} else {
			return ErrMigrationNotFound
		}

		newVersion := currVersion - 1
		if err := m.driver.SetVersion(ctx, newVersion); err != nil {
			return err
		}
		currVersion = newVersion
	}

	return nil
}

func (m *Migrator) ensureMigrationTable(ctx context.Context) error {
	return m.driver.CreateMigrationTable(ctx)
}

// getLatestVersion returns the highest migration version among
// the available migrations
// Returns -1 if there are no migrations
func (m *Migrator) getLatestVersion() int {
	maxVersion := -1
	for version := range m.migrations {
		if version > maxVersion {
			maxVersion = version
		}
	}

	return maxVersion
}
