package core

import "context"

type Migrator struct {
	driver     Driver
	migrations map[int]Migration
}



func (m *Migrator) Up(ctx context.Context) error {
	for _, mig := range m.migrations {
		if err := mig.Up(ctx, m.driver); err != nil {
			return err
		}
	}

	return nil
}

func (m *Migrator) Down(ctx context.Context) error {
	for _, mig := range m.migrations {
		if err := mig.Down(ctx, m.driver); err != nil {
			return err
		}
	}

	return nil
}
