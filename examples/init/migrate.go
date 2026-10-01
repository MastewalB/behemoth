package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters/postgres"
	binit "github.com/MastewalB/behemoth/types/init"
)

// migrate needs the full declared schema but must not boot the
// application: Prepare alone is enough, and it already carries the resolver
// the migration driver needs.
func migrate(ctx context.Context, confirm bool) error {
	app, err := binit.Prepare(plugins(), prepareConfig())
	if err != nil {
		return err
	}

	sqlDB, err := openDB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	driver := postgres.NewPostgreSQLDriver(sqlDB, app.Resolver)
	res, err := core.RunGenerateCLI(ctx, app.Migration, app.Declared(), core.GenerateDeps{
		Introspector: driver,
		Presenter:    core.NewFilePresenter(filepath.Join(app.Migration.FolderPath, "draft.json")),
		Generator:    &core.DefaultMigrationGenerator{},
		Renderer:     driver,
	}, confirm)
	if err != nil {
		return err
	}
	fmt.Println(res.Message)
	return nil
}
