package models

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

func SetupBunTestDB(t *testing.T, model behemoth.Model) (*bun.DB, func()) {
	ctx := context.Background()
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())

	sqldb, err := sql.Open(sqliteshim.ShimName, dbName)
	if err != nil {
		t.Fatal("failed to connect database")
	}

	cleanup := func() {
		sqldb.Close()
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())
	_, err = db.NewCreateTable().Model(model).IfNotExists().Exec(ctx)
	if err != nil {
		t.Fatal("failed to create table, %w", err)
	}
	return db, cleanup
}
func SetupBunAdapter(t *testing.T, db *bun.DB) *adapters.BunAdapter {
	return adapters.NewBunAdapter(db)
}
