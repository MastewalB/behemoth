package models

import (
	"fmt"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func SetupGormTestDB(t *testing.T, models behemoth.Model) (*gorm.DB, func()) {
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		t.Fatal("failed to connect database")
	}

	db.Exec("PRAGMA foreign_keys = ON;")
	db.AutoMigrate(models)

	cleanup := func() {
		if sqliteDB, err := db.DB(); err == nil {
			sqliteDB.Close()
		}
	}

	return db, cleanup
}

func SetupGormAdapter(t *testing.T, db *gorm.DB) *adapters.GormAdapter {
	return adapters.NewGormAdapter(db)
}

// func TestGormAdapter_CreateAndFindOne(t *testing.T) {
// 	ctx := context.Background()
// 	db := SetupGormTestDB(t, &testutils.GormTestUser{})
// 	adapter := SetupGormAdapter(t, db)

// 	user := testutils.NewGormTestUser("1")
// 	err := adapter.Create(t.Context(), user)
// 	assert.NoError(t, err)

// 	foundModel, err := adapter.FindOne(ctx, &testutils.GormTestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
// 	assert.NoError(t, err)
// 	foundUser := foundModel.(*testutils.GormTestUser)
// 	assert.Equal(t, user.ID, foundUser.ID)
// 	assert.Equal(t, user.Email, foundUser.Email)
// 	assert.Equal(t, user.Username, foundUser.Username)

// 	non_existent, err := adapter.FindOne(ctx, &testutils.GormTestUser{}, getWhereExpr("id", clause.OpEqual, "999"))
// 	assert.Error(t, err)
// 	assert.Nil(t, non_existent)

// }

// func TestGormAdapter_FindMany(t *testing.T) {
// 	db := SetupGormTestDB(t, &testutils.GormTestUser{})
// 	adapter := SetupGormAdapter(t, db)

// 	user1 := testutils.NewGormTestUser("5")
// 	user2 := testutils.NewGormTestUser("6")
// 	err := adapter.Create(context.Background(), user1)
// 	assert.NoError(t, err)
// 	err = adapter.Create(context.Background(), user2)
// 	assert.NoError(t, err)

// 	found, err := adapter.FindMany(context.Background(), &testutils.GormTestUser{}, getWhereExpr("id", clause.OpGreaterThan, "4"))
// 	assert.NoError(t, err)
// 	assert.Len(t, found, 2)

// 	foundUser1 := found[0].(*testutils.GormTestUser)
// 	foundUser2 := found[1].(*testutils.GormTestUser)

// 	assert.Greater(t, foundUser1.ID, "4")
// 	assert.Greater(t, foundUser2.ID, "4")
// }

// func TestGormAdapter_Update(t *testing.T) {
// 	db := SetupGormTestDB(t, &testutils.GormTestUser{})
// 	adapter := SetupGormAdapter(t, db)

// 	user := testutils.NewGormTestUser("1")
// 	err := adapter.Create(t.Context(), user)
// 	assert.NoError(t, err)

// 	user.Email = "updated@email.com"
// 	err = adapter.Update(context.Background(), user)
// 	assert.NoError(t, err)

// 	foundModel, err := adapter.FindOne(context.Background(), &testutils.GormTestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
// 	assert.NoError(t, err)
// 	updatedUser := foundModel.(*testutils.GormTestUser)
// 	assert.Equal(t, user.ID, updatedUser.ID)
// 	assert.Equal(t, user.Email, updatedUser.Email)
// 	assert.Equal(t, user.Username, updatedUser.Username)
// }

// func TestGormAdapter_Delete(t *testing.T) {
// 	db := SetupGormTestDB(t, &testutils.GormTestUser{})
// 	adapter := SetupGormAdapter(t, db)

// 	user := testutils.NewGormTestUser("4")
// 	err := adapter.Create(context.Background(), user)
// 	assert.NoError(t, err)

// 	err = adapter.Delete(context.Background(), user)
// 	assert.NoError(t, err)

// 	found, err := adapter.FindOne(context.Background(), &testutils.GormTestUser{}, getWhereExpr("id", clause.OpEqual, "4"))
// 	assert.Error(t, err)
// 	assert.Nil(t, found)

// }
