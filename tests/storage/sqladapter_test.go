package models

import (
	"context"

	"testing"

	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"
)

/*
Tests for the SQLLiteAdapter implementing the behemoth.Database interface.
*/

func TestCreate(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("1")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, "id = ?", "1")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestFind(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("2")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, "id = ?", "2")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestUpdate(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("3")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	user.Email = "updated@email.com"
	err = adapter.Update(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, "id = ?", "3")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	updatedUser := found.(*testutils.TestUser)
	assert.Equal(t, user.Email, updatedUser.Email)
}

func TestDelete(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("4")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	err = adapter.Delete(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, "id = ?", "4")
	assert.Error(t, err)
	assert.Nil(t, found)
}
