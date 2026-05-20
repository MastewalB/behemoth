package models

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
)

func TestCreate_FindByIDIA(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	sqliteAdapter := testutils.SetupSQLiteAdapter(t, db)
	adapter := testutils.SetupInternalAdapter(t, sqliteAdapter)

	userMap := testutils.NewTestUserMap(1)
	user, err := adapter.CreateUser(context.Background(), &testutils.TestUser{}, userMap)
	assert.NoError(t, err)
	assert.NotNil(t, user)

	testUser := user.(*testutils.TestUser)
	found, err := adapter.FindUserByID(context.Background(), &testutils.TestUser{}, testUser.ID)
	assert.NoError(t, err)
	assert.NotNil(t, found)

}

func TestUpdateIA(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	sqliteAdapter := testutils.SetupSQLiteAdapter(t, db)
	adapter := testutils.SetupInternalAdapter(t, sqliteAdapter)

	userMap := testutils.NewTestUserMap(1)
	user, err := adapter.CreateUser(context.Background(), &testutils.TestUser{}, userMap)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	testUser := user.(*testutils.TestUser)
	testUser.Email = "updated@email.com"

	updatedUser, err := adapter.UpdateUser(context.Background(), testUser)
	updatedTestUser := updatedUser.(*testutils.TestUser)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, testUser.Email, updatedTestUser.Email)
}

func TestDeleteIA(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	sqliteAdapter := testutils.SetupSQLiteAdapter(t, db)
	adapter := testutils.SetupInternalAdapter(t, sqliteAdapter)

	userMap := testutils.NewTestUserMap(1)
	user, err := adapter.CreateUser(context.Background(), &testutils.TestUser{}, userMap)
	assert.NoError(t, err)
	assert.NotNil(t, user)

	err = adapter.DeleteUser(context.Background(), user)
	assert.NoError(t, err)

	testUser := user.(*testutils.TestUser)
	foundUser, err := adapter.FindUserByID(context.Background(), &testutils.TestUser{}, testUser.ID)
	assert.Nil(t, foundUser)
	assert.Error(t, err)
}
