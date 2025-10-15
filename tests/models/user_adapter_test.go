package models

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/tests/testutils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

/*
Tests for the User model adapter functions.
*/

func TestCreateUserAdapter(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	user := testutils.NewTestUser("1")
	adapter := testutils.SetupSQLiteAdapter(t, db)

	created, err := models.CreateUser(context.Background(), adapter, user)
	assert.NoError(t, err)

	user = created.(*testutils.TestUser)
	assert.Equal(t, "1", user.ID)

}

func TestFindUserAdapter(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	user := testutils.NewTestUser("2")
	adapter := testutils.SetupSQLiteAdapter(t, db)

	_, err := models.CreateUser(context.Background(), adapter, user)
	assert.NoError(t, err)

	found, err := models.FindUserByID(context.Background(), adapter, user, "2")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, "2", foundUser.ID)
}

func TestUpdateUserAdapter(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	user := testutils.NewTestUser("3")
	adapter := testutils.SetupSQLiteAdapter(t, db)

	_, err := models.CreateUser(context.Background(), adapter, user)
	assert.NoError(t, err)

	user.Email = "new@update.com"
	updated, err := models.UpdateUser(context.Background(), adapter, user)
	assert.NoError(t, err)
	updatedUser := updated.(*testutils.TestUser)
	assert.Equal(t, updatedUser.Email, "new@update.com")

	found, err := models.FindUserByID(context.Background(), adapter, user, "3")
	assert.NoError(t, err)
	assert.NotNil(t, found)
}

func TestDeleteUserAdapter(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	user := testutils.NewTestUser("4")
	adapter := testutils.SetupSQLiteAdapter(t, db)

	_, err := models.CreateUser(context.Background(), adapter, user)
	assert.NoError(t, err)

	err = models.DeleteUser(context.Background(), adapter, user)
	assert.NoError(t, err)

	found, err := models.FindUserByID(context.Background(), adapter, user, "4")
	assert.Error(t, err)
	assert.Nil(t, found)
}
