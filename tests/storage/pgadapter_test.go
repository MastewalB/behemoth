package models

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgresTestDB(t *testing.T, schema string) (*sql.DB, func()) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:15",
		Env:          map[string]string{"POSTGRES_PASSWORD": "secret", "POSTGRES_DB": "testdb"},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor:   wait.ForListeningPort("5432/tcp"),
	}

	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	host, _ := pgContainer.Host(ctx)
	port, _ := pgContainer.MappedPort(ctx, "5432")

	dsn := fmt.Sprintf("postgres://postgres:secret@%s:%s/testdb?sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	// Migration/setup logic here
	_, err = db.Exec(schema)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}

	return db, cleanup
}

// func TestCreatePG(t *testing.T) {
// 	db, cleanup := setupPostgresTestDB(t, testutils.TestUserSchema)
// 	defer cleanup()

// 	adapter := &adapters.PostgresAdapter{DB: db}
// 	user := testutils.NewTestUser("1")
// 	err := adapter.Create(context.Background(), user)
// 	assert.NoError(t, err)

// 	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)

// 	foundUser := found.(*testutils.TestUser)
// 	assert.Equal(t, user.ID, foundUser.ID)
// 	assert.Equal(t, user.Email, foundUser.Email)
// 	assert.Equal(t, user.Username, foundUser.Username)
// }

// func TestFindPG(t *testing.T) {
// 	db, cleanup := setupPostgresTestDB(t, testutils.TestUserSchema)
// 	defer cleanup()

// 	adapter := &adapters.PostgresAdapter{DB: db}
// 	user := testutils.NewTestUser("2")
// 	err := adapter.Create(context.Background(), user)
// 	assert.NoError(t, err)

// 	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "2"))
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)

// 	foundUser := found.(*testutils.TestUser)
// 	assert.Equal(t, user.ID, foundUser.ID)
// 	assert.Equal(t, user.Email, foundUser.Email)
// 	assert.Equal(t, user.Username, foundUser.Username)
// }

// func TestUpdatePG(t *testing.T) {
// 	db, cleanup := setupPostgresTestDB(t, testutils.TestUserSchema)
// 	defer cleanup()

// 	adapter := &adapters.PostgresAdapter{DB: db}
// 	user := testutils.NewTestUser("3")
// 	err := adapter.Create(context.Background(), user)
// 	assert.NoError(t, err)

// 	user.Email = "updated@email.com"
// 	err = adapter.Update(context.Background(), user)
// 	assert.NoError(t, err)

// 	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "3"))
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)

// 	updatedUser := found.(*testutils.TestUser)
// 	assert.Equal(t, user.Email, updatedUser.Email)
// }

// func TestDeletePG(t *testing.T) {
// 	db, cleanup := setupPostgresTestDB(t, testutils.TestUserSchema)
// 	defer cleanup()

// 	adapter := &adapters.PostgresAdapter{DB: db}
// 	user := testutils.NewTestUser("4")
// 	err := adapter.Create(context.Background(), user)
// 	assert.NoError(t, err, "failed to create user")

// 	err = adapter.Delete(context.Background(), user)
// 	assert.NoError(t, err, "failed to delete user")

// 	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "4"))
// 	assert.Error(t, err)
// 	assert.Nil(t, found, "expected no user found after delete")
// }
