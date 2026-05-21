package models

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
)

func TestSQLiteAdapter(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := testutils.SetupSQLiteAdapter(t, db)

	factory := func(id string) behemoth.Model {
		return testutils.NewTestUser(id)
	}

	updater := func(model behemoth.Model) behemoth.Model {
		user := model.(*testutils.TestUser)
		user.Email = "updated@emailupdater.com"
		return user
	}

	comparator := func(T, U behemoth.Model) bool {
		M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
		return M.Email == N.Email &&
			M.ID == N.ID &&
			M.Username == N.Username
	}

	manager := ModelManager{
		Create:  factory,
		Update:  updater,
		Compare: comparator,
	}

	cleanupTables := func() {
		db.ExecContext(context.Background(), "DELETE FROM users;")
	}

	cleanupDatabase := func() {
		db.ExecContext(context.Background(), "DROP TABLE users;")
		db.Close()
	}

	suite := NewDatabaseTestSuite(t, adapter, manager, cleanupTables, cleanupDatabase)
	suite.Run()
}

func TestMongoAdapter(t *testing.T) {
	mongoClient, cleanupDatabase := setupMongoTestDB(context.Background(), t)
	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)

	manager := ModelManager{
		Create: func(id string) behemoth.Model {
			return testutils.NewTestUser(id)
		},
		Update: func(M behemoth.Model) behemoth.Model {
			user := M.(*testutils.TestUser)
			user.Email = "updated@emailupdater.com"
			return user
		},
		Compare: func(T, U behemoth.Model) bool {
			M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
			return M.Email == N.Email &&
				M.ID == N.ID &&
				M.Username == N.Username

		},
	}

	suite := NewDatabaseTestSuite(t, adapter, manager, func() {
		CleanupMongoTestDB(context.Background(), t, mongoClient)
	}, cleanupDatabase)
	suite.Run()
}

func TestPostgresAdapter(t *testing.T) {
	db, cleanupDatabase := setupPostgresTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.PostgresAdapter{DB: db}

	manager := ModelManager{
		Create: func(id string) behemoth.Model {
			return testutils.NewTestUser(id)
		},
		Update: func(M behemoth.Model) behemoth.Model {
			user := M.(*testutils.TestUser)
			user.Email = "updated@emailupdater.com"
			return user
		},
		Compare: func(T, U behemoth.Model) bool {
			M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
			return M.Email == N.Email &&
				M.ID == N.ID &&
				M.Username == N.Username

		},
	}
	cleanupTables := func() {
		db.ExecContext(context.Background(), "DELETE FROM users;")
	}

	suite := NewDatabaseTestSuite(t, adapter, manager, cleanupTables, cleanupDatabase)
	suite.Run()
}

func TestGormAdapter(t *testing.T) {
	db := SetupGormTestDB(t, &testutils.GormTestUser{})
	adapter := SetupGormAdapter(t, db)

	manager := ModelManager{
		Create: func(id string) behemoth.Model {
			return testutils.NewGormTestUser(id)
		},
		Update: func(M behemoth.Model) behemoth.Model {
			user := M.(*testutils.GormTestUser)
			user.Email = "updated@emailupdater.com"
			return user
		},
		Compare: func(T, U behemoth.Model) bool {
			M, N := T.(*testutils.GormTestUser), U.(*testutils.GormTestUser)
			return M.Email == N.Email &&
				M.ID == N.ID &&
				M.Username == N.Username

		},
	}

	cleanupTables := func() {
		db.Exec("DELETE FROM users;")
	}

	cleanupDatabase := func() {
		db.Exec("DROP TABLE users;")
	}

	suite := NewDatabaseTestSuite(t, adapter, manager, cleanupTables, cleanupDatabase)
	suite.Run()
}
