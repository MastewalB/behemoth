package models

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/uptrace/bun"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"gorm.io/gorm"
)

type SQLiteAdapterTestManager struct {
	t  *testing.T
	db *sql.DB
}

func (sqtm *SQLiteAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewTestUser(id)
}

func (sqtm *SQLiteAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.TestUser)
	user.Email = "updated@emailupdater.com"
	return user

}
func (sqtm *SQLiteAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (sqtm *SQLiteAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.TestUser)
	return &copy
}

func (sqtm *SQLiteAdapterTestManager) CleanupTables() {
	ctx := sqtm.t.Context()

	// _, _ = sqtm.db.ExecContext(ctx, `PRAGMA foreign_keys = OFF;`)
	// tables, err := sqtm.db.QueryContext(sqtm.t.Context(), `
	// 		SELECT name
	// 		FROM sqlite_master
	// 		WHERE type='table'
	// 			AND name NOT LIKE 'sqlite_%'
	// `)

	// if err != nil {
	// 	return
	// }
	// defer tables.Close()

	// for tables.Next() {
	// 	var name string
	// 	if err := tables.Scan(&name); err != nil {
	// 		fmt.Println("scan errr: ", err)
	// 	}

	// 	fmt.Printf("RAW table name: %q\n", name)
	// 	query := fmt.Sprintf("DELETE FROM %s;", name)
	// 	if _, err := sqtm.db.ExecContext(ctx, query); err != nil {
	// 		sqtm.t.Fatal(err)
	// 	}
	// }
	// _, _ = sqtm.db.ExecContext(ctx, `PRAGMA foreign_keys = ON;`)

	if _, err := sqtm.db.ExecContext(ctx, "DELETE FROM users;"); err != nil {
		sqtm.t.Fatal(err)
	}
}

func (sqtm *SQLiteAdapterTestManager) CleanupDatabase() {
	sqtm.db.Close()
}

func TestSQLiteAdapter(t *testing.T) {
	db := testutils.SetupSQLiteTestDBWithSchema(t, testutils.TestUserSchema)
	adapter := testutils.SetupSQLiteAdapter(t, db)

	manager := &SQLiteAdapterTestManager{
		t:  t,
		db: db,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}
func TestMongoAdapter(t *testing.T) {
	ctx := t.Context()
	mongoClient, cleanupDatabase := testutils.SetupMongoTestDB(ctx, t)
	adapter := testutils.SetupMongoAdapter(t, mongoClient, testutils.MongoDBName)

	manager := &MongoAdapterTestManager{
		t:      t,
		client: mongoClient,
		cleanupTables: func() {
			testutils.CleanupMongoTestDB(ctx, t, mongoClient, testutils.MongoDBName)
		},
		cleanupDatabase: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestPostgresAdapter(t *testing.T) {
	ctx := t.Context()
	db, cleanupDatabase := testutils.SetupPostgresTestDBWithSchema(t, ctx, testutils.TestUserSchema)
	adapter := testutils.SetupPostgresAdapter(db)

	manager := &PostgresAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestMySQLAdapter(t *testing.T) {
	ctx := t.Context()
	db, cleanupDatabase := testutils.SetupMySQLTestDBWithSchema(t, ctx, testutils.TestMySQLUserSchema)
	adapter := testutils.SetupMySQLAdapter(db)

	manager := &MySQLAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestMSSQLAdapter(t *testing.T) {
	db, cleanupDatabase := testutils.SetupMSSQLTestDBWithSchema(t, t.Context(), testutils.TestMSSQLServerUserSchema)
	adapter := adapters.NewSQLServerAdapter(db)

	manager := &MSSQLAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()

}

func TestGormAdapter(t *testing.T) {
	db, cleanup := testutils.SetupGORMDBWithSchema(t, &testutils.GormTestUser{})
	adapter := testutils.SetupGormAdapter(t, db)

	manager := &GormAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanup,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestBunAdapter(t *testing.T) {
	db, cleanup := testutils.SetupBunTestDBWithSchema(t, &testutils.GormTestUser{})
	adapter := testutils.SetupBunAdapter(t, db)

	manager := &BunAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanup,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

type MongoAdapterTestManager struct {
	t               *testing.T
	client          *mongo.Client
	cleanupTables   func()
	cleanupDatabase func()
}

func (m *MongoAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewTestUser(id)
}

func (m *MongoAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.TestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *MongoAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *MongoAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.TestUser)
	return &copy
}

func (m *MongoAdapterTestManager) CleanupTables() {
	ctx := m.t.Context()
	coll := m.client.Database(testutils.MongoDBName).Collection("users")
	if _, err := coll.DeleteMany(ctx, bson.M{}); err != nil {
		m.t.Fatal(err)
	}
}

func (m *MongoAdapterTestManager) CleanupDatabase() {
	if m.cleanupDatabase != nil {
		m.cleanupDatabase()
	}
}

type PostgresAdapterTestManager struct {
	t       *testing.T
	db      *sql.DB
	cleanup func()
}

func (m *PostgresAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewTestUser(id)
}

func (m *PostgresAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.TestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *PostgresAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *PostgresAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.TestUser)
	return &copy
}

func (m *PostgresAdapterTestManager) CleanupTables() {
	ctx := m.t.Context()
	// if _, err := m.db.ExecContext(ctx, "DELETE FROM users;"); err != nil {
	// 	m.t.Fatal(err)
	// }

	tables, err := m.db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		m.t.Fatal(err)
	}
	defer tables.Close()

	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			m.t.Fatal(err)
		}
		if _, err := m.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s;", name)); err != nil {
			m.t.Fatal(err)
		}
	}
}

func (m *PostgresAdapterTestManager) CleanupDatabase() {
	if m.cleanup != nil {
		m.cleanup()
		return
	}
	if err := m.db.Close(); err != nil {
		m.t.Fatal(err)
	}
}

type MySQLAdapterTestManager struct {
	t       *testing.T
	db      *sql.DB
	cleanup func()
}

func (m *MySQLAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewTestUser(id)
}

func (m *MySQLAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.TestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *MySQLAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *MySQLAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.TestUser)
	return &copy
}

func (m *MySQLAdapterTestManager) CleanupTables() {
	ctx := m.t.Context()
	if _, err := m.db.ExecContext(ctx, "DELETE FROM users;"); err != nil {
		m.t.Fatal(err)
	}
}

func (m *MySQLAdapterTestManager) CleanupDatabase() {
	if m.cleanup != nil {
		m.cleanup()
		return
	}
	if err := m.db.Close(); err != nil {
		m.t.Fatal(err)
	}
}

type MSSQLAdapterTestManager struct {
	t       *testing.T
	db      *sql.DB
	cleanup func()
}

func (m *MSSQLAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewTestUser(id)
}

func (m *MSSQLAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.TestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *MSSQLAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.TestUser), U.(*testutils.TestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *MSSQLAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.TestUser)
	return &copy
}

func (m *MSSQLAdapterTestManager) CleanupTables() {
	ctx := m.t.Context()
	if _, err := m.db.ExecContext(ctx, "DELETE FROM users;"); err != nil {
		m.t.Fatal(err)
	}
}

func (m *MSSQLAdapterTestManager) CleanupDatabase() {
	if m.cleanup != nil {
		m.cleanup()
		return
	}
	if err := m.db.Close(); err != nil {
		m.t.Fatal(err)
	}
}

type GormAdapterTestManager struct {
	t       *testing.T
	db      *gorm.DB
	cleanup func()
}

func (m *GormAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewGormTestUser(id)
}

func (m *GormAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.GormTestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *GormAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.GormTestUser), U.(*testutils.GormTestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *GormAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.GormTestUser)
	return &copy
}

func (m *GormAdapterTestManager) CleanupTables() {
	if err := m.db.Exec("DELETE FROM users;").Error; err != nil {
		m.t.Fatal(err)
	}
}

func (m *GormAdapterTestManager) CleanupDatabase() {
	if m.cleanup != nil {
		m.cleanup()
	}
}

type BunAdapterTestManager struct {
	t       *testing.T
	db      *bun.DB
	cleanup func()
}

func (m *BunAdapterTestManager) Create(id string) behemoth.Model {
	return testutils.NewGormTestUser(id)
}

func (m *BunAdapterTestManager) Update(M behemoth.Model) behemoth.Model {
	user := M.(*testutils.GormTestUser)
	user.Email = "updated@emailupdater.com"
	return user
}

func (m *BunAdapterTestManager) Compare(T, U behemoth.Model) bool {
	M, N := T.(*testutils.GormTestUser), U.(*testutils.GormTestUser)
	return M.Email == N.Email &&
		M.ID == N.ID &&
		M.Username == N.Username
}

func (m *BunAdapterTestManager) Clone(M behemoth.Model) behemoth.Model {
	copy := *M.(*testutils.GormTestUser)
	return &copy
}

func (m *BunAdapterTestManager) CleanupTables() {
	ctx := m.t.Context()
	if _, err := m.db.NewRaw("DELETE FROM users;").Exec(ctx); err != nil {
		m.t.Fatal(err)
	}
}

func (m *BunAdapterTestManager) CleanupDatabase() {
	if m.cleanup != nil {
		m.cleanup()
	}
}
