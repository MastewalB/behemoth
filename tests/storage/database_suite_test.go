package models

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	mongoAdapter "github.com/MastewalB/behemoth/storage/adapters/mongo"
	mysqlAdapter "github.com/MastewalB/behemoth/storage/adapters/mysql"
	pgAdapter "github.com/MastewalB/behemoth/storage/adapters/postgres"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	sqlserverAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlserver"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"github.com/uptrace/bun"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/gorm"
)

type SQLiteAdapterTestManager struct {
	t     *testing.T
	db    *sql.DB
	table string // physical users table; "users" when empty
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

	table := sqtm.table
	if table == "" {
		table = "users"
	}
	if _, err := sqtm.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
		sqtm.t.Fatal(err)
	}
}

func (sqtm *SQLiteAdapterTestManager) CleanupDatabase() {
	sqtm.db.Close()
}

func TestSQLiteAdapter(t *testing.T) {
	db := testutils.SetupSQLiteTestDBWithSchema(t, testutils.TestUserSchema)
	adapter := testutils.SetupSQLiteAdapter(t, db)

	t.Run("UndefinedTable", func(t *testing.T) { assertUndefinedTable(t, adapter) })
	t.Run("ConstraintErrors", func(t *testing.T) {
		// A separate database: the shared one has foreign key enforcement off.
		fkDB, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "fk.db")+"?_foreign_keys=on")
		if err != nil {
			t.Fatal(err)
		}
		defer fkDB.Close()
		if _, err := fkDB.Exec(testutils.TestUserSchema); err != nil {
			t.Fatal(err)
		}
		assertConstraintClassification(t, sqliteAdapter.NewSQLiteAdapter(fkDB, nil), fkDB,
			`CREATE TABLE memberships (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id))`)
	})

	manager := &SQLiteAdapterTestManager{
		t:  t,
		db: db,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

// TestSQLiteAdapterWithPhysicalNames runs the whole suite against a table
// whose physical table and column names all differ from the model's canonical
// ones: every statement the adapter builds has to resolve every name.
func TestSQLiteAdapterWithPhysicalNames(t *testing.T) {
	db := testutils.SetupSQLiteTestDBWithSchema(t, `
		CREATE TABLE app_users (
			user_id TEXT PRIMARY KEY,
			email_address TEXT NOT NULL,
			handle TEXT UNIQUE NOT NULL
		);`)

	manager := &SQLiteAdapterTestManager{t: t, db: db, table: "app_users"}
	suite := NewDatabaseTestSuite(t, sqliteAdapter.NewSQLiteAdapter(db, physicalNamesResolver(t)), manager)
	suite.Run()
}

// physicalNamesResolver maps TestUser's canonical names to the physical ones
// of the app_users tables below, built the way Boot builds it: declared
// PhysicalNames -> BuildSchemaResolverTable -> DefaultSchemaResolver.
func physicalNamesResolver(t *testing.T) behemoth.SchemaResolver {
	t.Helper()
	registry := schema.NewRegistry()
	err := registry.Declare(&testutils.TestUser{}, schema.Table{
		Name: "users", PhysicalName: "app_users",
		Columns: []schema.Column{
			{Name: "id", PhysicalName: "user_id", Type: schema.ColTypeText, PrimaryKey: true},
			{Name: "email", PhysicalName: "email_address", Type: schema.ColTypeText},
			{Name: "username", PhysicalName: "handle", Type: schema.ColTypeText, Unique: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := core.NewSchemaResolver()
	resolver.Freeze(core.BuildSchemaResolverTable(registry, core.NewMigrationConfig(core.MigrationConfig{})))
	return resolver
}

// membership references users(id); only used to provoke foreign key errors.
type membership struct{ ID, UserID string }

func (m *membership) SchemaName() string     { return "memberships" }
func (m *membership) PrimaryKeyName() string { return "id" }
func (m *membership) PrimaryKeyField() any   { return m.ID }
func (m *membership) New() behemoth.Model    { return &membership{} }
func (m *membership) ToMap() (map[string]any, error) {
	return map[string]any{"id": m.ID, "user_id": m.UserID}, nil
}
func (m *membership) FromMap(data map[string]any) error {
	m.ID, _ = data["id"].(string)
	m.UserID, _ = data["user_id"].(string)
	return nil
}

// assertConstraintClassification: each adapter maps its driver's constraint
// errors to the shared categories. membershipsDDL creates the memberships
// table (with a foreign key to users.id) in the adapter's dialect; the users
// table must already exist.
func assertConstraintClassification(t *testing.T, adapter behemoth.Database, db *sql.DB, membershipsDDL string) {
	t.Helper()
	ctx := t.Context()
	if _, err := db.ExecContext(ctx, membershipsDDL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.ExecContext(context.Background(), "DROP TABLE memberships") })

	user := testutils.NewTestUser("fk-parent")
	if err := adapter.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adapter.Delete(context.Background(), user) })

	if err := adapter.Create(ctx, testutils.NewTestUser("fk-parent")); !behemotherr.IsDuplicateKey(err) {
		t.Errorf("duplicate primary key: want duplicate_key, got %v", err)
	}
	if err := adapter.Create(ctx, &membership{ID: "m1", UserID: "no-such-user"}); !behemotherr.Is(err, behemotherr.CategoryForeignKey) {
		t.Errorf("insert referencing a missing row: want foreign_key_violation, got %v", err)
	}

	child := &membership{ID: "m2", UserID: user.ID}
	if err := adapter.Create(ctx, child); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adapter.Delete(context.Background(), child) }) // registered last, runs first
	if err := adapter.Delete(ctx, user); !behemotherr.Is(err, behemotherr.CategoryForeignKey) {
		t.Errorf("delete of a referenced row: want foreign_key_violation, got %v", err)
	}
}

// assertUndefinedTable: a query against a table that doesn't exist is
// classified undefined_table — never not-found, which means "no such row".
func assertUndefinedTable(t *testing.T, adapter behemoth.Database) {
	t.Helper()
	ctx := t.Context()
	missing := &core.SchemaSnapshot{} // its table is never created in these databases

	_, err := adapter.FindOne(ctx, missing, clause.Expression{})
	if !behemotherr.IsUndefinedTable(err) || behemotherr.IsNotFound(err) {
		t.Errorf("FindOne on a missing table: want undefined_table, got %v", err)
	}
	if _, err := adapter.FindMany(ctx, missing, clause.Expression{}, nil); !behemotherr.IsUndefinedTable(err) {
		t.Errorf("FindMany on a missing table: want undefined_table, got %v", err)
	}
	if _, err := adapter.Count(ctx, missing, clause.Expression{}); !behemotherr.IsUndefinedTable(err) {
		t.Errorf("Count on a missing table: want undefined_table, got %v", err)
	}
}

func TestMongoAdapter(t *testing.T) {
	ctx := t.Context()
	mongoClient, cleanupDatabase := testutils.SetupMongoTestDB(ctx, t)
	adapter := testutils.SetupMongoAdapter(t, mongoClient, testutils.MongoDBName)

	dropAll := func() { testutils.CleanupMongoTestDB(ctx, t, mongoClient, testutils.MongoDBName) }

	t.Run("CheckTransactions passes on a replica set", func(t *testing.T) {
		if err := adapter.CheckTransactions(ctx); err != nil {
			t.Fatalf("CheckTransactions on a replica set = %v", err)
		}
	})

	// The whole suite again, with every name physical-only. Runs first: the
	// standard suite's CleanupDatabase disconnects the client.
	t.Run("PhysicalNames", func(t *testing.T) {
		defer dropAll()
		mapped := mongoAdapter.NewMongoAdapter(mongoClient, testutils.MongoDBName, physicalNamesResolver(t))
		manager := &MongoAdapterTestManager{t: t, client: mongoClient, cleanupTables: dropAll, cleanupDatabase: func() {}}
		NewDatabaseTestSuite(t, mapped, manager).Run()
	})

	// Documents are stored under physical names and read back as canonical ones.
	t.Run("StoresPhysicalNames", func(t *testing.T) {
		defer dropAll()
		mapped := mongoAdapter.NewMongoAdapter(mongoClient, testutils.MongoDBName, physicalNamesResolver(t))
		user := testutils.NewTestUser("u-1")
		if err := mapped.Create(ctx, user); err != nil {
			t.Fatal(err)
		}

		var raw bson.M
		if err := mongoClient.Database(testutils.MongoDBName).Collection("app_users").FindOne(ctx, bson.M{"user_id": "u-1"}).Decode(&raw); err != nil {
			t.Fatalf("stored document not found under physical names: %v", err)
		}
		for _, canonical := range []string{"id", "email", "username"} {
			if _, ok := raw[canonical]; ok {
				t.Errorf("stored document has canonical key %q: %v", canonical, raw)
			}
		}
		if raw["email_address"] != user.Email || raw["handle"] != user.Username {
			t.Errorf("stored document: %v", raw)
		}
		if n, _ := mongoClient.Database(testutils.MongoDBName).Collection("users").CountDocuments(ctx, bson.M{}); n != 0 {
			t.Errorf("%d document(s) written to the canonical collection", n)
		}

		found, err := mapped.FindOne(ctx, &testutils.TestUser{}, getWhereExpr("email", clause.OpEqual, user.Email))
		if err != nil {
			t.Fatal(err)
		}
		if got := found.(*testutils.TestUser); *got != *user {
			t.Errorf("read back %+v, want %+v", got, user)
		}
	})

	t.Run("DuplicateKey", func(t *testing.T) {
		defer dropAll()
		// Only a unique index makes MongoDB reject a duplicate.
		_, err := mongoClient.Database(testutils.MongoDBName).Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: bson.D{{Key: "id", Value: 1}}, Options: options.Index().SetUnique(true),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Create(ctx, testutils.NewTestUser("dup")); err != nil {
			t.Fatal(err)
		}
		if err := adapter.Create(ctx, testutils.NewTestUser("dup")); !behemotherr.IsDuplicateKey(err) {
			t.Errorf("duplicate on a unique index: want duplicate_key, got %v", err)
		}
	})

	manager := &MongoAdapterTestManager{
		t:               t,
		client:          mongoClient,
		cleanupTables:   dropAll,
		cleanupDatabase: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestPostgresAdapter(t *testing.T) {
	ctx := t.Context()
	db, cleanupDatabase := testutils.SetupPostgresTestDBWithSchema(t, ctx, testutils.TestUserSchema)
	adapter := testutils.SetupPostgresAdapter(db)

	t.Run("UndefinedTable", func(t *testing.T) { assertUndefinedTable(t, adapter) })
	t.Run("ConstraintErrors", func(t *testing.T) {
		assertConstraintClassification(t, adapter, db,
			`CREATE TABLE memberships (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id))`)
	})

	// The whole suite again, against a table whose every name is physical-only.
	// Runs first: the standard suite's CleanupDatabase stops the container.
	t.Run("PhysicalNames", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `CREATE TABLE app_users (
			user_id TEXT PRIMARY KEY,
			email_address TEXT NOT NULL,
			handle TEXT UNIQUE NOT NULL
		)`); err != nil {
			t.Fatal(err)
		}
		manager := &PostgresAdapterTestManager{t: t, db: db, cleanup: func() {}}
		NewDatabaseTestSuite(t, pgAdapter.NewPostgresAdapter(db, physicalNamesResolver(t)), manager).Run()
	})

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

	t.Run("UndefinedTable", func(t *testing.T) { assertUndefinedTable(t, adapter) })
	t.Run("ConstraintErrors", func(t *testing.T) {
		// MySQL ignores column-level REFERENCES; the constraint must be table-level.
		assertConstraintClassification(t, adapter, db,
			`CREATE TABLE memberships (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))`)
	})

	// The whole suite again, against a table whose every name is physical-only.
	// Runs first: the standard suite's CleanupDatabase stops the container.
	t.Run("PhysicalNames", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `CREATE TABLE app_users (
			user_id CHAR(36) PRIMARY KEY,
			email_address VARCHAR(255) NOT NULL,
			handle VARCHAR(255) NOT NULL UNIQUE
		)`); err != nil {
			t.Fatal(err)
		}
		manager := &MySQLAdapterTestManager{t: t, db: db, cleanup: func() {}, table: "app_users"}
		NewDatabaseTestSuite(t, mysqlAdapter.NewMySQLAdapter(db, physicalNamesResolver(t)), manager).Run()
	})

	manager := &MySQLAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()
}

func TestMSSQLAdapter(t *testing.T) {
	ctx := t.Context()
	db, cleanupDatabase := testutils.SetupMSSQLTestDBWithSchema(t, ctx, testutils.TestMSSQLServerUserSchema)
	adapter := sqlserverAdapter.NewSQLServerAdapter(db, nil)

	t.Run("UndefinedTable", func(t *testing.T) { assertUndefinedTable(t, adapter) })
	t.Run("ConstraintErrors", func(t *testing.T) {
		assertConstraintClassification(t, adapter, db,
			`CREATE TABLE memberships (id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL REFERENCES users(id))`)
	})

	// The whole suite again, against a table whose every name is physical-only.
	// Runs first: the standard suite's CleanupDatabase stops the container.
	t.Run("PhysicalNames", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `CREATE TABLE app_users (
			user_id VARCHAR(36) PRIMARY KEY,
			email_address VARCHAR(255) NOT NULL,
			handle VARCHAR(255) NOT NULL UNIQUE
		)`); err != nil {
			t.Fatal(err)
		}
		manager := &MSSQLAdapterTestManager{t: t, db: db, cleanup: func() {}, table: "app_users"}
		NewDatabaseTestSuite(t, sqlserverAdapter.NewSQLServerAdapter(db, physicalNamesResolver(t)), manager).Run()
	})

	manager := &MSSQLAdapterTestManager{
		t:       t,
		db:      db,
		cleanup: cleanupDatabase,
	}

	suite := NewDatabaseTestSuite(t, adapter, manager)
	suite.Run()

}

func TestGormAdapter(t *testing.T) {
	db, cleanup := testutils.SetupGORMDBWithSchema(t, testutils.TestUserSchema)
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
	db, cleanup := testutils.SetupBunTestDBWithSchema(t, testutils.TestUserSchema)
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
	if m.cleanupTables != nil {
		m.cleanupTables()
		return
	}
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
	table   string // physical users table; "users" when empty
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
	table := m.table
	if table == "" {
		table = "users"
	}
	if _, err := m.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
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
	table   string // physical users table; "users" when empty
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
	table := m.table
	if table == "" {
		table = "users"
	}
	if _, err := m.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
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

// A standalone MongoDB server has no transactions. The adapter says so
// before any write is attempted.
func TestMongoAdapterRejectsAStandaloneServer(t *testing.T) {
	ctx := context.Background()
	container, err := mongodb.Run(ctx, "mongo:6") // no replica set
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(container) })
	uri, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(ctx) })

	err = mongoAdapter.NewMongoAdapter(client, testutils.MongoDBName, nil).CheckTransactions(ctx)
	if !behemotherr.Is(err, behemotherr.CategoryConfiguration) {
		t.Fatalf("CheckTransactions on a standalone server = %v, want a configuration error", err)
	}
	if !strings.Contains(err.Error(), "replica set") {
		t.Errorf("the error should say what to do: %v", err)
	}
}
