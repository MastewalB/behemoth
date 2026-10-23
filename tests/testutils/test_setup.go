package testutils

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	bunAdapter "github.com/MastewalB/behemoth/storage/adapters/bun"
	gormAdapter "github.com/MastewalB/behemoth/storage/adapters/gorm"
	mongoAdapter "github.com/MastewalB/behemoth/storage/adapters/mongo"
	mysqlAdapter "github.com/MastewalB/behemoth/storage/adapters/mysql"
	pgAdapter "github.com/MastewalB/behemoth/storage/adapters/postgres"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	sqlserverAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlserver"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/microsoft/go-mssqldb"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/uptrace/bun"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var MongoDBName = "testdb"

// The images the container suites start. Each is the oldest release Behemoth
// supports (docs/api/supported-databases.md), and an environment variable
// replaces it, so the suites can run against any other release, such as the
// newest:
//
//	BEHEMOTH_TEST_POSTGRES_IMAGE=postgres:17 go test ./storage/...
const (
	defaultPostgresImage = "postgres:15"
	defaultMySQLImage    = "mysql:8.4"
	defaultMongoImage    = "mongo:7.0"
	defaultMSSQLImage    = "mcr.microsoft.com/mssql/server:2019-latest"
	defaultRedisImage    = "redis:6.2-alpine"
)

// Image returns the image named by the environment variable env, or def when
// the variable is empty.
func Image(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

// PostgresImage, MySQLImage, MongoImage, MSSQLImage and RedisImage return the
// image a container suite starts for that database.
func PostgresImage() string { return Image("BEHEMOTH_TEST_POSTGRES_IMAGE", defaultPostgresImage) }
func MySQLImage() string    { return Image("BEHEMOTH_TEST_MYSQL_IMAGE", defaultMySQLImage) }
func MongoImage() string    { return Image("BEHEMOTH_TEST_MONGO_IMAGE", defaultMongoImage) }
func MSSQLImage() string    { return Image("BEHEMOTH_TEST_MSSQL_IMAGE", defaultMSSQLImage) }
func RedisImage() string    { return Image("BEHEMOTH_TEST_REDIS_IMAGE", defaultRedisImage) }

func SetupSQLiteTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	return db
}

func SetupSQLiteTestDBWithSchema(t *testing.T, schema string) *sql.DB {
	db := SetupSQLiteTestDB(t)
	_, err := db.Exec(schema)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	return db
}

// waitForLogin pings db until the server accepts a login, for up to a
// minute. A container's wait strategy can pass a moment before that: the
// port is open, or the "ready" line is logged, and the first login is still
// reset, more often on a busy CI runner. On failure it calls cleanup, so the
// container does not outlive the test.
func waitForLogin(t *testing.T, ctx context.Context, db *sql.DB, cleanup func(), name string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			cleanup()
			t.Fatalf("%s did not accept a login within a minute: %v", name, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// SetupPostgresTestDB creates Postgres Container and returns *sql.DB opened from the container instance
// and a cleanup function to be called afterwards
func SetupPostgresTestDB(t *testing.T, ctx context.Context) (db *sql.DB, cleanup func()) {

	req := testcontainers.ContainerRequest{
		Image:        PostgresImage(),
		Env:          map[string]string{"POSTGRES_PASSWORD": "secret", "POSTGRES_DB": "testdb"},
		ExposedPorts: []string{"5432/tcp"},
		// The image starts a server for its setup and then restarts it, and
		// Docker's port proxy accepts connections before either is up. The
		// second "ready" line is the server the tests use.
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("5432/tcp"),
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
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
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}
	waitForLogin(t, ctx, db, cleanup, "Postgres")

	return db, cleanup
}

func SetupPostgresTestDBWithSchema(t *testing.T, ctx context.Context, schema string) (db *sql.DB, cleanup func()) {
	db, cleanup = SetupPostgresTestDB(t, ctx)

	_, err := db.Exec(schema)
	if err != nil {
		t.Fatal(err)
	}

	return db, cleanup
}

func SetupMySQLTestDB(t *testing.T, ctx context.Context) (db *sql.DB, cleanup func()) {

	mysqlContainer, err := mysql.Run(ctx,
		MySQLImage(),
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("root"),
		mysql.WithPassword("secret"),
	)
	if err != nil {
		t.Fatal(err)
	}

	connStr, err := mysqlContainer.ConnectionString(ctx, "tls=false")
	if err != nil {
		t.Fatal(err)
	}

	db, err = sql.Open("mysql", connStr)
	if err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		_ = db.Close()
		_ = mysqlContainer.Terminate(ctx)
	}
	waitForLogin(t, ctx, db, cleanup, "MySQL")

	return db, cleanup
}

func SetupMySQLTestDBWithSchema(t *testing.T, ctx context.Context, schema string) (db *sql.DB, cleanup func()) {
	db, cleanup = SetupMySQLTestDB(t, ctx)

	_, err := db.Exec(schema)
	if err != nil {
		t.Fatal(err)
	}

	return db, cleanup
}

func SetupMongoTestDB(ctx context.Context, t *testing.T) (*mongo.Client, func()) {
	// Create a new MongoDB container.
	// Use ReplicaSet for transactions support.
	mongodbContainer, err := mongodb.Run(ctx, MongoImage(), mongodb.WithReplicaSet("rs0"))

	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}

	host, _ := mongodbContainer.Host(ctx)
	port, _ := mongodbContainer.MappedPort(ctx, "27017")
	mongoURI := fmt.Sprintf("mongodb://%s:%s", host, port.Port())

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))

	if err != nil {
		t.Fatalf("failed to connect to MongoDB: %v", err)
	}

	cleanup := func() {
		if err := testcontainers.TerminateContainer(mongodbContainer); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}
	return mongoClient, cleanup
}

func CleanupMongoTestDB(ctx context.Context, t *testing.T, client *mongo.Client, dbName string) error {
	collections, err := client.Database(dbName).ListCollectionNames(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	for _, coll := range collections {
		err := client.Database(dbName).Collection(coll).Drop(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to drop collection %s: %w", coll, err)
		}
	}
	return nil
}

func SetupMSSQLTestDB(t *testing.T) (db *sql.DB, cleanup func()) {
	ctx := context.Background()

	password := "SuperStrong@Passw0rd"
	mssqlContainer, err := testcontainers.Run(
		ctx,
		MSSQLImage(),
		testcontainers.WithEnv(map[string]string{
			"ACCEPT_EULA": "Y",
			"SA_PASSWORD": password,
		}),
		testcontainers.WithExposedPorts("1433/tcp"),
		// SQL Server opens its port before it accepts logins, so the
		// port alone is not enough. The log line comes once it does.
		testcontainers.WithWaitStrategy(wait.ForAll(
			wait.ForListeningPort("1433/tcp"),
			wait.ForLog("SQL Server is now ready for client connections").WithStartupTimeout(2*time.Minute),
		)),
	)

	if err != nil {
		t.Fatal(err)
	}

	host, err := mssqlContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	port, err := mssqlContainer.MappedPort(ctx, "1433/tcp")
	if err != nil {
		t.Fatal(err)
	}

	connStr := fmt.Sprintf(
		"sqlserver://sa:%s@%s:%s?encrypt=false&TrustServerCertificate=true",
		password,
		host,
		port.Port(),
	)

	db, err = sql.Open("sqlserver", connStr)
	if err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		_ = db.Close()
		_ = mssqlContainer.Terminate(ctx)
	}
	waitForLogin(t, ctx, db, cleanup, "SQL Server")

	return db, cleanup

}

func SetupMSSQLTestDBWithSchema(t *testing.T, ctx context.Context, schema string) (db *sql.DB, cleanup func()) {
	db, cleanup = SetupMSSQLTestDB(t)
	_, err := db.Exec(schema)
	if err != nil {
		t.Fatal(err)
	}

	return db, cleanup
}

func SetupGormTestDB(t *testing.T) (*gorm.DB, func()) {
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		t.Fatal("failed to connect database")
	}

	cleanup := func() {
		if sqliteDB, err := db.DB(); err == nil {
			sqliteDB.Close()
		}
	}

	return db, cleanup
}

// SetupGORMDBWithSchema opens a GORM database and runs schema (DDL) on it.
// The tables come from the DDL, not from AutoMigrate: the adapter never
// hands GORM a struct, so the test models need no gorm tags or TableName.
func SetupGORMDBWithSchema(t *testing.T, schema string) (db *gorm.DB, cleanup func()) {
	db, cleanup = SetupGormTestDB(t)
	if err := db.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		t.Fatalf("failed to enable foreign keys: %v", err)
	}
	if err := db.Exec(schema).Error; err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	return db, cleanup
}

func SetupBunTestDB(t *testing.T) (db *bun.DB, cleanup func()) {
	dbName := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())

	sqldb, err := sql.Open(sqliteshim.ShimName, dbName)
	if err != nil {
		t.Fatal("failed to connect database")
	}

	cleanup = func() {
		sqldb.Close()
	}

	db = bun.NewDB(sqldb, sqlitedialect.New())

	return db, cleanup
}

// SetupBunTestDBWithSchema opens a bun database and runs schema (DDL) on it.
// The tables come from the DDL, not from NewCreateTable().Model: the adapter
// never hands bun a struct, so the test models need no bun.BaseModel or tags.
func SetupBunTestDBWithSchema(t *testing.T, schema string) (db *bun.DB, cleanup func()) {
	db, cleanup = SetupBunTestDB(t)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	return db, cleanup
}

func SetupRedisClient(t *testing.T, ctx context.Context) (*goredis.Client, func()) {

	redisContainer, err := redis.Run(ctx, RedisImage())
	assert.NoError(t, err)
	cleanup := func() { _ = redisContainer.Terminate(ctx) }

	connStr, err := redisContainer.ConnectionString(ctx)
	assert.NoError(t, err)

	opts, err := goredis.ParseURL(connStr)
	assert.NoError(t, err)

	client := goredis.NewClient(opts)

	return client, cleanup
}

// Adapter Setups

func SetupSQLiteAdapter(t *testing.T, db *sql.DB) *sqliteAdapter.SQLiteAdapter {
	adapter := &sqliteAdapter.SQLiteAdapter{DB: db}
	return adapter
}

func SetupGormAdapter(t *testing.T, db *gorm.DB) *gormAdapter.GormAdapter {
	return gormAdapter.NewGormAdapter(db, nil)
}

func SetupBunAdapter(t *testing.T, db *bun.DB) *bunAdapter.BunAdapter {
	return bunAdapter.NewBunAdapter(db, nil)
}

func SetupMongoAdapter(t *testing.T, client *mongo.Client, dbName string) *mongoAdapter.MongoAdapter {
	return mongoAdapter.NewMongoAdapter(client, dbName, nil)
}

func SetupPostgresAdapter(db *sql.DB) *pgAdapter.PostgresAdapter {
	return pgAdapter.NewPostgresAdapter(db, nil)
}

func SetupMySQLAdapter(db *sql.DB) *mysqlAdapter.MySQLAdapter {
	return mysqlAdapter.NewMySQLAdapter(db, nil)
}

func SetupMSSQLAdapter(db *sql.DB) *sqlserverAdapter.SQLServerAdapter {
	return sqlserverAdapter.NewSQLServerAdapter(db, nil)
}
