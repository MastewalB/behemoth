package testutils

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/MastewalB/behemoth"
	_ "github.com/MastewalB/behemoth/migration/plugins/postgres"
	_ "github.com/MastewalB/behemoth/migration/plugins/sqlite"
	"github.com/MastewalB/behemoth/storage/adapters"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/microsoft/go-mssqldb"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

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

// SetupPostgresTestDB creates Postgres Container and returns *sql.DB opened from the container instance
// and a cleanup function to be called afterwards
func SetupPostgresTestDB(t *testing.T, ctx context.Context) (db *sql.DB, cleanup func()) {

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
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}

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
		"mysql:8.0.36",
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

	// Wait until MySQL is actually ready for connections.
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		_ = db.Close()
		_ = mysqlContainer.Terminate(ctx)
	}

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
	mongodbContainer, err := mongodb.Run(ctx, "mongo:6", mongodb.WithReplicaSet("rs0"))

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
		"mcr.microsoft.com/mssql/server:2019-latest",
		testcontainers.WithEnv(map[string]string{
			"ACCEPT_EULA": "Y",
			"SA_PASSWORD": password,
		}),
		testcontainers.WithExposedPorts("1433/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("1433/tcp"),
		),
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

	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		_ = db.Close()
		_ = mssqlContainer.Terminate(ctx)
	}

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

func SetupGORMDBWithSchema(t *testing.T, model behemoth.Model) (db *gorm.DB, cleanup func()) {
	db, cleanup = SetupGormTestDB(t)
	db.Exec("PRAGMA foreign_keys = ON;")
	db.AutoMigrate(model)

	return db, cleanup
}

func SetupRedisClient(t *testing.T, ctx context.Context) (*goredis.Client, func()) {

	redisContainer, err := redis.Run(ctx, "redis:7.4-alpine")
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

func SetupSQLiteAdapter(t *testing.T, db *sql.DB) *adapters.SQLiteAdapter {
	adapter := &adapters.SQLiteAdapter{DB: db}
	return adapter
}

func SetupInternalAdapter(t *testing.T, db behemoth.Database) *adapters.InternalAdapter {
	return &adapters.InternalAdapter{
		DB: db,
	}
}

func SetupGormAdapter(t *testing.T, db *gorm.DB) *adapters.GormAdapter {
	return adapters.NewGormAdapter(db)
}
