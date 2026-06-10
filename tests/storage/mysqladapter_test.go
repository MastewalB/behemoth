package models

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
)

func setupMySQLTestDB(t *testing.T, schema string) (*sql.DB, func()) {
	ctx := context.Background()

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

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		t.Fatal(err)
	}

	// Wait until MySQL is actually ready for connections.
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}

	// Migration/setup logic here.
	_, err = db.Exec(schema)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = mysqlContainer.Terminate(ctx)
	}

	return db, cleanup
}
