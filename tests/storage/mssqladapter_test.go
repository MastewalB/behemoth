package models

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func SetupMSSQLServerTestDB(t *testing.T, schema string) (*sql.DB, func()) {
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

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		t.Fatal(err)
	}

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
		_ = mssqlContainer.Terminate(ctx)
	}

	return db, cleanup

}
