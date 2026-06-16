package core

import (
	"context"
	"errors"
)

// Common errors
var (
	ErrMigrationNotFound = errors.New("migration not found")
	ErrVersionNotFound   = errors.New("version not found")
	ErrPluginNotFound    = errors.New("plugin not found")
)

type Migration struct {
	Version     int
	Description string
	Up          func(ctx context.Context, driver Driver) error
	Down        func(ctx context.Context, driver Driver) error
}

type Driver interface {
	CreateTable(ctx context.Context, name string, schema *TableSchema) error
	DropTable(ctx context.Context, name string) error
	AddColumn(ctx context.Context, table, column, columnType string) error
	RemoveColumn(ctx context.Context, table, column string) error

	CreateMigrationTable(ctx context.Context) error

	Open(config map[string]any) (Driver, error)

	// Run executes raw migration string
	Run(ctx context.Context, migration string) error

	// Version returns the currently active version.
	// When no migration has been applied, it must return version -1.
	Version(ctx context.Context) (version int, err error)

	SetVersion(ctx context.Context, version int) error

	Close() error
	Ping(ctx context.Context) error

	Name() string
}

type TableSchema struct {
	Name    string
	Columns []Column
	Indexes []Index
}

type Column struct {
	Name     string
	Type     string
	Nullable bool
	Unique   bool
	Primary  bool
}

type Index struct {
	Name    string
	Columns []string
	Unique  bool
}
