package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth/migration/core"
)

func init() {
	core.Register("sqlite", &SQLiteDriver{})
}

type Config struct {
}

type SQLiteDriver struct {
	db     *sql.DB
	config *Config
}

func NewSQLiteDriver(config map[string]any) (core.Driver, error) {
	return &SQLiteDriver{}, nil
}

func WithInstance(ctx context.Context, db *sql.DB, config *Config) (core.Driver, error) {
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return &SQLiteDriver{
		db:     db,
		config: config,
	}, nil
}

func (sqld *SQLiteDriver) CreateTable(ctx context.Context, name string, schema *core.TableSchema) error {

	query := CreateTable(schema)
	_, err := sqld.db.ExecContext(ctx, query)
	return err
}

func (sqld *SQLiteDriver) DropTable(ctx context.Context, name string) error {
	query := DropTable(name)
	_, err := sqld.db.ExecContext(ctx, query)
	return err
}

func (sqld *SQLiteDriver) AddColumn(ctx context.Context, table, column, columnType string) error {
	query := AddColumn(table, column, columnType)
	_, err := sqld.db.ExecContext(ctx, query)
	return err
}

func (sqld *SQLiteDriver) RemoveColumn(ctx context.Context, table, column string) error {
	return fmt.Errorf("SQLite doesn't support DROP COLUMN, recreate table instead.")
}

func (sqld *SQLiteDriver) CreateMigrationTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	_, err := sqld.db.ExecContext(ctx, query)
	return err
}

func (sqld *SQLiteDriver) Open(config map[string]any) (core.Driver, error) {
	dbInstance, exists := config["db"]
	if !exists {
		return nil, fmt.Errorf("sql db instance required")
	}
	db, ok := dbInstance.(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("unknown sql db instance provided")
	}

	return WithInstance(context.Background(), db, &Config{})
}

func (sqld *SQLiteDriver) Run(ctx context.Context, migration string) error {
	_, err := sqld.db.ExecContext(ctx, migration)
	return err
}

func (sqld *SQLiteDriver) Version(ctx context.Context) (version int, err error) {
	query := "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
	err = sqld.db.QueryRowContext(ctx, query).Scan(&version)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	return version, err
}

func (sqld *SQLiteDriver) SetVersion(ctx context.Context, version int) error {
	query := "UPDATE schema_migrations SET version = ?"
	_, err := sqld.db.ExecContext(ctx, query, version)
	return err
}

func (sqld *SQLiteDriver) Close() error {
	return sqld.db.Close()
}

func (sqld *SQLiteDriver) Ping(ctx context.Context) error {
	return sqld.db.PingContext(ctx)
}

func (sqld *SQLiteDriver) Name() string {
	return "sqlite"
}

func getColumnType(col string) string {
	switch col {
	case "string", "text":
		return "TEXT"
	case "int", "integer":
		return "INTEGER"
	case "bool", "boolean":
		return "BOOLEAN"
	case "datetime", "time":
		return "DATETIME"
	default:
		return "TEXT"
	}
}

func CreateTable(tableSchema *core.TableSchema) string {
	var query strings.Builder

	fmt.Fprintf(&query, "CREATE TABLE IF NOT EXISTS %s (", tableSchema.Name)
	for i, col := range tableSchema.Columns {
		if i > 0 {
			query.WriteString(",")
		}

		query.WriteString(fmt.Sprintf(" %s %s", col.Name, getColumnType(col.Type)))
		if col.Primary {
			query.WriteString(" PRIMARY KEY")
		}
		if !col.Nullable {
			query.WriteString(" NOT NULL")
		}
		if col.Unique {
			query.WriteString(" UNIQUE")
		}
	}

	query.WriteString(" )")
	return query.String()
}

func DropTable(name string) string {
	return fmt.Sprintf("DROP TABLE IF EXISTS %s", name)
}

func AddColumn(table, column, colType string) string {
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, colType)
}
