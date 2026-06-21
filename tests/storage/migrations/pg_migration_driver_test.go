package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// PostgresTestManager implements the DriverTestManager interface.
type PostgresTestManager struct {
	db          *sql.DB
	cleanupFunc func()
}

func NewPostgresTestManager(db *sql.DB, cleanupFunc func()) *PostgresTestManager {
	return &PostgresTestManager{
		db:          db,
		cleanupFunc: cleanupFunc,
	}
}

func (pgtm *PostgresTestManager) TableExists(ctx context.Context, tableName string) (bool, error) {
	query := `SELECT EXISTS (
					SELECT 1 
					FROM information_schema.tables 
					WHERE table_schema = 'public' 
						AND table_name = $1
				)
			`
	var exists bool
	err := pgtm.db.QueryRowContext(ctx, query, tableName).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (pgtm *PostgresTestManager) ColumnExists(ctx context.Context, tableName, columnName string) (bool, error) {
	// query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	// rows, err := pgtm.db.QueryContext(ctx, query)
	// if err != nil {
	// 	return false, err
	// }
	// defer rows.Close()

	// for rows.Next() {
	// 	var cid int
	// 	var name, ctype string
	// 	var notnull, pk int
	// 	var dflt sql.NullString
	// 	if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
	// 		return false, err
	// 	}
	// 	if name == columnName {
	// 		return true, nil
	// 	}
	// }
	return false, nil
}

func (pgtm *PostgresTestManager) IndexExists(ctx context.Context, tableName, indexName string) (bool, error) {
	// query := `SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND name=?`
	// var name string
	// err := pgtm.db.QueryRowContext(ctx, query, tableName, indexName).Scan(&name)
	// if err == sql.ErrNoRows {
	// 	return false, nil
	// }
	// if err != nil {
	// 	return false, err
	// }
	return true, nil
}

func (pgtm *PostgresTestManager) TableRowCount(ctx context.Context, tableName string) (int64, error) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	var count int64
	err := pgtm.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func (pgtm *PostgresTestManager) MigrationTableExists(ctx context.Context) (bool, error) {
	return pgtm.TableExists(ctx, "schema_migrations")
}

func (pgtm *PostgresTestManager) GetMigrationVersion(ctx context.Context) (int, error) {
	var version int
	err := pgtm.db.QueryRowContext(ctx, "SELECT version FROM schema_migrations LIMIT 1").Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return version, err
}

func (pgtm *PostgresTestManager) Cleanup(ctx context.Context) error {
	return pgtm.DropAllTables(ctx)
}

func (pgtm *PostgresTestManager) DropAllTables(ctx context.Context) error {
	// tables, err := pgtm.db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	// if err != nil {
	// 	return err
	// }
	// defer tables.Close()

	// for tables.Next() {
	// 	var name string
	// 	if err := tables.Scan(&name); err != nil {
	// 		return err
	// 	}
	// 	if _, err := pgtm.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
	// 		return err
	// 	}
	// }

	_, err := pgtm.db.ExecContext(ctx, `
    	DROP SCHEMA public CASCADE;
    	CREATE SCHEMA public;
	`)
	
	if err != nil {
		return err
	}
	return nil
}

func (pgtm *PostgresTestManager) InsertTestData(ctx context.Context, tableName string, data map[string]interface{}) error {
	columns := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))
	values := make([]any, 0, len(data))

	for col, val := range data {
		columns = append(columns, col)
		placeholders = append(placeholders, "?")
		values = append(values, val)
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "))

	_, err := pgtm.db.ExecContext(ctx, query, values...)
	return err
}

func (pgtm *PostgresTestManager) QueryTable(ctx context.Context, tableName string, query string) ([]map[string]interface{}, error) {
	rows, err := pgtm.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]any
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}
	return results, nil
}

func (pgtm *PostgresTestManager) CleanupDatabase(ctx context.Context) {
	pgtm.cleanupFunc()
}
