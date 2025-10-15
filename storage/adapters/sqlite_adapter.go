package adapters

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
)

type SQLiteAdapter struct {
	DB *sql.DB
}

func NewSQLiteAdapter(db *sql.DB) *SQLiteAdapter {
	return &SQLiteAdapter{DB: db}
}

func (sqlt *SQLiteAdapter) Create(ctx context.Context, m behemoth.Model) error {
	query := `INSERT INTO ` + m.TableName() + ` (` +
		strings.Join(m.Fields(), ", ") + `) VALUES ` +
		utils.GenerateSqlitePlaceholders(len(m.Fields()))

	fmt.Println("Executing query:", query, "with values:", m.ScanDestinations())
	_, err := sqlt.DB.ExecContext(ctx, query, m.ScanDestinations()...)
	return err
}

func (sqlt *SQLiteAdapter) Find(ctx context.Context, m behemoth.Model, where string, args ...any) (behemoth.Model, error) {
	query := `SELECT * FROM ` + m.TableName() + ` WHERE ` + where + ` LIMIT 1`
	fmt.Println("Executing query:", query, "with args:", args)
	row := sqlt.DB.QueryRowContext(ctx, query, args...)

	err := row.Scan(m.ScanDestinations()...)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (sqlt *SQLiteAdapter) Update(ctx context.Context, m behemoth.Model) error {
	query := `UPDATE ` + m.TableName() +
		` SET ` + utils.GenerateSQLiteSETClause(m.Fields()) +
		` WHERE ` + m.PrimaryKey() + ` = ?`

	_, err := sqlt.DB.ExecContext(ctx, query, append(m.ScanDestinations(), m.PrimaryValue())...)
	return err
}

func (sqlt *SQLiteAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := `DELETE FROM ` + m.TableName() + ` WHERE ` + m.PrimaryKey() + ` = ?`
	_, err := sqlt.DB.ExecContext(ctx, query, m.PrimaryValue())
	return err
}
