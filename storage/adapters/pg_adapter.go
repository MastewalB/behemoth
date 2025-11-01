package adapters

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/utils"
)

type PostgresAdapter struct {
	DB *sql.DB
}

func NewPostgresAdapter(db *sql.DB) *PostgresAdapter {
	return &PostgresAdapter{DB: db}
}

func (pg *PostgresAdapter) Create(ctx context.Context, m behemoth.Model) error {
	query := `INSERT INTO ` + m.TableName() + ` (` +
		strings.Join(m.Fields(), ", ") + `) VALUES ` +
		utils.GenerateSQLPlaceholders(len(m.Fields()))

	_, err := pg.DB.ExecContext(ctx, query, m.ScanDestinations()...)
	return err
}

func (pg *PostgresAdapter) Find(ctx context.Context, m behemoth.Model, whereExpression clause.Expression) (behemoth.Model, error) {
	whereClause, args := BuildSQLiteWhereClause(&whereExpression, 1)
	query := `SELECT * FROM ` + m.TableName() + ` WHERE ` + whereClause + ` LIMIT 1`
	fmt.Println("Executing query:", query, "with args:", args)
	row := pg.DB.QueryRowContext(ctx, query, args...)

	err := row.Scan(m.ScanDestinations()...)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (pg *PostgresAdapter) Update(ctx context.Context, m behemoth.Model) error {
	query := `UPDATE ` + m.TableName() +
		` SET ` + utils.GenerateSQLSETClause(m.Fields()) +
		` WHERE ` + m.PrimaryKey() + ` = $` + fmt.Sprint(len(m.Fields())+1)

	_, err := pg.DB.ExecContext(ctx, query, append(m.ScanDestinations(), m.PrimaryValue())...)
	return err
}

func (pg *PostgresAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	query := `DELETE FROM ` + m.TableName() + ` WHERE ` + m.PrimaryKey() + ` = $1`
	_, err := pg.DB.ExecContext(ctx, query, m.PrimaryValue())
	return err
}
