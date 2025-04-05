package storage

import (
	"database/sql"
	"fmt"

	"github.com/MastewalB/behemoth"
	_ "github.com/mattn/go-sqlite3"
)

type SQLlite[T behemoth.User] struct {
	DB    *sql.DB
	Table string
	PK    string
}

func (sqlt *SQLlite[T]) FindByPK(val any) (T, error) {
	var entity T

	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s = ?`, sqlt.Table, sqlt.PK)
	row := sqlt.DB.QueryRow(query, val)

	columns, err := getSQLiteColumnNames(sqlt.DB, sqlt.Table)
	if err != nil {
		return entity, err
	}

	fmt.Println("Columns from DB:", columns)
	entity, err = mapRowToStruct(row, entity, columns)
	return entity, err
}

func (sqlt *SQLlite[T]) SaveUser(user *behemoth.DefaultUser) error {
	return sqlt.WithTransaction(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
            INSERT INTO users 
                (id, email, username, firstname, lastname, password_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
        `,
			user.GetID(),
			user.GetEmail(),
			user.GetUsername(),
			user.GetFirstname(),
			user.GetLastname(),
			user.GetPasswordHash(),
		)
		return err
	})
}

func (sqlt *SQLlite[T]) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := sqlt.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // re-throw panic after rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx failed: %v, rollback failed: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
