package storage

import (
	"database/sql"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
	_ "github.com/lib/pq"
)

type Postgres[T any] struct {
	DB    *sql.DB
	Table string
	PK    string
}

func (pg *Postgres[T]) FindByPK(val any) (T, error) {
	var entity T

	query := fmt.Sprintf(`SELECT * FROM %s WHERE %s = $1`, pg.Table, pg.PK)
	row := pg.DB.QueryRow(query, val)

	columns, err := getPGColumnNames(pg.DB, pg.Table)
	if err != nil {
		return entity, err
	}

	fmt.Println("Columns from DB:", columns)
	entity, err = mapRowToStruct(row, entity, columns)
	return entity, err
}

func (p *Postgres[T]) SaveUser(user *behemoth.DefaultUser) error {
	return p.WithTransaction(func(tx *sql.Tx) error {
		var emailExists, usernameExists bool

		err := tx.QueryRow(`
		SELECT 
                EXISTS(SELECT 1 FROM users WHERE email = $1),
                EXISTS(SELECT 1 FROM users WHERE username = $2)
		`, user.Email, user.Username).Scan(&emailExists, &usernameExists)

		if err != nil {
			return err
		}

		if !emailExists && !usernameExists {
			uuidStr := utils.GenerateUUID()

			_, err = tx.Exec(`
			INSERT INTO users 
			(id, email, username, firstname, lastname, password_hash)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT ON CONSTRAINT users_email_key DO NOTHING
			`,
				uuidStr,
				user.GetEmail(),
				user.GetUsername(),
				user.GetFirstname(),
				user.GetLastname(),
				user.GetPasswordHash())
		}
		return err
	})
}

func (p *Postgres[T]) WithTransaction(fn func(tx *sql.Tx) error) error {
	tx, err := p.DB.Begin()
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

func (p *Postgres[T]) Update(user behemoth.DefaultUser) error {
	return nil
}

func (p *Postgres[T]) Delete(user behemoth.DefaultUser) error {
	return nil
}
