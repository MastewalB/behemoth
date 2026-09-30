package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
)

var _ core.MigrationRenderer = (*SQLiteDriver)(nil)

// FileExtension implements [core.MigrationRenderer].
func (d *SQLiteDriver) FileExtension() string { return ".sql" }

// RenderMigration implements [core.MigrationRenderer].
//
// SQLite's table rebuilds derive their statements from the live schema, so
// rendering can't be a pure function of the Migration. Instead Up is executed
// in a transaction that is always rolled back, and every statement is recorded:
// the script is exactly what ApplyMigration would execute against the database
// in its current state — which is why it must be rendered before Apply.
//
// A baseline's Up is never executed; it renders the existing definitions of
// the tables it records, straight from sqlite_master.
func (d *SQLiteDriver) RenderMigration(ctx context.Context, m core.Migration) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "-- Migration: %s\n-- Generated: %s\n", m.ID, m.CreatedAt.Format(time.RFC3339))

	var stmts []string
	var err error
	if m.IsBaseline {
		b.WriteString("-- Baseline: records the existing schema; never executed by the runner.\n")
		stmts, err = d.renderBaseline(ctx, m)
	} else {
		stmts, err = d.renderDryRun(ctx, m)
	}
	if err != nil {
		return "", err
	}

	for _, stmt := range stmts {
		if strings.HasPrefix(stmt, `CREATE TABLE "`+rebuildTablePrefix) {
			b.WriteString("-- Contains table rebuilds: run with PRAGMA foreign_keys = OFF (set outside the\n" +
				"-- transaction), then check PRAGMA foreign_key_check before committing.\n")
			break
		}
	}
	b.WriteString("\n")
	for _, stmt := range stmts {
		fmt.Fprintf(&b, "%s;\n", strings.TrimSpace(stmt))
	}
	return b.String(), nil
}

func (d *SQLiteDriver) renderDryRun(ctx context.Context, m core.Migration) ([]string, error) {
	var rec *recordingTx
	err := d.inMigrationTx(ctx, "SQLiteDriver.RenderMigration", true, func(tx *sql.Tx) error {
		rec = &recordingTx{execQuerier: tx}
		for _, op := range m.Up {
			if err := d.applyOperation(ctx, rec, op); err != nil {
				return behemotherr.WrapOp("SQLiteDriver.RenderMigration", fmt.Sprintf("operation %q (%s on %s)", op.ID, op.Kind, op.Table), err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rec.stmts, nil
}

func (d *SQLiteDriver) renderBaseline(ctx context.Context, m core.Migration) ([]string, error) {
	var stmts []string
	for _, op := range m.Up {
		if op.Kind != core.OpCreateTable {
			continue // the table's indexes, triggers and FKs come with its sqlite_master entries
		}
		phys := d.resolver.Resolve(op.Table)
		defs, err := querySQLColumn(ctx, d.db, `SELECT sql FROM sqlite_master
			WHERE tbl_name = ? COLLATE NOCASE AND sql IS NOT NULL
			ORDER BY type = 'table' DESC, type, name`, phys)
		if err != nil {
			return nil, behemotherr.NewMigrationError("SQLiteDriver.RenderMigration", behemotherr.ErrorCodeMigrationQueryFailed, err)
		}
		if len(defs) == 0 {
			return nil, behemotherr.NewMigrationError("SQLiteDriver.RenderMigration", behemotherr.ErrorCodeMigrationTableNotFound,
				fmt.Errorf("baseline table %q does not exist", phys))
		}
		stmts = append(stmts, defs...)
	}
	return stmts, nil
}

// recordingTx records every executed statement, with bound arguments inlined
// so the script is runnable on its own. Reads pass through unrecorded.
type recordingTx struct {
	execQuerier
	stmts []string
}

func (r *recordingTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	r.stmts = append(r.stmts, inlineArgs(query, args))
	return r.execQuerier.ExecContext(ctx, query, args...)
}

// inlineArgs substitutes ? placeholders in order. The driver's own statements
// never contain a literal '?' outside a placeholder, so no quote-awareness is needed.
func inlineArgs(query string, args []any) string {
	for _, a := range args {
		var lit string
		switch v := a.(type) {
		case string:
			lit = "'" + strings.ReplaceAll(v, "'", "''") + "'"
		case nil:
			lit = "NULL"
		default:
			lit = fmt.Sprint(v)
		}
		query = strings.Replace(query, "?", lit, 1)
	}
	return query
}
