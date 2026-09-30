package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
)

// pgTypeMapping implements Tier 0 (same-family native types collapse to one
// canonical type) directly — every string-ish Postgres type maps to
// ColTypeString/ColTypeText without flagging an ambiguity, since database/sql
// already scans all of them into a Go string uniformly. Keys are
// information_schema.columns.data_type values.
var pgTypeMapping = map[string]core.ColumnType{
	"character varying":           core.ColTypeString,
	"character":                   core.ColTypeString, // CHAR(n) — fixed-width, still string-compatible
	"text":                        core.ColTypeText,
	"smallint":                    core.ColTypeInteger,
	"integer":                     core.ColTypeInteger,
	"bigint":                      core.ColTypeBigInt,
	"real":                        core.ColTypeReal,
	"double precision":            core.ColTypeReal,
	"numeric":                     core.ColTypeNumeric,
	"boolean":                     core.ColTypeBoolean,
	"timestamp without time zone": core.ColTypeDateTime,
	"timestamp with time zone":    core.ColTypeTimestamp,
	"uuid":                        core.ColTypeUuid,
	"json":                        core.ColTypeJson,
	"jsonb":                       core.ColTypeJson,
	"bytea":                       core.ColTypeBytes,
}

// mapPgType returns the canonical type, or (ColTypeText, ambiguity) as a safe
// fallback for anything not in the table — NEVER silently guessed as a
// specific canonical type it might not actually be. ColTypeText is chosen as
// the fallback because it's the loosest, least lossy landing spot (a value
// scanned as a Go string is always representable), not because it's presumed
// correct.
func mapPgType(dataType, udtName string) (core.ColumnType, *core.ColumnAmbiguity) {
	if ct, ok := pgTypeMapping[dataType]; ok {
		return ct, nil
	}
	native := dataType
	if dataType == "USER-DEFINED" || dataType == "ARRAY" {
		native = udtName // e.g. an enum's name, or "_int4" for integer[]
	}
	return core.ColTypeText, &core.ColumnAmbiguity{Reason: fmt.Sprintf("unrecognized Postgres type %q — defaulted to text; verify manually", native)}
}

// TableExists implements [core.SchemaIntrospector]. Any relation counts —
// a view or sequence of the same name is reported by Introspect as an
// incompatible object rather than hidden here.
func (d *PostgreSQLDriver) TableExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := d.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relname = $1
		)`, d.resolver.Resolve(name)).Scan(&exists)
	if err != nil {
		return false, behemotherr.NewMigrationError("PostgresIntrospector.TableExists", "query_failed", err)
	}
	return exists, nil
}

// relKind maps pg_class.relkind to ObjectKind — this is what backs the
// "table found live as incompatible object" branch of RunIntrospection.
func (d *PostgreSQLDriver) relKind(ctx context.Context, physical string) (kind core.ObjectKind, exists bool, err error) {
	var relkind string
	err = d.db.QueryRowContext(ctx, `
		SELECT c.relkind FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = $1`, physical).Scan(&relkind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, behemotherr.NewMigrationError("PostgresIntrospector.relKind", "query_failed", err)
	}
	switch relkind {
	case "r", "p": // ordinary table, or partitioned-table parent
		return core.ObjectTable, true, nil
	case "v", "m":
		return core.ObjectView, true, nil
	default:
		return core.ObjectOther, true, nil
	}
}

// Introspect implements [core.SchemaIntrospector]: a best-effort reverse
// mapping of one live table into the canonical model.
//
// Column names are returned as their physical names: SchemaResolver maps
// canonical -> physical only, so a column whose physical name differs from
// its canonical one can't be mapped back here.
func (d *PostgreSQLDriver) Introspect(ctx context.Context, name string) (core.IntrospectedTable, error) {
	physical := d.resolver.Resolve(name)

	kind, exists, err := d.relKind(ctx, physical)
	if err != nil || !exists {
		return core.IntrospectedTable{}, err
	}
	if kind != core.ObjectTable {
		return core.IntrospectedTable{Kind: kind, Exists: true}, nil // caller checks Kind before touching Schema
	}

	pkCols, err := d.primaryKeyColumns(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	uniqueSingle, uniqueComposite, err := d.uniqueConstraints(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	cols, ambiguities, err := d.introspectColumns(ctx, physical, pkCols, uniqueSingle)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	indexes, err := d.introspectIndexes(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	indexes = append(indexes, uniqueComposite...) // multi-column UNIQUE constraints are representable as Index{Unique: true}
	fks, err := d.introspectForeignKeys(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}

	return core.IntrospectedTable{
		Kind:        core.ObjectTable,
		Exists:      true,
		Schema:      core.TableSchema{Name: name, PhysicalName: physical, Columns: cols, Indexes: indexes, ForeignKeys: fks},
		Ambiguities: ambiguities,
	}, nil
}

func (d *PostgreSQLDriver) introspectColumns(ctx context.Context, physical string, pkCols, uniqueCols []string) ([]core.Column, []core.ColumnAmbiguity, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT column_name, data_type, udt_name, character_maximum_length, is_nullable, column_default, is_identity
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1
		ORDER BY ordinal_position`, physical)
	if err != nil {
		return nil, nil, behemotherr.NewMigrationError("PostgresIntrospector.columns", "query_failed", err)
	}
	defer rows.Close()

	pkSet, uniqueSet := toSet(pkCols), toSet(uniqueCols)
	var cols []core.Column
	var ambiguities []core.ColumnAmbiguity

	for rows.Next() {
		var name, dataType, udtName, isNullable, isIdentity string
		var length sql.NullInt64
		var defaultExpr sql.NullString
		if err := rows.Scan(&name, &dataType, &udtName, &length, &isNullable, &defaultExpr, &isIdentity); err != nil {
			return nil, nil, behemotherr.NewMigrationError("PostgresIntrospector.columns", "scan_failed", err)
		}

		ct, ambig := mapPgType(dataType, udtName)
		if ambig != nil {
			ambig.Column = name
			ambiguities = append(ambiguities, *ambig)
		}
		if ct == core.ColTypeString && !length.Valid {
			ct = core.ColTypeText // VARCHAR without a length is unbounded — the same thing as TEXT
		}

		col := core.Column{
			Name: name, Type: ct, Length: int(length.Int64),
			Nullable: isNullable == "YES", PrimaryKey: pkSet[name], Unique: uniqueSet[name] && !pkSet[name],
			AutoInc: isIdentity == "YES",
		}

		if defaultExpr.Valid {
			switch val, isLiteral := parsePgDefault(defaultExpr.String); {
			case strings.HasPrefix(defaultExpr.String, "nextval("):
				col.AutoInc = true // serial / bigserial: the sequence is the auto-increment
			case isLiteral:
				col.Default = val
			default:
				// A function/expression default (now(), gen_random_uuid(), ...)
				// isn't a data literal; parsing it into Default would be a
				// guess. It's kept verbatim as a raw Postgres expression —
				// exactly what an override Default means, and what the
				// renderer emits unchanged.
				col.Overrides = map[string]core.ColumnOverride{DriverName: {Default: defaultExpr.String}}
			}
		}
		cols = append(cols, col)
	}
	return cols, ambiguities, rows.Err()
}

// parsePgDefault interprets the literal forms Postgres reports via
// column_default: a quoted string with an optional cast ('x'::type), a bare
// or parenthesized number, a boolean, or NULL. Anything else (function calls,
// nextval, CURRENT_*) is NOT interpreted and returned as non-literal.
func parsePgDefault(expr string) (value any, isLiteral bool) {
	expr = strings.TrimSpace(expr)

	if strings.HasPrefix(expr, "'") {
		// Scan to the closing quote ('' is an escaped quote); what follows may
		// only be a cast.
		for i := 1; i < len(expr); i++ {
			if expr[i] != '\'' {
				continue
			}
			if i+1 < len(expr) && expr[i+1] == '\'' {
				i++
				continue
			}
			rest := expr[i+1:]
			if rest != "" && !strings.HasPrefix(rest, "::") {
				return nil, false
			}
			return strings.ReplaceAll(expr[1:i], "''", "'"), true
		}
		return nil, false
	}

	if idx := strings.Index(expr, "::"); idx != -1 {
		expr = expr[:idx] // e.g. "NULL::character varying", "(-1)::integer"
	}
	expr = strings.TrimSuffix(strings.TrimPrefix(expr, "("), ")")

	if n, err := strconv.ParseInt(expr, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(expr, 64); err == nil {
		return f, true
	}
	switch expr {
	case "true":
		return true, true
	case "false":
		return false, true
	case "NULL":
		return nil, true
	}
	return nil, false
}

func (d *PostgreSQLDriver) primaryKeyColumns(ctx context.Context, physical string) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT a.attname
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE n.nspname = current_schema() AND t.relname = $1 AND c.contype = 'p'
		ORDER BY k.ord`, physical)
	if err != nil {
		return nil, behemotherr.NewMigrationError("PostgresIntrospector.primaryKey", "query_failed", err)
	}
	defer rows.Close()
	return scanStrings(rows)
}

// uniqueConstraints splits single-column UNIQUE constraints (mapped onto
// Column.Unique) from multi-column ones (which have no per-column
// representation and become an Index{Unique: true} instead).
func (d *PostgreSQLDriver) uniqueConstraints(ctx context.Context, physical string) (single []string, composite []core.Index, err error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT c.conname, a.attname
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE n.nspname = current_schema() AND t.relname = $1 AND c.contype = 'u'
		ORDER BY c.conname, k.ord`, physical)
	if err != nil {
		return nil, nil, behemotherr.NewMigrationError("PostgresIntrospector.unique", "query_failed", err)
	}
	defer rows.Close()

	grouped := map[string][]string{}
	var order []string
	for rows.Next() {
		var constraintName, colName string
		if err := rows.Scan(&constraintName, &colName); err != nil {
			return nil, nil, behemotherr.NewMigrationError("PostgresIntrospector.unique", "scan_failed", err)
		}
		if _, seen := grouped[constraintName]; !seen {
			order = append(order, constraintName)
		}
		grouped[constraintName] = append(grouped[constraintName], colName)
	}
	for _, name := range order {
		if cols := grouped[name]; len(cols) == 1 {
			single = append(single, cols[0])
		} else {
			composite = append(composite, core.Index{Name: name, Columns: cols, Unique: true})
		}
	}
	return single, composite, rows.Err()
}

// introspectIndexes returns explicitly created indexes only. Postgres
// auto-creates a backing index for every PRIMARY KEY and UNIQUE constraint;
// those are already represented via Column.PrimaryKey/Unique (or, for a
// composite UNIQUE, by uniqueConstraints), and including them would show a
// phantom "extra live index" on every diff. Expression indexes are skipped:
// the canonical Index has no way to express them.
func (d *PostgreSQLDriver) introspectIndexes(ctx context.Context, physical string) ([]core.Index, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT ix.relname, a.attname, i.indisunique
		FROM pg_class t
		JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_index i ON i.indrelid = t.oid
		JOIN pg_class ix ON ix.oid = i.indexrelid
		JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE n.nspname = current_schema() AND t.relname = $1
			AND i.indexprs IS NULL
			AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = ix.oid AND c.contype IN ('p', 'u', 'x'))
		ORDER BY ix.relname, k.ord`, physical)
	if err != nil {
		return nil, behemotherr.NewMigrationError("PostgresIntrospector.indexes", "query_failed", err)
	}
	defer rows.Close()

	var indexes []core.Index
	for rows.Next() {
		var idxName, colName string
		var isUnique bool
		if err := rows.Scan(&idxName, &colName, &isUnique); err != nil {
			return nil, behemotherr.NewMigrationError("PostgresIntrospector.indexes", "scan_failed", err)
		}
		if n := len(indexes); n > 0 && indexes[n-1].Name == idxName {
			indexes[n-1].Columns = append(indexes[n-1].Columns, colName)
			continue
		}
		indexes = append(indexes, core.Index{Name: idxName, Columns: []string{colName}, Unique: isUnique})
	}
	return indexes, rows.Err()
}

// introspectForeignKeys reads pg_constraint directly: joining
// information_schema.constraint_column_usage pairs every local column with
// every referenced column, which scrambles composite keys.
func (d *PostgreSQLDriver) introspectForeignKeys(ctx context.Context, physical string) ([]core.ForeignKey, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT c.conname, c.confdeltype::text, rt.relname, a.attname, ra.attname
		FROM pg_constraint c
		JOIN pg_class t ON t.oid = c.conrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_class rt ON rt.oid = c.confrelid
		JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY AS k(col, refcol, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.col
		JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.refcol
		WHERE n.nspname = current_schema() AND t.relname = $1 AND c.contype = 'f'
		ORDER BY c.conname, k.ord`, physical)
	if err != nil {
		return nil, behemotherr.NewMigrationError("PostgresIntrospector.foreignKeys", "query_failed", err)
	}
	defer rows.Close()

	var fks []core.ForeignKey
	for rows.Next() {
		var name, action, refTable, col, refCol string
		if err := rows.Scan(&name, &action, &refTable, &col, &refCol); err != nil {
			return nil, behemotherr.NewMigrationError("PostgresIntrospector.foreignKeys", "scan_failed", err)
		}
		if n := len(fks); n > 0 && fks[n-1].Name == name {
			fks[n-1].Columns = append(fks[n-1].Columns, col)
			fks[n-1].RefColumns = append(fks[n-1].RefColumns, refCol)
			continue
		}
		fks = append(fks, core.ForeignKey{
			Name: name, Columns: []string{col}, RefTable: refTable, RefColumns: []string{refCol},
			OnDelete: mapDeleteAction(action),
		})
	}
	return fks, rows.Err()
}

// mapDeleteAction maps pg_constraint.confdeltype. Postgres's "no action"
// ('a', the default) and "set default" ('d') have no ForeignKeyAction
// equivalent; both collapse to Restrict as the closest safe behavior — a real
// distinction Postgres makes that the canonical model doesn't.
func mapDeleteAction(code string) core.ForeignKeyAction {
	switch code {
	case "c":
		return core.FKCascade
	case "n":
		return core.FKSetNull
	default: // 'r' restrict, 'a' no action, 'd' set default
		return core.FKRestrict
	}
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func scanStrings(rows *sql.Rows) ([]string, error) {
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
