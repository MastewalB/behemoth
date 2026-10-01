package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/types/schema"
)

// sqliteTypeMapping maps declared column types, upper-cased with their
// arguments removed. It covers everything renderSQLiteType emits, plus the
// common SQL type names a table created outside behemoth uses, so an existing
// database can be adopted. Lengths are only meaningful for the string family.
//
// Several canonical types render to the same declared type — TEXT for text
// and json, BLOB for uuid, blob and bytes — so those read back as the first
// of each group. That is a lossy mapping, not an ambiguity: the column is
// fully usable as the type reported.
var sqliteTypeMapping = map[string]schema.ColumnType{
	// string family: with a length, ColTypeString; without, ColTypeText
	"VARCHAR": schema.ColTypeString, "CHAR": schema.ColTypeString, "CHARACTER": schema.ColTypeString,
	"NCHAR": schema.ColTypeString, "NVARCHAR": schema.ColTypeString,
	"VARYING CHARACTER": schema.ColTypeString, "NATIVE CHARACTER": schema.ColTypeString,
	"TEXT": schema.ColTypeText, "CLOB": schema.ColTypeText,

	"INTEGER": schema.ColTypeInteger, "INT": schema.ColTypeInteger, "TINYINT": schema.ColTypeInteger,
	"SMALLINT": schema.ColTypeInteger, "MEDIUMINT": schema.ColTypeInteger, "INT2": schema.ColTypeInteger,
	"BIGINT": schema.ColTypeBigInt, "INT8": schema.ColTypeBigInt, "UNSIGNED BIG INT": schema.ColTypeBigInt,

	"REAL": schema.ColTypeReal, "DOUBLE": schema.ColTypeReal, "DOUBLE PRECISION": schema.ColTypeReal, "FLOAT": schema.ColTypeReal,
	"NUMERIC": schema.ColTypeNumeric, "DECIMAL": schema.ColTypeNumeric,

	"BOOLEAN": schema.ColTypeBoolean, "BOOL": schema.ColTypeBoolean,
	"DATETIME":  schema.ColTypeDateTime,
	"TIMESTAMP": schema.ColTypeTimestamp,
	"BLOB":      schema.ColTypeBlob,
}

var declaredTypePattern = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*(?:\(\s*(\d+)\s*(?:,\s*\d+\s*)?\))?\s*$`)

// mapSQLiteType returns the canonical type and length for a declared column
// type, or (ColTypeText, ambiguity) for anything it doesn't recognize — never
// a guess. SQLite accepts any type name and derives an affinity from it, but
// an affinity says how values are stored, not what the column means (DATE
// gets NUMERIC affinity), so unrecognized names are not mapped by affinity.
// As for Postgres, an ambiguity stops generation (core.RejectAmbiguousTypes).
func mapSQLiteType(declared string) (schema.ColumnType, int, *core.ColumnAmbiguity) {
	if m := declaredTypePattern.FindStringSubmatch(declared); m != nil {
		name := strings.ToUpper(strings.Join(strings.Fields(m[1]), " "))
		if ct, ok := sqliteTypeMapping[name]; ok {
			if ct != schema.ColTypeString {
				return ct, 0, nil
			}
			if length, _ := strconv.Atoi(m[2]); length > 0 {
				return schema.ColTypeString, length, nil
			}
			return schema.ColTypeText, 0, nil // a string type without a length is unbounded — the same thing as TEXT
		}
	}
	if strings.TrimSpace(declared) == "" {
		return schema.ColTypeText, 0, &core.ColumnAmbiguity{Reason: "column has no declared type (any value is accepted); defaulted to text — verify manually"}
	}
	return schema.ColTypeText, 0, &core.ColumnAmbiguity{Reason: fmt.Sprintf("unrecognized SQLite type %q — defaulted to text; verify manually", declared)}
}

// TableExists implements [core.SchemaIntrospector]. Tables, views and indexes
// share SQLite's namespace, so any of them counts — Introspect then reports a
// view or index of the same name as an incompatible object rather than hiding it.
func (d *SQLiteDriver) TableExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := d.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = ? AND type IN ('table', 'view', 'index'))`,
		d.resolver.Resolve(name)).Scan(&exists)
	if err != nil {
		return false, behemotherr.NewMigrationError("SQLiteIntrospector.TableExists", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	return exists, nil
}

// Introspect implements [core.SchemaIntrospector]: a best-effort reverse
// mapping of one live table into the canonical model.
//
// Column names are returned as their physical names: SchemaResolver maps
// canonical -> physical only, so a column whose physical name differs from
// its canonical one can't be mapped back here.
//
// Most structure comes from SQLite's pragmas; what they don't report —
// foreign-key constraint names and AUTOINCREMENT — is read from the table's
// stored CREATE TABLE statement with the same parser table rebuilds use.
func (d *SQLiteDriver) Introspect(ctx context.Context, name string) (core.IntrospectedTable, error) {
	physical := d.resolver.Resolve(name)

	var objType string
	var createSQL sql.NullString
	err := d.db.QueryRowContext(ctx,
		`SELECT type, sql FROM sqlite_master WHERE name = ? AND type IN ('table', 'view', 'index')`, physical).Scan(&objType, &createSQL)
	if errors.Is(err, sql.ErrNoRows) {
		return core.IntrospectedTable{}, nil
	}
	if err != nil {
		return core.IntrospectedTable{}, behemotherr.NewMigrationError("SQLiteIntrospector.Introspect", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	switch {
	case objType == "view":
		return core.IntrospectedTable{Kind: core.ObjectView, Exists: true}, nil
	case objType != "table", isVirtualTable(createSQL.String):
		return core.IntrospectedTable{Kind: core.ObjectOther, Exists: true}, nil // caller checks Kind before touching Schema
	}

	parsed, err := parseCreateTable(createSQL.String)
	if err != nil {
		return core.IntrospectedTable{}, behemotherr.NewMigrationError("SQLiteIntrospector.Introspect", behemotherr.ErrorCodeMigrationIntrospectionFailed,
			fmt.Errorf("table %q: %w", physical, err))
	}

	uniqueSingle, indexes, err := d.introspectIndexes(ctx, physical, parsed)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	cols, ambiguities, err := d.introspectColumns(ctx, physical, parsed, uniqueSingle)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	fks, err := d.introspectForeignKeys(ctx, physical, parsed)
	if err != nil {
		return core.IntrospectedTable{}, err
	}

	return core.IntrospectedTable{
		Kind:        core.ObjectTable,
		Exists:      true,
		Schema:      schema.Table{Name: name, PhysicalName: physical, Columns: cols, Indexes: indexes, ForeignKeys: fks},
		Ambiguities: ambiguities,
	}, nil
}

func isVirtualTable(createSQL string) bool {
	toks := tokenize(createSQL)
	return len(toks) > 1 && toks[1].isKeyword("VIRTUAL")
}

func (d *SQLiteDriver) introspectColumns(ctx context.Context, physical string, parsed *tableSQL, uniqueCols map[string]bool) ([]schema.Column, []core.ColumnAmbiguity, error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", quoteIdent(physical)))
	if err != nil {
		return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.columns", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	type liveColumn struct {
		name, declType string
		notNull        bool
		dflt           sql.NullString
		pk             int
	}
	var live []liveColumn
	pkCount := 0
	for rows.Next() {
		var c liveColumn
		var cid int
		if err := rows.Scan(&cid, &c.name, &c.declType, &c.notNull, &c.dflt, &c.pk); err != nil {
			return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.columns", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if c.pk > 0 {
			pkCount++
		}
		live = append(live, c)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.columns", behemotherr.ErrorCodeMigrationScanFailed, err)
	}

	cols := make([]schema.Column, 0, len(live))
	var ambiguities []core.ColumnAmbiguity
	for _, c := range live {
		ct, length, ambig := mapSQLiteType(c.declType)
		// The renderer declares every AUTOINCREMENT column INTEGER (the only
		// type SQLite accepts), so a bigint one reads back as integer.
		autoInc := columnHasKeyword(parsed, c.name, "AUTOINCREMENT")
		if ambig != nil {
			ambig.Column = c.name
			ambiguities = append(ambiguities, *ambig)
		}

		// A lone INTEGER PRIMARY KEY is an alias for the rowid, which can never
		// be NULL, even though SQLite reports no NOT NULL constraint on it.
		rowidAlias := c.pk > 0 && pkCount == 1 && strings.EqualFold(strings.TrimSpace(c.declType), "INTEGER")

		col := schema.Column{
			Name: c.name, Type: ct, Length: length,
			Nullable:   !c.notNull && !rowidAlias,
			PrimaryKey: c.pk > 0,
			Unique:     uniqueCols[strings.ToLower(c.name)] && c.pk == 0,
			AutoInc:    autoInc,
		}
		if c.dflt.Valid {
			if val, isLiteral := parseSQLiteDefault(c.dflt.String, ct); isLiteral {
				col.Default = val
			} else {
				// An expression default (CURRENT_TIMESTAMP, (datetime('now')), ...)
				// isn't a data literal; it is kept verbatim as a raw SQLite
				// expression — what an override Default means, and what the
				// renderer emits back, wrapped in parentheses.
				col.Overrides = map[string]schema.ColumnOverride{DriverName: {Default: stripParens(c.dflt.String)}}
			}
		}
		cols = append(cols, col)
	}
	return cols, ambiguities, nil
}

// parseSQLiteDefault interprets the literal forms PRAGMA table_info reports
// for dflt_value: a quoted string, a number, NULL, or TRUE/FALSE. Booleans are
// stored as 0/1, so a 0/1 default on a boolean column reads back as a bool.
// Anything else is returned as non-literal.
func parseSQLiteDefault(expr string, ct schema.ColumnType) (value any, isLiteral bool) {
	expr = strings.TrimSpace(expr)

	if len(expr) >= 2 && expr[0] == '\'' && expr[len(expr)-1] == '\'' {
		inner := expr[1 : len(expr)-1]
		if strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
			return nil, false // more than one literal, e.g. 'a' || 'b'
		}
		return strings.ReplaceAll(inner, "''", "'"), true
	}
	if n, err := strconv.ParseInt(expr, 10, 64); err == nil {
		if ct == schema.ColTypeBoolean && (n == 0 || n == 1) {
			return n == 1, true
		}
		return n, true
	}
	if f, err := strconv.ParseFloat(expr, 64); err == nil {
		return f, true
	}
	switch strings.ToUpper(expr) {
	case "NULL":
		return nil, true
	case "TRUE":
		return true, true
	case "FALSE":
		return false, true
	}
	return nil, false
}

// stripParens removes one pair of parentheses enclosing the whole expression.
func stripParens(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && matchParen(expr, 0) == len(expr)-1 {
		return strings.TrimSpace(expr[1 : len(expr)-1])
	}
	return expr
}

func columnHasKeyword(parsed *tableSQL, column, keyword string) bool {
	i := parsed.findColumn(column)
	if i < 0 {
		return false
	}
	for _, t := range parsed.items[i].tokens[1:] { // tokens[0] is the column name
		if t.isKeyword(keyword) {
			return true
		}
	}
	return false
}

// introspectIndexes splits PRAGMA index_list into what the canonical model
// represents differently:
//   - origin "pk": the primary key's own index — represented by Column.PrimaryKey, skipped
//   - origin "u", one column: a UNIQUE constraint — represented by Column.Unique
//   - origin "u", several columns: no per-column form — an Index{Unique: true},
//     named after the CONSTRAINT when the table declares one
//   - origin "c": an explicit CREATE INDEX
//
// Partial indexes and indexes on expressions are skipped: the canonical Index
// can express neither.
func (d *SQLiteDriver) introspectIndexes(ctx context.Context, physical string, parsed *tableSQL) (uniqueSingle map[string]bool, indexes []schema.Index, err error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf("PRAGMA index_list(%s)", quoteIdent(physical)))
	if err != nil {
		return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexes", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	type listed struct {
		name, origin string
		unique       bool
	}
	var list []listed
	for rows.Next() {
		var seq int
		var l listed
		var partial bool
		if err := rows.Scan(&seq, &l.name, &l.unique, &l.origin, &partial); err != nil {
			rows.Close()
			return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexes", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if l.origin != "pk" && !partial {
			list = append(list, l)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexes", behemotherr.ErrorCodeMigrationScanFailed, err)
	}

	uniqueSingle = map[string]bool{}
	for _, l := range list {
		cols, err := d.indexColumns(ctx, l.name)
		if err != nil {
			return nil, nil, err
		}
		if cols == nil {
			continue // indexes an expression
		}
		switch {
		case l.origin == "u" && len(cols) == 1:
			uniqueSingle[strings.ToLower(cols[0])] = true
		case l.origin == "u":
			name := l.name
			if c := parsed.constraintOn(itemUnique, cols); c != "" {
				name = c
			}
			indexes = append(indexes, schema.Index{Name: name, Columns: cols, Unique: true})
		default:
			indexes = append(indexes, schema.Index{Name: l.name, Columns: cols, Unique: l.unique})
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i].Name < indexes[j].Name })
	return uniqueSingle, indexes, nil
}

// indexColumns lists an index's columns in key order, or nil if any key is an
// expression (reported with a NULL name).
func (d *SQLiteDriver) indexColumns(ctx context.Context, index string) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf("PRAGMA index_info(%s)", quoteIdent(index)))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexColumns", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()
	var cols []string
	expression := false
	for rows.Next() {
		var seqno, cid int
		var name sql.NullString
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexColumns", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if !name.Valid {
			expression = true
			continue
		}
		cols = append(cols, name.String)
	}
	if err := rows.Err(); err != nil {
		return nil, behemotherr.NewMigrationError("SQLiteIntrospector.indexColumns", behemotherr.ErrorCodeMigrationScanFailed, err)
	}
	if expression {
		return nil, nil
	}
	return cols, nil
}

// introspectForeignKeys reads PRAGMA foreign_key_list, which reports a key's
// columns, referenced table and ON DELETE action but not its name. The name
// comes from the table's CONSTRAINT clauses, matched on the local columns —
// the driver always adds foreign keys as named constraints. A foreign key
// declared without a name (e.g. a column-level REFERENCES) keeps Name "".
func (d *SQLiteDriver) introspectForeignKeys(ctx context.Context, physical string, parsed *tableSQL) ([]schema.ForeignKey, error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf("PRAGMA foreign_key_list(%s)", quoteIdent(physical)))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLiteIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}

	type fkRow struct {
		id, seq  int
		refTable string
		from     string
		to       sql.NullString
		onDelete string
	}
	var fkRows []fkRow
	for rows.Next() {
		var r fkRow
		var onUpdate, match string
		if err := rows.Scan(&r.id, &r.seq, &r.refTable, &r.from, &r.to, &onUpdate, &r.onDelete, &match); err != nil {
			rows.Close()
			return nil, behemotherr.NewMigrationError("SQLiteIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		fkRows = append(fkRows, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, behemotherr.NewMigrationError("SQLiteIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationScanFailed, err)
	}
	sort.Slice(fkRows, func(i, j int) bool {
		if fkRows[i].id != fkRows[j].id {
			return fkRows[i].id < fkRows[j].id
		}
		return fkRows[i].seq < fkRows[j].seq
	})

	var fks []schema.ForeignKey
	byID := map[int]int{} // foreign_key_list id -> index in fks
	for _, r := range fkRows {
		i, seen := byID[r.id]
		if !seen {
			fks = append(fks, schema.ForeignKey{RefTable: r.refTable, OnDelete: mapSQLiteDeleteAction(r.onDelete)})
			i = len(fks) - 1
			byID[r.id] = i
		}
		fks[i].Columns = append(fks[i].Columns, r.from)
		if r.to.Valid {
			fks[i].RefColumns = append(fks[i].RefColumns, r.to.String)
		}
	}

	for i := range fks {
		// REFERENCES parent (without columns) targets the parent's primary key.
		if len(fks[i].RefColumns) == 0 {
			pk, err := d.primaryKeyColumns(ctx, fks[i].RefTable)
			if err != nil {
				return nil, err
			}
			fks[i].RefColumns = pk
		}
		fks[i].Name = parsed.constraintOn(itemForeignKey, fks[i].Columns)
	}
	sort.SliceStable(fks, func(i, j int) bool { return fks[i].Name < fks[j].Name })
	return fks, nil
}

func (d *SQLiteDriver) primaryKeyColumns(ctx context.Context, physical string) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", quoteIdent(physical)))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLiteIntrospector.primaryKey", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()
	type keyCol struct {
		name string
		pk   int
	}
	var keys []keyCol
	for rows.Next() {
		var cid, pk int
		var name, declType string
		var notNull bool
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &declType, &notNull, &dflt, &pk); err != nil {
			return nil, behemotherr.NewMigrationError("SQLiteIntrospector.primaryKey", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if pk > 0 {
			keys = append(keys, keyCol{name, pk})
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].pk < keys[j].pk })
	cols := make([]string, len(keys))
	for i, k := range keys {
		cols[i] = k.name
	}
	return cols, rows.Err()
}

// constraintOn returns the name of the table constraint of kind declared on
// exactly columns (case-insensitively, in order), or "" if none is named.
func (s *tableSQL) constraintOn(kind itemKind, columns []string) string {
	for _, it := range s.items {
		if it.kind != kind || it.name == "" || len(it.columns) != len(columns) {
			continue
		}
		match := true
		for i := range columns {
			if !strings.EqualFold(it.columns[i], columns[i]) {
				match = false
				break
			}
		}
		if match {
			return it.name
		}
	}
	return ""
}

// mapSQLiteDeleteAction maps foreign_key_list's on_delete. "NO ACTION" (the
// default) and "SET DEFAULT" have no ForeignKeyAction equivalent; both
// collapse to Restrict as the closest safe behavior, as for Postgres.
func mapSQLiteDeleteAction(action string) schema.ForeignKeyAction {
	switch strings.ToUpper(action) {
	case "CASCADE":
		return schema.FKCascade
	case "SET NULL":
		return schema.FKSetNull
	default: // RESTRICT, NO ACTION, SET DEFAULT
		return schema.FKRestrict
	}
}
