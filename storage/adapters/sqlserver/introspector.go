package sqlserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/types/schema"
)

// mapSQLServerType is the reverse (native -> canonical) type mapping, from a
// column's system type name and its max_length in bytes (-1 for MAX). Native
// types of one family collapse to one canonical type without an ambiguity:
// database/sql scans all of them into the same Go type.
//
// A type outside the table (DATE, TIME, XML, rowversion, sql_variant, spatial
// types, ...) comes back as text with an ambiguity, never as a guess at a
// specific type. Text is the fallback because any value scanned as a Go
// string fits it.
func mapSQLServerType(typeName string, maxLength int) (ct schema.ColumnType, length int, ambiguity *core.ColumnAmbiguity) {
	switch strings.ToLower(typeName) {
	case "nvarchar", "nchar":
		if maxLength < 0 {
			return schema.ColTypeText, 0, nil
		}
		return schema.ColTypeString, maxLength / 2, nil // max_length counts bytes; these store two per character
	case "varchar", "char":
		if maxLength < 0 {
			return schema.ColTypeText, 0, nil
		}
		return schema.ColTypeString, maxLength, nil
	case "text", "ntext":
		return schema.ColTypeText, 0, nil
	case "int", "smallint", "tinyint":
		return schema.ColTypeInteger, 0, nil
	case "bigint":
		return schema.ColTypeBigInt, 0, nil
	case "float", "real":
		return schema.ColTypeReal, 0, nil
	case "decimal", "numeric", "money", "smallmoney":
		return schema.ColTypeNumeric, 0, nil
	case "bit":
		return schema.ColTypeBoolean, 0, nil
	case "datetime2", "datetime", "smalldatetime":
		return schema.ColTypeDateTime, 0, nil
	case "datetimeoffset":
		return schema.ColTypeTimestamp, 0, nil
	case "uniqueidentifier":
		return schema.ColTypeUuid, 0, nil
	case "varbinary":
		if maxLength < 0 {
			return schema.ColTypeBlob, 0, nil
		}
		return schema.ColTypeBytes, 0, nil
	case "binary":
		return schema.ColTypeBytes, 0, nil
	case "image":
		return schema.ColTypeBlob, 0, nil
	}
	return schema.ColTypeText, 0, &core.ColumnAmbiguity{Reason: fmt.Sprintf("unrecognized SQL Server type %q, defaulted to text; verify manually", typeName)}
}

// NormalizeColumn implements [core.ColumnNormalizer]: col as Introspect
// reports it once columnDefinition has created it. It replays every change
// the DDL makes to a declaration, so it must change together with
// columnDefinition, renderSQLServerType and renderDefaultExpr:
//   - the sqlserver override's Type and AutoInc replace the declared ones
//   - a uuid is NCHAR(36), which reads back as a string of length 36
//   - json is NVARCHAR(MAX), which reads back as text
//   - bytes and blob are both VARBINARY(MAX), which reads back as blob
//   - a string without a length is created as NVARCHAR(255); one longer than
//     4000 as NVARCHAR(MAX), which reads back as text
//   - only character types carry a length; every other type reads back without one
//   - a primary key or identity column is always NOT NULL, and a primary key
//     is never also UNIQUE
//   - the default is what Introspect parses out of what renderDefaultExpr
//     writes (sqlServerDefaultFromStored): the sqlserver override expression
//     or the literal, as one of the two forms. Other drivers' overrides don't
//     apply, and an identity column has no default.
func (d *SQLServerDriver) NormalizeColumn(_ string, raw schema.Column) schema.Column {
	col := applyOverride(raw)
	switch col.Type {
	case schema.ColTypeUuid:
		col.Type, col.Length = schema.ColTypeString, 36
	case schema.ColTypeJson:
		col.Type = schema.ColTypeText
	case schema.ColTypeBytes:
		col.Type = schema.ColTypeBlob
	case schema.ColTypeString:
		if col.Length <= 0 {
			col.Length = 255
		}
		if col.Length > maxStringLength {
			col.Type = schema.ColTypeText
		}
	}
	if col.Type != schema.ColTypeString {
		col.Length = 0
	}
	if col.PrimaryKey {
		col.Nullable = false
		col.Unique = false
	}
	if col.AutoInc {
		col.Nullable = false
	}
	// An unrenderable default fails at apply time; it's left as declared.
	if expr, err := renderDefaultExpr(raw); err == nil {
		col.Default, col.Overrides = nil, nil
		if expr != "" && !col.AutoInc {
			col.Default, col.Overrides = sqlServerDefaultFromStored(expr, col.Type)
		}
	}
	return col
}

// TableExists implements [core.SchemaIntrospector]. A view counts: Introspect
// reports it as an incompatible object rather than hiding it here.
func (d *SQLServerDriver) TableExists(ctx context.Context, name string) (bool, error) {
	_, exists, err := d.objectKind(ctx, d.resolver.Resolve(name))
	return exists, err
}

// objectKind maps sys.objects.type to an ObjectKind. It backs the "table
// found live as incompatible object" branch of RunIntrospection.
func (d *SQLServerDriver) objectKind(ctx context.Context, physical string) (kind core.ObjectKind, exists bool, err error) {
	var objType string
	err = d.db.QueryRowContext(ctx, `SELECT RTRIM(type) FROM sys.objects WHERE schema_id = SCHEMA_ID() AND name = @p1`, physical).Scan(&objType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, behemotherr.NewMigrationError("SQLServerIntrospector.objectKind", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	switch objType {
	case "U":
		return core.ObjectTable, true, nil
	case "V":
		return core.ObjectView, true, nil
	default:
		return core.ObjectOther, true, nil
	}
}

// Introspect implements [core.SchemaIntrospector]: a best-effort reverse
// mapping of one live table into the canonical model.
//
// Column names are returned as their physical names: SchemaResolver maps
// canonical -> physical only. RunIntrospection maps them back.
//
// Not represented, because the canonical model has no place for them:
// collations, included and descending index columns, check constraints, and a
// foreign key's ON UPDATE action. Indexes the model can't express at all are
// left out (see liveIndex.representable).
func (d *SQLServerDriver) Introspect(ctx context.Context, name string) (core.IntrospectedTable, error) {
	physical := d.resolver.Resolve(name)

	kind, exists, err := d.objectKind(ctx, physical)
	if err != nil || !exists {
		return core.IntrospectedTable{}, err
	}
	if kind != core.ObjectTable {
		return core.IntrospectedTable{Kind: kind, Exists: true}, nil // caller checks Kind before touching Schema
	}

	live, err := d.readTable(ctx, d.db, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}

	var pkCols, uniqueCols []string
	var indexes []schema.Index
	for _, idx := range live.indexes {
		switch {
		case idx.primaryKey:
			pkCols = idx.columns
		case !idx.representable:
		case idx.isColumnUnique(physical):
			uniqueCols = append(uniqueCols, idx.columns[0])
		default:
			indexes = append(indexes, schema.Index{Name: idx.name, Columns: idx.columns, Unique: idx.unique})
		}
	}

	var cols []schema.Column
	var ambiguities []core.ColumnAmbiguity
	for _, c := range live.columns {
		col, ambig := c.canonical(pkCols, uniqueCols)
		if ambig != nil {
			ambig.Column = c.name
			ambiguities = append(ambiguities, *ambig)
		}
		cols = append(cols, col)
	}

	var fks []schema.ForeignKey
	for _, fk := range live.foreignKeys {
		fks = append(fks, schema.ForeignKey{
			Name: fk.name, Columns: fk.columns, RefTable: fk.refTable, RefColumns: fk.refColumns,
			OnDelete: mapDeleteAction(fk.onDelete),
		})
	}

	return core.IntrospectedTable{
		Kind:        core.ObjectTable,
		Exists:      true,
		Schema:      schema.Table{Name: name, PhysicalName: physical, Columns: cols, Indexes: indexes, ForeignKeys: fks},
		Ambiguities: ambiguities,
	}, nil
}

// ---- Catalog readers ----
//
// These take a Querier and physical names, because the driver reads the
// catalog inside the migration's transaction as well (see SQLServerDriver).

// liveTable is a table as the catalog describes it.
type liveTable struct {
	columns     []liveColumn
	indexes     []liveIndex
	foreignKeys []liveForeignKey // the table's own, not the ones pointing at it
}

func (d *SQLServerDriver) readTable(ctx context.Context, q adapters.Querier, table string) (liveTable, error) {
	var t liveTable
	var err error
	if t.columns, err = d.liveColumns(ctx, q, table); err != nil {
		return t, err
	}
	if t.indexes, err = d.liveIndexes(ctx, q, table); err != nil {
		return t, err
	}
	t.foreignKeys, err = d.liveForeignKeys(ctx, q, table, false)
	return t, err
}

// liveColumn is one row of sys.columns, kept in native terms so a table
// rebuild can recreate the column exactly (nativeDefinition) and Introspect
// can map it to the canonical model (canonical).
type liveColumn struct {
	name       string
	typeName   string // system type: an alias type is reported as its base
	maxLength  int    // bytes; -1 for MAX
	precision  int
	scale      int
	nullable   bool
	identity   bool
	seed, step string         // identity seed and increment
	computed   bool           //
	collation  sql.NullString // set only when it differs from the database's
	defaultDef sql.NullString // sys.default_constraints.definition
}

func (d *SQLServerDriver) liveColumns(ctx context.Context, q adapters.Querier, table string) ([]liveColumn, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT c.name, TYPE_NAME(c.system_type_id), c.max_length, c.precision, c.scale, c.is_nullable, c.is_identity,
			COALESCE(CONVERT(nvarchar(40), ic.seed_value), '1'), COALESCE(CONVERT(nvarchar(40), ic.increment_value), '1'),
			c.is_computed,
			CASE WHEN c.collation_name <> CONVERT(sysname, DATABASEPROPERTYEX(DB_NAME(), 'Collation')) THEN c.collation_name END,
			dc.definition
		FROM sys.columns c
		LEFT JOIN sys.identity_columns ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
		LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id
		WHERE c.object_id = OBJECT_ID(@p1)
		ORDER BY c.column_id`, quoteIdent(table))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLServerIntrospector.columns", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var cols []liveColumn
	for rows.Next() {
		var c liveColumn
		if err := rows.Scan(&c.name, &c.typeName, &c.maxLength, &c.precision, &c.scale, &c.nullable, &c.identity,
			&c.seed, &c.step, &c.computed, &c.collation, &c.defaultDef); err != nil {
			return nil, behemotherr.NewMigrationError("SQLServerIntrospector.columns", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// canonical maps the column to the canonical model. pkCols and uniqueCols are
// the table's primary key columns and the columns with a unique index of
// their own.
func (c liveColumn) canonical(pkCols, uniqueCols []string) (schema.Column, *core.ColumnAmbiguity) {
	ct, length, ambig := mapSQLServerType(c.typeName, c.maxLength)
	if ambig == nil && c.computed {
		ambig = &core.ColumnAmbiguity{Reason: "computed column; the canonical model can't express it"}
	}
	isPK := slices.Contains(pkCols, c.name)
	col := schema.Column{
		Name: c.name, Type: ct, Length: length,
		Nullable: c.nullable, PrimaryKey: isPK, Unique: slices.Contains(uniqueCols, c.name) && !isPK,
		AutoInc: c.identity,
	}
	if c.defaultDef.Valid {
		col.Default, col.Overrides = sqlServerDefaultFromStored(c.defaultDef.String, ct)
	}
	return col, ambig
}

// nativeDefinition renders everything of the column after its name, as it is
// now: the counterpart of columnDefinition for a column the migration doesn't
// change.
func (c liveColumn) nativeDefinition() string {
	def := strings.ToUpper(c.typeName)
	size := func(n int) string {
		if n < 0 {
			return "(MAX)"
		}
		return fmt.Sprintf("(%d)", n)
	}
	switch strings.ToLower(c.typeName) {
	case "nvarchar", "nchar":
		if c.maxLength < 0 {
			def += "(MAX)"
		} else {
			def += size(c.maxLength / 2)
		}
	case "varchar", "char", "varbinary", "binary":
		def += size(c.maxLength)
	case "decimal", "numeric":
		def += fmt.Sprintf("(%d,%d)", c.precision, c.scale)
	case "datetime2", "datetimeoffset", "time":
		def += fmt.Sprintf("(%d)", c.scale)
	case "float":
		def += fmt.Sprintf("(%d)", c.precision)
	}
	if c.collation.Valid {
		def += " COLLATE " + c.collation.String
	}
	if c.identity {
		def += fmt.Sprintf(" IDENTITY(%s,%s)", c.seed, c.step)
	}
	if c.nullable {
		def += " NULL"
	} else {
		def += " NOT NULL"
	}
	if c.defaultDef.Valid {
		def += " DEFAULT " + c.defaultDef.String
	}
	return def
}

// nullableColumns reports which of the table's columns accept NULL.
func (d *SQLServerDriver) nullableColumns(ctx context.Context, q adapters.Querier, table string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, is_nullable FROM sys.columns WHERE object_id = OBJECT_ID(@p1)`, quoteIdent(table))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLServerIntrospector.nullableColumns", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()
	nullable := map[string]bool{}
	for rows.Next() {
		var name string
		var isNullable bool
		if err := rows.Scan(&name, &isNullable); err != nil {
			return nil, behemotherr.NewMigrationError("SQLServerIntrospector.nullableColumns", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		nullable[name] = isNullable
	}
	return nullable, rows.Err()
}

// liveIndex is one index as sys.indexes reports it. SQL Server keeps the
// primary key, unique constraints and plain indexes in that one list.
type liveIndex struct {
	name             string
	unique           bool
	primaryKey       bool
	uniqueConstraint bool // created by a UNIQUE constraint; dropped with DROP CONSTRAINT
	filter           string
	columns          []string // key columns, in key order
	included         []string // INCLUDE columns

	// representable is false for an index the canonical Index can't express
	// and the driver therefore can't recreate: one with included columns, a
	// columnstore, XML or spatial index, or a filter other than the NULL
	// filter indexSQL writes.
	representable bool
}

func (i liveIndex) allColumns() []string { return append(slices.Clone(i.columns), i.included...) }

func (i liveIndex) dropSQL(table string) string {
	if i.uniqueConstraint {
		return fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", quoteIdent(table), quoteIdent(i.name))
	}
	return fmt.Sprintf("DROP INDEX %s ON %s", quoteIdent(i.name), quoteIdent(table))
}

// isColumnUnique reports whether the index is what stands behind
// Column.Unique: a unique index on one column that is either a UNIQUE
// constraint or carries the name the driver gives such an index
// (uniqueKeyName). The name is what keeps a declared Index{Unique: true} on
// one column an index.
func (i liveIndex) isColumnUnique(table string) bool {
	return i.unique && !i.primaryKey && i.representable && len(i.columns) == 1 &&
		(i.uniqueConstraint || i.name == uniqueKeyName(table, i.columns[0]))
}

func (d *SQLServerDriver) liveIndexes(ctx context.Context, q adapters.Querier, table string) ([]liveIndex, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT i.name, i.is_unique, i.is_primary_key, i.is_unique_constraint, i.type, COALESCE(i.filter_definition, ''),
			ic.is_included_column, col.name
		FROM sys.indexes i
		JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
		JOIN sys.columns col ON col.object_id = ic.object_id AND col.column_id = ic.column_id
		WHERE i.object_id = OBJECT_ID(@p1) AND i.type > 0 AND i.is_hypothetical = 0
		ORDER BY i.name, ic.is_included_column, ic.key_ordinal`, quoteIdent(table))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLServerIntrospector.indexes", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var indexes []liveIndex
	rowstore := map[string]bool{}
	for rows.Next() {
		var idx liveIndex
		var indexType int
		var included bool
		var column string
		if err := rows.Scan(&idx.name, &idx.unique, &idx.primaryKey, &idx.uniqueConstraint, &indexType, &idx.filter, &included, &column); err != nil {
			return nil, behemotherr.NewMigrationError("SQLServerIntrospector.indexes", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if n := len(indexes); n == 0 || indexes[n-1].name != idx.name {
			indexes = append(indexes, idx)
			rowstore[idx.name] = indexType == 1 || indexType == 2 // clustered or nonclustered
		}
		last := &indexes[len(indexes)-1]
		if included {
			last.included = append(last.included, column)
		} else {
			last.columns = append(last.columns, column)
		}
	}
	for i := range indexes {
		idx := &indexes[i]
		idx.representable = rowstore[idx.name] && len(idx.included) == 0 && len(idx.columns) > 0 && isNullFilter(idx.filter, idx.columns)
	}
	return indexes, rows.Err()
}

// isNullFilter reports whether filter is empty or the filter indexSQL writes,
// as SQL Server stores it: "([a] IS NOT NULL AND [b] IS NOT NULL)" over key
// columns only.
func isNullFilter(filter string, columns []string) bool {
	if filter == "" {
		return true
	}
	filter = strings.TrimSuffix(strings.TrimPrefix(filter, "("), ")")
	for _, term := range strings.Split(filter, " AND ") {
		column, ok := strings.CutSuffix(term, " IS NOT NULL")
		if !ok || !slices.ContainsFunc(columns, func(c string) bool { return quoteIdent(c) == column }) {
			return false
		}
	}
	return true
}

// liveForeignKey is a foreign key in native terms: table is the table that
// holds the constraint, and the actions are T-SQL (NO ACTION, CASCADE, ...).
type liveForeignKey struct {
	table      string
	name       string
	columns    []string
	refTable   string
	refColumns []string
	onDelete   string
	onUpdate   string
}

// liveForeignKeys returns the foreign keys table holds, or with inbound the
// ones other tables hold on it.
func (d *SQLServerDriver) liveForeignKeys(ctx context.Context, q adapters.Querier, table string, inbound bool) ([]liveForeignKey, error) {
	where := "fk.parent_object_id = OBJECT_ID(@p1)"
	if inbound {
		where = "fk.referenced_object_id = OBJECT_ID(@p1) AND fk.parent_object_id <> fk.referenced_object_id"
	}
	rows, err := q.QueryContext(ctx, `
		SELECT OBJECT_NAME(fk.parent_object_id), fk.name, fk.delete_referential_action_desc, fk.update_referential_action_desc,
			OBJECT_NAME(fk.referenced_object_id), pc.name, rc.name
		FROM sys.foreign_keys fk
		JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
		JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
		JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
		WHERE `+where+`
		ORDER BY fk.name, fkc.constraint_column_id`, quoteIdent(table))
	if err != nil {
		return nil, behemotherr.NewMigrationError("SQLServerIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var fks []liveForeignKey
	for rows.Next() {
		var fk liveForeignKey
		var onDelete, onUpdate, col, refCol string
		if err := rows.Scan(&fk.table, &fk.name, &onDelete, &onUpdate, &fk.refTable, &col, &refCol); err != nil {
			return nil, behemotherr.NewMigrationError("SQLServerIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if n := len(fks); n == 0 || fks[n-1].name != fk.name || fks[n-1].table != fk.table {
			// The catalog spells actions NO_ACTION, SET_NULL, SET_DEFAULT.
			fk.onDelete, fk.onUpdate = strings.ReplaceAll(onDelete, "_", " "), strings.ReplaceAll(onUpdate, "_", " ")
			fks = append(fks, fk)
		}
		last := &fks[len(fks)-1]
		last.columns = append(last.columns, col)
		last.refColumns = append(last.refColumns, refCol)
	}
	return fks, rows.Err()
}

// mapDeleteAction maps a T-SQL delete action. NO ACTION (the default) and SET
// DEFAULT have no ForeignKeyAction; both collapse to Restrict. NO ACTION is
// also what the driver writes for Restrict.
func mapDeleteAction(action string) schema.ForeignKeyAction {
	switch action {
	case "CASCADE":
		return schema.FKCascade
	case "SET NULL":
		return schema.FKSetNull
	default:
		return schema.FKRestrict
	}
}

// unrebuildableObjects names what a table rebuild would lose and can't
// recreate: check constraints and triggers. It returns "" when there are none.
func (d *SQLServerDriver) unrebuildableObjects(ctx context.Context, q adapters.Querier, table string) (string, error) {
	var checks, triggers int
	err := q.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM sys.check_constraints WHERE parent_object_id = OBJECT_ID(@p1)),
			(SELECT COUNT(*) FROM sys.triggers WHERE parent_id = OBJECT_ID(@p1))`, quoteIdent(table)).Scan(&checks, &triggers)
	if err != nil {
		return "", behemotherr.NewMigrationError("SQLServerIntrospector.unrebuildableObjects", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	switch {
	case checks > 0:
		return fmt.Sprintf("%d check constraint(s)", checks), nil
	case triggers > 0:
		return fmt.Sprintf("%d trigger(s)", triggers), nil
	}
	return "", nil
}

// ---- Defaults ----

// sqlServerDefaultFromStored maps a default expression, as SQL Server stores
// it in sys.default_constraints.definition, onto the canonical column.
// Introspect and NormalizeColumn both go through it, so a declaration and the
// live column it produced are described the same way.
//
// SQL Server wraps what it stores in parentheses: ((7)), (N'x'),
// (getdate()). Once those are removed, a quoted string or a number is a
// literal and becomes Default; on a BIT column 1 and 0 are booleans. NULL is
// no default. Anything else is an expression and is kept under the sqlserver
// override, which is what the renderer emits unchanged. CURRENT_TIMESTAMP is
// spelled getdate(), as SQL Server stores it.
func sqlServerDefaultFromStored(expr string, ct schema.ColumnType) (any, map[string]schema.ColumnOverride) {
	expr = stripEnclosingParens(strings.TrimSpace(expr))
	if s, isString := parseStringLiteral(expr); isString {
		return s, nil
	}
	if n, isNumber := parseNumber(expr); isNumber {
		if ct == schema.ColTypeBoolean && (n == int64(0) || n == int64(1)) {
			return n == int64(1), nil
		}
		return n, nil
	}
	switch strings.ToLower(expr) {
	case "null", "":
		return nil, nil
	case "current_timestamp":
		expr = "getdate()"
	}
	return nil, map[string]schema.ColumnOverride{DriverName: {Default: expr}}
}

// parseStringLiteral reads expr as exactly one string literal, 'x' or N'x'.
// A quote inside it is doubled; T-SQL has no backslash escapes.
func parseStringLiteral(expr string) (string, bool) {
	body := strings.TrimPrefix(strings.TrimPrefix(expr, "N"), "n")
	if len(body) < 2 || body[0] != '\'' || body[len(body)-1] != '\'' {
		return "", false
	}
	body = body[1 : len(body)-1]
	for i := 0; i < len(body); i++ {
		if body[i] != '\'' {
			continue
		}
		if i+1 >= len(body) || body[i+1] != '\'' {
			return "", false // the string ends before the expression does: 'a' + 'b'
		}
		i++
	}
	return strings.ReplaceAll(body, "''", "'"), true
}

// stripEnclosingParens removes parentheses that enclose the whole expression,
// repeatedly: "((7))" -> "7", while "((1)+(1))" stops at "(1)+(1)".
func stripEnclosingParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth, inString := 0, false
		for i := 0; i < len(s); i++ {
			switch {
			case s[i] == '\'':
				inString = !inString // a doubled quote toggles twice
			case inString:
			case s[i] == '(':
				depth++
			case s[i] == ')':
				depth--
			}
			if depth == 0 && i < len(s)-1 {
				return s // the first parenthesis closes before the end
			}
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func parseNumber(s string) (any, bool) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	return nil, false
}
