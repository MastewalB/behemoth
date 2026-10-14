package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/types/schema"
)

// mysqlTypeMapping is the reverse (native -> canonical) type mapping. Native
// types of one family collapse to one canonical type without an ambiguity:
// database/sql scans all of them into the same Go type. Keys are
// information_schema.COLUMNS.DATA_TYPE values.
//
// TINYINT(1) is the exception to a plain lookup and is handled by
// mapMySQLType: it is MySQL's BOOLEAN.
var mysqlTypeMapping = map[string]schema.ColumnType{
	"varchar":    schema.ColTypeString,
	"char":       schema.ColTypeString,
	"tinytext":   schema.ColTypeText,
	"text":       schema.ColTypeText,
	"mediumtext": schema.ColTypeText,
	"longtext":   schema.ColTypeText,
	"tinyint":    schema.ColTypeInteger,
	"smallint":   schema.ColTypeInteger,
	"mediumint":  schema.ColTypeInteger,
	"int":        schema.ColTypeInteger,
	"bigint":     schema.ColTypeBigInt,
	"float":      schema.ColTypeReal,
	"double":     schema.ColTypeReal,
	"decimal":    schema.ColTypeNumeric,
	// TIMESTAMP reads back as datetime too: the driver creates DATETIME for
	// both canonical types, so a live TIMESTAMP column matches either.
	"datetime":   schema.ColTypeDateTime,
	"timestamp":  schema.ColTypeDateTime,
	"json":       schema.ColTypeJson,
	"tinyblob":   schema.ColTypeBlob,
	"blob":       schema.ColTypeBlob,
	"mediumblob": schema.ColTypeBlob,
	"longblob":   schema.ColTypeBlob,
	"binary":     schema.ColTypeBytes,
	"varbinary":  schema.ColTypeBytes,
}

// mapMySQLType returns the canonical type for a column's DATA_TYPE and
// COLUMN_TYPE (the full type, e.g. "tinyint(1)"). A type outside the table
// (ENUM, SET, DATE, TIME, BIT, spatial types, ...) comes back as text with an
// ambiguity, never as a guess at a specific type. Text is the fallback because
// any value scanned as a Go string fits it.
func mapMySQLType(dataType, columnType string) (schema.ColumnType, *core.ColumnAmbiguity) {
	dataType, columnType = strings.ToLower(dataType), strings.ToLower(columnType)
	if dataType == "tinyint" && strings.HasPrefix(columnType, "tinyint(1)") {
		return schema.ColTypeBoolean, nil
	}
	if ct, ok := mysqlTypeMapping[dataType]; ok {
		return ct, nil
	}
	return schema.ColTypeText, &core.ColumnAmbiguity{Reason: fmt.Sprintf("unrecognized MySQL type %q, defaulted to text; verify manually", columnType)}
}

// NormalizeColumn implements [core.ColumnNormalizer]: col as Introspect
// reports it once renderColumnDefinition has created it. It replays every
// change the DDL makes to a declaration, so it must change together with
// renderColumnDefinition, renderMySQLType and renderDefaultExpr:
//   - the mysql override's Type and AutoInc replace the declared ones
//   - a uuid is CHAR(36), which reads back as a string of length 36
//   - a timestamp is DATETIME(6), which reads back as datetime
//   - bytes and blob are both LONGBLOB, which reads back as blob
//   - a string without a length is created as VARCHAR(255)
//   - only CHAR and VARCHAR carry a length; every other type reads back without one
//   - a primary key column is always NOT NULL, and never also UNIQUE
//   - the default is what Introspect parses out of what renderDefaultExpr
//     writes (storedDefault, then mysqlDefaultFromStored): the mysql override
//     expression or the literal, as one of the two forms. Other drivers'
//     overrides don't apply, and an AUTO_INCREMENT column has no default.
func (d *MySQLDriver) NormalizeColumn(_ string, raw schema.Column) schema.Column {
	col := applyOverride(raw)
	switch col.Type {
	case schema.ColTypeUuid:
		col.Type, col.Length = schema.ColTypeString, 36
	case schema.ColTypeTimestamp:
		col.Type = schema.ColTypeDateTime
	case schema.ColTypeBytes:
		col.Type = schema.ColTypeBlob
	case schema.ColTypeString:
		if col.Length <= 0 {
			col.Length = 255
		}
	}
	if col.Type != schema.ColTypeString {
		col.Length = 0
	}
	if col.PrimaryKey {
		col.Nullable = false
		col.Unique = false
	}
	// An unrenderable default fails at apply time; it's left as declared.
	if text, generated, ok, err := storedDefault(raw); err == nil {
		col.Default, col.Overrides = nil, nil
		if ok && !col.AutoInc {
			col.Default, col.Overrides = mysqlDefaultFromStored(text, generated, col.Type)
		}
	}
	return col
}

// TableExists implements [core.SchemaIntrospector]. A view counts: Introspect
// reports it as an incompatible object rather than hiding it here.
func (d *MySQLDriver) TableExists(ctx context.Context, name string) (bool, error) {
	_, exists, err := d.objectKind(ctx, d.resolver.Resolve(name))
	return exists, err
}

// objectKind maps information_schema.TABLES.TABLE_TYPE to an ObjectKind. It
// backs the "table found live as incompatible object" branch of RunIntrospection.
func (d *MySQLDriver) objectKind(ctx context.Context, physical string) (kind core.ObjectKind, exists bool, err error) {
	var tableType string
	err = d.db.QueryRowContext(ctx, `
		SELECT TABLE_TYPE FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, physical).Scan(&tableType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, behemotherr.NewMigrationError("MySQLIntrospector.objectKind", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	switch tableType {
	case "BASE TABLE":
		return core.ObjectTable, true, nil
	case "VIEW":
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
// Not represented, because the canonical model has no place for them: ON
// UPDATE CURRENT_TIMESTAMP, index prefix lengths, character sets and
// collations, and a foreign key's ON UPDATE action.
func (d *MySQLDriver) Introspect(ctx context.Context, name string) (core.IntrospectedTable, error) {
	physical := d.resolver.Resolve(name)

	kind, exists, err := d.objectKind(ctx, physical)
	if err != nil || !exists {
		return core.IntrospectedTable{}, err
	}
	if kind != core.ObjectTable {
		return core.IntrospectedTable{Kind: kind, Exists: true}, nil // caller checks Kind before touching Schema
	}

	fks, err := d.introspectForeignKeys(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	keys, err := d.introspectKeys(ctx, physical)
	if err != nil {
		return core.IntrospectedTable{}, err
	}
	pkCols, uniqueCols, indexes := classifyKeys(physical, keys, fks)
	cols, ambiguities, err := d.introspectColumns(ctx, physical, pkCols, uniqueCols)
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

func (d *MySQLDriver) introspectColumns(ctx context.Context, physical string, pkCols, uniqueCols []string) ([]schema.Column, []core.ColumnAmbiguity, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_DEFAULT, EXTRA
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
		ORDER BY ORDINAL_POSITION`, physical)
	if err != nil {
		return nil, nil, behemotherr.NewMigrationError("MySQLIntrospector.columns", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var cols []schema.Column
	var ambiguities []core.ColumnAmbiguity

	for rows.Next() {
		var name, dataType, columnType, isNullable, extra string
		var length sql.NullInt64
		var defaultText sql.NullString
		if err := rows.Scan(&name, &dataType, &columnType, &length, &isNullable, &defaultText, &extra); err != nil {
			return nil, nil, behemotherr.NewMigrationError("MySQLIntrospector.columns", behemotherr.ErrorCodeMigrationScanFailed, err)
		}

		ct, ambig := mapMySQLType(dataType, columnType)
		if ambig == nil && strings.Contains(extra, " GENERATED") {
			// "VIRTUAL GENERATED" / "STORED GENERATED": a computed column.
			ambig = &core.ColumnAmbiguity{Reason: "generated column; the canonical model can't express it"}
		}
		if ambig != nil {
			ambig.Column = name
			ambiguities = append(ambiguities, *ambig)
		}

		isPK := slices.Contains(pkCols, name)
		col := schema.Column{
			Name: name, Type: ct,
			Nullable: isNullable == "YES", PrimaryKey: isPK, Unique: slices.Contains(uniqueCols, name) && !isPK,
			AutoInc: strings.Contains(extra, "auto_increment"),
		}
		if ct == schema.ColTypeString {
			col.Length = int(length.Int64)
		}
		// COLUMN_DEFAULT is NULL both for no default and for DEFAULT NULL.
		if defaultText.Valid && !col.AutoInc {
			text, generated := defaultText.String, strings.Contains(extra, "DEFAULT_GENERATED")
			if generated {
				text = unescapeStoredExpression(text)
			}
			col.Default, col.Overrides = mysqlDefaultFromStored(text, generated, ct)
		}
		cols = append(cols, col)
	}
	return cols, ambiguities, rows.Err()
}

// ---- Defaults ----

// storedDefault returns what MySQL reports for the default
// renderDefaultExpr writes for raw: the text of COLUMN_DEFAULT (already
// unescaped, see unescapeStoredExpression) and whether EXTRA flags it
// DEFAULT_GENERATED, which MySQL does for every parenthesized default. ok is
// false when the column has no default.
//
// MySQL also rewrites an expression when storing it (function names in lower
// case, spaces around operators). That part is not replayed here:
// core's expression comparison ignores case and whitespace.
func storedDefault(raw schema.Column) (text string, generated, ok bool, err error) {
	if expr := raw.Overrides[DriverName].Default; expr != "" {
		return expr, true, true, nil
	}
	if raw.Default == nil {
		return "", false, false, nil
	}
	text, err = literalText(raw.Default)
	if err != nil {
		return "", false, false, err
	}
	if needsExpressionDefault(applyOverride(raw).Type) {
		return quoteLiteral(text), true, true, nil
	}
	return text, false, true, nil
}

// mysqlDefaultFromStored maps a stored default onto the canonical column.
// Introspect and NormalizeColumn both go through it, so a declaration and the
// live column it produced are described the same way.
//
// A literal default (generated false) is reported by MySQL as bare text, so
// the column type decides how to read it: "1" is true on a boolean column, a
// number on a numeric one and a string anywhere else.
//
// A generated default is an expression. One that is only a literal (a quoted
// string, a number, TRUE, FALSE) becomes Default; NULL is no default; anything
// else is kept under the mysql override, which is what the renderer emits
// unchanged. Charset introducers MySQL adds to string literals are removed,
// and the synonyms of now() are spelled now(), as MySQL stores them.
func mysqlDefaultFromStored(text string, generated bool, ct schema.ColumnType) (any, map[string]schema.ColumnOverride) {
	if !generated {
		switch {
		case ct == schema.ColTypeBoolean && text == "1":
			return true, nil
		case ct == schema.ColTypeBoolean && text == "0":
			return false, nil
		case isNumericType(ct):
			if n, isNumber := parseNumber(text); isNumber {
				return n, nil
			}
		}
		return text, nil
	}

	expr := stripEnclosingParens(stripCharsetIntroducers(strings.TrimSpace(text)))
	if s, isString := parseStringLiteral(expr); isString {
		if isNumericType(ct) {
			if n, isNumber := parseNumber(s); isNumber {
				return n, nil
			}
		}
		return s, nil
	}
	if n, isNumber := parseNumber(expr); isNumber {
		return n, nil
	}
	switch strings.ToLower(expr) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "":
		return nil, nil
	}
	if m := nowSynonym.FindStringSubmatch(expr); m != nil {
		expr = "now(" + m[1] + ")"
	}
	return nil, map[string]schema.ColumnOverride{DriverName: {Default: expr}}
}

// nowSynonym matches the spellings MySQL stores as now() / now(n) when they
// are written in parentheses, the way renderDefaultExpr writes them. A legacy
// column created with a bare DEFAULT CURRENT_TIMESTAMP keeps that spelling in
// the catalog; mapping it too makes both read the same.
var nowSynonym = regexp.MustCompile(`(?i)^(?:now|current_timestamp|localtime|localtimestamp)(?:\(\s*(\d*)\s*\))?$`)

// unescapeStoredExpression undoes the escaping MySQL applies to an expression
// default in COLUMN_DEFAULT: DEFAULT ('it”s') is reported as
// _utf8mb4\'it\\\'s\', i.e. the expression text _utf8mb4'it\'s' with every
// quote and backslash escaped once more.
func unescapeStoredExpression(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+1 < len(text) {
			i++
		}
		out.WriteByte(text[i])
	}
	return out.String()
}

// stripCharsetIntroducers removes the introducer MySQL puts in front of every
// string literal of a stored expression (_utf8mb4'x'). Which charset it names
// depends on the connection that created the column, so it is noise for a
// comparison.
func stripCharsetIntroducers(expr string) string {
	var out strings.Builder
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '\'' || c == '"' || c == '`' {
			end := quotedEnd(expr, i)
			out.WriteString(expr[i:end])
			i = end - 1
			continue
		}
		if c == '_' && (i == 0 || !isIdentByte(expr[i-1])) {
			j := i + 1
			for j < len(expr) && isAlphaNum(expr[j]) {
				j++
			}
			if j > i+1 && j < len(expr) && expr[j] == '\'' {
				i = j - 1 // drop the introducer; the literal is copied next
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

// quotedEnd returns the index just past the quoted string or identifier that
// opens at expr[start]. A backslash escapes the next byte and a doubled quote
// stays inside. An unterminated quote runs to the end.
func quotedEnd(expr string, start int) int {
	quote := expr[start]
	for i := start + 1; i < len(expr); i++ {
		switch {
		case expr[i] == '\\' && quote != '`':
			i++
		case expr[i] == quote:
			if i+1 < len(expr) && expr[i+1] == quote {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(expr)
}

func isAlphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isIdentByte(c byte) bool { return isAlphaNum(c) || c == '_' || c == '$' }

// parseStringLiteral reads expr as exactly one single-quoted string, with
// both of MySQL's quote escapes (” and \') and its backslash escapes.
func parseStringLiteral(expr string) (string, bool) {
	if len(expr) < 2 || expr[0] != '\'' || quotedEnd(expr, 0) != len(expr) || expr[len(expr)-1] != '\'' {
		return "", false
	}
	body := expr[1 : len(expr)-1]
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body):
			i++
			switch body[i] {
			case 'n':
				out.WriteByte('\n')
			case 't':
				out.WriteByte('\t')
			case 'r':
				out.WriteByte('\r')
			case '0':
				out.WriteByte(0)
			default:
				out.WriteByte(body[i])
			}
		case c == '\'':
			i++ // a quote inside the body is always doubled
			out.WriteByte('\'')
		default:
			out.WriteByte(c)
		}
	}
	return out.String(), true
}

// stripEnclosingParens removes parentheses that enclose the whole expression,
// repeatedly: "((now()))" -> "now()", while "(a)+(b)" is left alone.
func stripEnclosingParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '\'', '"', '`':
				i = quotedEnd(s, i) - 1
			case '(':
				depth++
			case ')':
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

func isNumericType(ct schema.ColumnType) bool {
	switch ct {
	case schema.ColTypeInteger, schema.ColTypeBigInt, schema.ColTypeReal, schema.ColTypeNumeric:
		return true
	}
	return false
}

// ---- Keys, indexes and foreign keys ----

// liveKey is one index as information_schema.STATISTICS reports it. MySQL
// keeps the primary key, unique constraints and plain indexes in that one
// list.
type liveKey struct {
	name       string
	unique     bool
	columns    []string
	functional bool // has an expression key part, which the canonical Index can't express
}

func (d *MySQLDriver) introspectKeys(ctx context.Context, physical string) ([]liveKey, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
		ORDER BY INDEX_NAME, SEQ_IN_INDEX`, physical)
	if err != nil {
		return nil, behemotherr.NewMigrationError("MySQLIntrospector.keys", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var keys []liveKey
	for rows.Next() {
		var name string
		var nonUnique int
		var column sql.NullString // NULL for an expression key part
		if err := rows.Scan(&name, &nonUnique, &column); err != nil {
			return nil, behemotherr.NewMigrationError("MySQLIntrospector.keys", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if n := len(keys); n == 0 || keys[n-1].name != name {
			keys = append(keys, liveKey{name: name, unique: nonUnique == 0})
		}
		key := &keys[len(keys)-1]
		if column.Valid {
			key.columns = append(key.columns, column.String)
		} else {
			key.functional = true
		}
	}
	return keys, rows.Err()
}

// classifyKeys sorts a table's keys into the canonical model:
//   - PRIMARY is the primary key.
//   - A single-column unique key is Column.Unique when it carries the name
//     the driver gives such a key (uniqueKeyName) or the column's own name,
//     which is what MySQL calls the key of an inline UNIQUE. MySQL doesn't
//     tell a unique constraint from a unique index, so the name is the only
//     way to keep a declared Index{Unique: true} on one column an index.
//   - A non-unique index on exactly a foreign key's columns, named after
//     the key (or after its first column, MySQL's choice for an unnamed key),
//     is the one MySQL created for that key. It is left out: it was never
//     declared and would show as an extra live index on every diff.
//   - Functional indexes are left out: the canonical Index can't express them.
//   - Everything else is an Index.
func classifyKeys(physicalTable string, keys []liveKey, fks []schema.ForeignKey) (pkCols, uniqueCols []string, indexes []schema.Index) {
	for _, key := range keys {
		switch {
		case key.name == "PRIMARY":
			pkCols = key.columns
		case key.functional:
		case key.unique && len(key.columns) == 1 &&
			(key.name == key.columns[0] || key.name == uniqueKeyName(physicalTable, key.columns[0])):
			uniqueCols = append(uniqueCols, key.columns[0])
		case !key.unique && slices.ContainsFunc(fks, func(fk schema.ForeignKey) bool {
			return slices.Equal(fk.Columns, key.columns) && (key.name == fk.Name || key.name == fk.Columns[0])
		}):
		default:
			indexes = append(indexes, schema.Index{Name: key.name, Columns: key.columns, Unique: key.unique})
		}
	}
	return pkCols, uniqueCols, indexes
}

func (d *MySQLDriver) introspectForeignKeys(ctx context.Context, physical string) ([]schema.ForeignKey, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT k.CONSTRAINT_NAME, r.DELETE_RULE, k.REFERENCED_TABLE_NAME, k.COLUMN_NAME, k.REFERENCED_COLUMN_NAME
		FROM information_schema.KEY_COLUMN_USAGE k
		JOIN information_schema.REFERENTIAL_CONSTRAINTS r
			ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME AND r.TABLE_NAME = k.TABLE_NAME
		WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ? AND k.REFERENCED_TABLE_NAME IS NOT NULL
		ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION`, physical)
	if err != nil {
		return nil, behemotherr.NewMigrationError("MySQLIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationQueryFailed, err)
	}
	defer rows.Close()

	var fks []schema.ForeignKey
	for rows.Next() {
		var name, rule, refTable, col, refCol string
		if err := rows.Scan(&name, &rule, &refTable, &col, &refCol); err != nil {
			return nil, behemotherr.NewMigrationError("MySQLIntrospector.foreignKeys", behemotherr.ErrorCodeMigrationScanFailed, err)
		}
		if n := len(fks); n > 0 && fks[n-1].Name == name {
			fks[n-1].Columns = append(fks[n-1].Columns, col)
			fks[n-1].RefColumns = append(fks[n-1].RefColumns, refCol)
			continue
		}
		fks = append(fks, schema.ForeignKey{
			Name: name, Columns: []string{col}, RefTable: refTable, RefColumns: []string{refCol},
			OnDelete: mapDeleteRule(rule),
		})
	}
	return fks, rows.Err()
}

// mapDeleteRule maps REFERENTIAL_CONSTRAINTS.DELETE_RULE. NO ACTION (the
// default) and SET DEFAULT have no ForeignKeyAction; both collapse to
// Restrict, which is how InnoDB behaves for them anyway.
func mapDeleteRule(rule string) schema.ForeignKeyAction {
	switch rule {
	case "CASCADE":
		return schema.FKCascade
	case "SET NULL":
		return schema.FKSetNull
	default: // RESTRICT, NO ACTION, SET DEFAULT
		return schema.FKRestrict
	}
}
