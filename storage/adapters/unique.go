package adapters

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/errs"
)

// Dialect names the SQL engine an adapter talks to, for what differs between
// engines when a write breaks a unique key: how the database names the key,
// and how the key's columns are looked up.
type Dialect string

const (
	DialectPostgres  Dialect = "postgres"
	DialectMySQL     Dialect = "mysql"
	DialectSQLServer Dialect = "sqlserver"
	DialectSQLite    Dialect = "sqlite"
)

// UniqueKeyName is the name a migration driver gives the unique key behind
// a column declared unique, from physical names, as the database stores it:
// "<table>_<column>_key". PostgreSQL cuts a name to 63 bytes. MySQL (64
// characters) and SQL Server (128) are given a name already cut, ending in a
// hash of the full one. SQLite names the key itself, and its errors name the
// columns instead, so it has no name here.
//
// The MySQL and SQL Server drivers name their keys with it. The PostgreSQL
// driver passes the full name and lets the server cut it
// (uniqueConstraintName in storage/adapters/postgres/driver.go).
func UniqueKeyName(dialect Dialect, table, column string) string {
	name := table + "_" + column + "_key"
	switch dialect {
	case DialectPostgres:
		if len(name) > 63 {
			return name[:63]
		}
		return name
	case DialectMySQL:
		return hashedName(name, 64)
	case DialectSQLServer:
		return hashedName(name, 128)
	default:
		return ""
	}
}

// hashedName cuts name to max characters, ending it with a hash of the full
// name so that two long names that share a start stay apart.
func hashedName(name string, max int) string {
	if len(name) <= max {
		return name
	}
	h := fnv.New32a()
	h.Write([]byte(name))
	suffix := fmt.Sprintf("_%08x", h.Sum32())
	return name[:max-len(suffix)] + suffix
}

// KeyFinder tells which unique key a duplicate key error broke, so that the
// error can name its columns (errs.NewDuplicateKeyOn). The store answers a
// duplicate value of a column declared unique with the column's code, which
// needs the column.
//
// The error names the key in one of two ways. SQLite's names the columns,
// physical names that the resolver maps back. PostgreSQL's, MySQL's and SQL
// Server's name the key, which is matched first against the names the
// migration drivers give the declared keys (UniqueKeyName and the declared
// index names), and otherwise looked up in the database's catalog, which
// covers a table the application created itself.
type KeyFinder struct {
	Dialect  Dialect
	Resolver behemoth.SchemaResolver

	// Catalog runs query, which CatalogQuery wrote, and returns the first
	// column of each row. nil leaves a name that matches no declared key
	// unexplained. On PostgreSQL it must not run in the transaction of the
	// failed write, which the error has aborted.
	Catalog func(ctx context.Context, query string, args ...any) ([]string, error)
	// Placeholder renders the nth (from 1) argument of a catalog query:
	// "$1", "?", "@p1". nil means "?".
	Placeholder func(n int) string
}

// catalogTimeout bounds a catalog lookup. It runs while an error is being
// classified, which has no context of its own; the query reads one index.
const catalogTimeout = 5 * time.Second

// DuplicateKey returns the duplicate key error of err, a unique violation of
// table, naming the columns of the key when f can tell them.
func (f KeyFinder) DuplicateKey(op, table string, err error) error {
	return errs.NewDuplicateKeyOn(op, table, f.Columns(table, err), err)
}

// Columns returns the canonical columns of the unique key of table that err
// broke, or nil when f can't tell.
func (f KeyFinder) Columns(table string, err error) []string {
	name, physical := UniqueViolation(err)
	if len(physical) > 0 {
		return CanonicalColumns(f.Resolver, table, physical)
	}
	if name == "" {
		return nil
	}
	if columns := f.declared(table, name); columns != nil {
		return columns
	}
	if f.Catalog == nil {
		return nil
	}
	placeholder := f.Placeholder
	if placeholder == nil {
		placeholder = func(int) string { return "?" }
	}
	query := CatalogQuery(f.Dialect, placeholder)
	if query == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), catalogTimeout)
	defer cancel()
	physical, lookupErr := f.Catalog(ctx, query, resolveName(f.Resolver, table), name)
	if lookupErr != nil || len(physical) == 0 {
		return nil
	}
	return CanonicalColumns(f.Resolver, table, physical)
}

// declared returns the columns of the declared unique key of table that the
// database knows as name.
func (f KeyFinder) declared(table, name string) []string {
	keys, ok := f.Resolver.(behemoth.UniqueKeyResolver)
	if !ok {
		return nil
	}
	physTable := resolveName(f.Resolver, table)
	for _, key := range keys.UniqueKeys(table) {
		switch {
		case key.Index != "":
			if key.Index == name {
				return slices.Clone(key.Columns)
			}
		case len(key.Columns) == 1:
			column := resolveColumn(f.Resolver, table, key.Columns[0])
			if UniqueKeyName(f.Dialect, physTable, column) == name {
				return slices.Clone(key.Columns)
			}
		}
	}
	return nil
}

// CatalogQuery returns the query that lists the columns of an index, in the
// index's order, from the database's catalog. Its two arguments are the
// physical table and the index's name. placeholder renders the nth argument.
// It is "" for SQLite, whose errors name the columns.
func CatalogQuery(dialect Dialect, placeholder func(n int) string) string {
	switch dialect {
	case DialectPostgres:
		// A unique constraint has an index of the same name, so pg_index
		// covers constraints and indexes alike.
		return "SELECT a.attname FROM pg_index x" +
			" JOIN pg_class i ON i.oid = x.indexrelid" +
			" JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = ANY(x.indkey)" +
			" WHERE x.indrelid = to_regclass(quote_ident(" + placeholder(1) + ")) AND i.relname = " + placeholder(2) +
			" ORDER BY array_position(x.indkey::int2[], a.attnum)"
	case DialectMySQL:
		return "SELECT COLUMN_NAME FROM information_schema.STATISTICS" +
			" WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + placeholder(1) + " AND INDEX_NAME = " + placeholder(2) +
			" ORDER BY SEQ_IN_INDEX"
	case DialectSQLServer:
		return "SELECT c.name FROM sys.indexes i" +
			" JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id" +
			" JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id" +
			" WHERE i.object_id = OBJECT_ID(" + placeholder(1) + ") AND i.name = " + placeholder(2) + " AND ic.is_included_column = 0" +
			" ORDER BY ic.key_ordinal"
	default:
		return ""
	}
}

// UniqueViolation reads what a unique violation names: the key's name
// (PostgreSQL, MySQL, SQL Server), or its physical columns (SQLite). Both
// are empty when err is not one, or names nothing it can read. It knows no
// driver's types, so that every adapter can use it whatever driver the
// application chose:
//
//   - PostgreSQL: the constraint field of the error, which lib/pq
//     (Get('n')), bun's pgdriver (Field('n')) and pgx (ConstraintName)
//     each expose differently. The message is not read: the server may
//     translate it.
//   - SQLite: "UNIQUE constraint failed: users.email".
//   - MySQL (1062): "Duplicate entry '...' for key 'users.users_email_key'".
//   - SQL Server (2601, 2627): "... with unique index 'users_email_key'" or
//     "Violation of UNIQUE KEY constraint 'UQ__users__...'".
func UniqueViolation(err error) (name string, physicalColumns []string) {
	if err == nil {
		return "", nil
	}
	if name, ok := postgresConstraint(err); ok {
		return name, nil
	}
	msg := err.Error()
	if _, rest, ok := strings.Cut(msg, "UNIQUE constraint failed: "); ok {
		if index, ok := quoted(rest, "index '"); ok {
			return index, nil
		}
		for _, part := range strings.Split(rest, ",") {
			part = strings.TrimSpace(part)
			if _, column, ok := strings.Cut(part, "."); ok {
				part = column
			}
			if part != "" {
				physicalColumns = append(physicalColumns, part)
			}
		}
		return "", physicalColumns
	}
	if strings.Contains(msg, "Error 1062") {
		if i := strings.LastIndex(msg, "for key '"); i >= 0 {
			key := strings.TrimSuffix(msg[i+len("for key '"):], "'")
			if _, after, ok := strings.Cut(key, "."); ok { // MySQL 8.0.19 and later prefix the table
				key = after
			}
			return key, nil
		}
	}
	if strings.Contains(msg, "duplicate key") {
		if index, ok := quoted(msg, "with unique index '"); ok {
			return index, nil
		}
		if constraint, ok := quoted(msg, "constraint '"); ok {
			return constraint, nil
		}
	}
	return "", nil
}

// quoted returns the text after prefix in s, up to the next quote.
func quoted(s, prefix string) (string, bool) {
	_, rest, ok := strings.Cut(s, prefix)
	if !ok {
		return "", false
	}
	value, _, ok := strings.Cut(rest, "'")
	return value, ok && value != ""
}

// postgresConstraint returns the constraint a PostgreSQL unique violation
// (SQLSTATE 23505) names.
func postgresConstraint(err error) (string, bool) {
	var withState interface{ SQLState() string }
	var withField interface{ Field(byte) string }
	switch {
	case errors.As(err, &withField): // bun's pgdriver
		if withField.Field('C') != "23505" {
			return "", false
		}
		return withField.Field('n'), true
	case errors.As(err, &withState):
		if withState.SQLState() != "23505" {
			return "", false
		}
		if withGet, ok := withState.(interface{ Get(byte) string }); ok { // lib/pq
			return withGet.Get('n'), true
		}
		// pgx's *pgconn.PgError has the field and no accessor.
		v := reflect.ValueOf(withState)
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		if v.Kind() == reflect.Struct {
			if f := v.FieldByName("ConstraintName"); f.IsValid() && f.Kind() == reflect.String {
				return f.String(), true
			}
		}
		return "", true
	}
	return "", false
}

// CanonicalColumns maps physical columns of table back to canonical names. A
// column the resolver does not know keeps its name.
func CanonicalColumns(resolver behemoth.SchemaResolver, table string, physical []string) []string {
	byPhysical := map[string]string{}
	if resolver != nil {
		for _, c := range resolver.Columns(table) {
			byPhysical[resolver.ResolveColumn(table, c)] = c
		}
	}
	out := make([]string, len(physical))
	for i, p := range physical {
		if canonical, ok := byPhysical[p]; ok {
			out[i] = canonical
		} else {
			out[i] = p
		}
	}
	return out
}

func resolveName(r behemoth.SchemaResolver, table string) string {
	if r == nil {
		return table
	}
	return r.Resolve(table)
}

func resolveColumn(r behemoth.SchemaResolver, table, column string) string {
	if r == nil {
		return column
	}
	return r.ResolveColumn(table, column)
}

// CatalogOn returns a KeyFinder.Catalog that runs its query on q.
func CatalogOn(q Querier) func(ctx context.Context, query string, args ...any) ([]string, error) {
	if q == nil {
		return nil
	}
	return func(ctx context.Context, query string, args ...any) ([]string, error) {
		rows, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var columns []string
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				return nil, err
			}
			columns = append(columns, column)
		}
		return columns, rows.Err()
	}
}
