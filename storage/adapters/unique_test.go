package adapters

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/errs"
)

// Errors shaped like the PostgreSQL drivers' own, which expose the
// constraint each in their way.
type (
	// libpqError is lib/pq's *pq.Error: SQLState and Get.
	libpqError struct{ code, constraint string }
	// pgxError is pgx's *pgconn.PgError: SQLState, and the constraint in a
	// field.
	pgxError struct {
		Code           string
		ConstraintName string
	}
	// pgdriverError is bun's pgdriver.Error: Field.
	pgdriverError struct{ fields map[byte]string }
)

func (e *libpqError) Error() string    { return "pq: duplicate key value violates unique constraint" }
func (e *libpqError) SQLState() string { return e.code }
func (e *libpqError) Get(k byte) string {
	if k == 'n' {
		return e.constraint
	}
	return ""
}
func (e *pgxError) Error() string           { return "ERROR: duplicate key value (SQLSTATE " + e.Code + ")" }
func (e *pgxError) SQLState() string        { return e.Code }
func (e pgdriverError) Error() string       { return "ERROR #" + e.fields['C'] }
func (e pgdriverError) Field(k byte) string { return e.fields[k] }

// UniqueViolation reads the key's name, or its columns, from each engine's
// error, through a wrapping too. Another error names nothing.
func TestUniqueViolation(t *testing.T) {
	for name, tc := range map[string]struct {
		err     error
		key     string
		columns []string
	}{
		"lib/pq":                            {&libpqError{"23505", "users_email_key"}, "users_email_key", nil},
		"pgx":                               {fmt.Errorf("insert: %w", &pgxError{"23505", "users_email_key"}), "users_email_key", nil},
		"pgdriver":                          {pgdriverError{map[byte]string{'C': "23505", 'n': "users_email_key"}}, "users_email_key", nil},
		"sqlite":                            {errors.New("UNIQUE constraint failed: users.email"), "", []string{"email"}},
		"sqlite key":                        {errors.New("UNIQUE constraint failed: accounts.provider_id, accounts.account_id"), "", []string{"provider_id", "account_id"}},
		"sqlite expression index":           {errors.New("UNIQUE constraint failed: index 'users_lower_email'"), "users_lower_email", nil},
		"mysql 8":                           {errors.New("Error 1062 (23000): Duplicate entry 'a@b.c' for key 'users.users_email_key'"), "users_email_key", nil},
		"mysql 5.7":                         {errors.New("Error 1062: Duplicate entry 'a@b.c' for key 'users_email_key'"), "users_email_key", nil},
		"mysql primary key":                 {errors.New("Error 1062 (23000): Duplicate entry 'u-1' for key 'users.PRIMARY'"), "PRIMARY", nil},
		"mysql value that looks like a key": {errors.New("Error 1062 (23000): Duplicate entry 'x for key 'y' for key 'users.users_email_key'"), "users_email_key", nil},
		"sqlserver index":                   {errors.New("mssql: Cannot insert duplicate key row in object 'dbo.users' with unique index 'users_email_key'. The duplicate key value is (a@b.c)."), "users_email_key", nil},
		"sqlserver constraint":              {errors.New("mssql: Violation of PRIMARY KEY constraint 'PK__users__3213E83F'. Cannot insert duplicate key in object 'dbo.users'. The duplicate key value is (u-1)."), "PK__users__3213E83F", nil},
		"another postgres error":            {&libpqError{"23503", "fk"}, "", nil},
		"another error":                     {errors.New("connection refused"), "", nil},
		"nil":                               {nil, "", nil},
	} {
		key, columns := UniqueViolation(tc.err)
		if key != tc.key || !slices.Equal(columns, tc.columns) {
			t.Errorf("%s: UniqueViolation = (%q, %q), want (%q, %q)", name, key, columns, tc.key, tc.columns)
		}
	}
}

// The name of a unique column's key is what the migration drivers give it,
// as the database stores it: PostgreSQL cuts a long one, and MySQL and SQL
// Server end a long one with a hash of the full name.
func TestUniqueKeyName(t *testing.T) {
	if got := UniqueKeyName(DialectPostgres, "users", "email"); got != "users_email_key" {
		t.Errorf("postgres: %q", got)
	}
	long := strings.Repeat("c", 70)
	if got := UniqueKeyName(DialectPostgres, "users", long); got != ("users_" + long + "_key")[:63] {
		t.Errorf("postgres cuts at 63 bytes: %q", got)
	}
	for dialect, max := range map[Dialect]int{DialectMySQL: 64, DialectSQLServer: 128} {
		if got := UniqueKeyName(dialect, "users", "email"); got != "users_email_key" {
			t.Errorf("%s: %q", dialect, got)
		}
		longer := strings.Repeat("c", max)
		a, b := UniqueKeyName(dialect, "users", longer+"a"), UniqueKeyName(dialect, "users", longer+"b")
		if len(a) != max || a == b || !strings.HasPrefix(a, "users_ccc") {
			t.Errorf("%s: long names %q and %q, want %d characters, apart", dialect, a, b, max)
		}
	}
	if got := UniqueKeyName(DialectSQLite, "users", "email"); got != "" {
		t.Errorf("sqlite names its own keys: %q", got)
	}
}

// keyResolver is a resolver with physical names and unique keys.
type keyResolver struct {
	columns map[string]string // canonical -> physical, of users
	keys    []behemoth.UniqueKey
}

func (r keyResolver) Resolve(table string) string { return "app_" + table }
func (r keyResolver) ResolveColumn(_ string, column string) string {
	if physical, ok := r.columns[column]; ok {
		return physical
	}
	return column
}
func (r keyResolver) Columns(string) []string {
	var out []string
	for c := range r.columns {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}
func (r keyResolver) UniqueKeys(string) []behemoth.UniqueKey { return r.keys }

// A KeyFinder names the canonical columns of the key an error broke: from
// the physical columns the error names, from a declared key the name is the
// name of, or else from the catalog, asked about the physical table and the
// name.
func TestKeyFinder(t *testing.T) {
	resolver := keyResolver{
		columns: map[string]string{"id": "id", "email": "email", "handle": "user_handle", "provider_id": "provider", "account_id": "subject"},
		keys: []behemoth.UniqueKey{
			{Columns: []string{"email"}, TakenCode: "email_taken"},
			{Columns: []string{"handle"}, TakenCode: "handle_taken"},
			{Index: "uq_accounts", Columns: []string{"provider_id", "account_id"}},
		},
	}
	var asked [][]any
	catalog := func(_ context.Context, query string, args ...any) ([]string, error) {
		asked = append(asked, args)
		if !strings.Contains(query, "$1") || !strings.Contains(query, "$2") {
			return nil, errors.New("the query was not given the dialect's placeholders: " + query)
		}
		return []string{"id"}, nil
	}
	f := KeyFinder{Dialect: DialectPostgres, Resolver: resolver, Catalog: catalog, Placeholder: func(n int) string { return fmt.Sprintf("$%d", n) }}

	for name, tc := range map[string]struct {
		err  error
		want []string
	}{
		"physical columns":           {errors.New("UNIQUE constraint failed: app_users.user_handle"), []string{"handle"}},
		"a unique column, by name":   {&libpqError{"23505", "app_users_email_key"}, []string{"email"}},
		"a physical column, by name": {&libpqError{"23505", "app_users_user_handle_key"}, []string{"handle"}},
		"a unique index":             {&libpqError{"23505", "uq_accounts"}, []string{"provider_id", "account_id"}},
		"the catalog":                {&libpqError{"23505", "app_users_pkey"}, []string{"id"}},
		"not a unique violation":     {errors.New("timeout"), nil},
	} {
		asked = nil
		if got := f.Columns("users", tc.err); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Columns = %q, want %q", name, got, tc.want)
		}
		if name == "the catalog" {
			if len(asked) != 1 || asked[0][0] != "app_users" || asked[0][1] != "app_users_pkey" {
				t.Errorf("the catalog was asked %v, want the physical table and the name", asked)
			}
		} else if len(asked) != 0 {
			t.Errorf("%s: the catalog was asked %v, though the name was explained", name, asked)
		}
	}

	f.Catalog = nil
	if got := f.Columns("users", &libpqError{"23505", "app_users_pkey"}); got != nil {
		t.Errorf("no catalog: Columns = %q, want nil", got)
	}
	f.Catalog = func(context.Context, string, ...any) ([]string, error) { return nil, errors.New("aborted") }
	if got := f.Columns("users", &libpqError{"23505", "app_users_pkey"}); got != nil {
		t.Errorf("a failed lookup: Columns = %q, want nil", got)
	}

	err := f.DuplicateKey("Create", "users", &libpqError{"23505", "app_users_email_key"})
	if !errs.IsDuplicateKey(err) || !slices.Equal(errs.DuplicateKeyColumns(err), []string{"email"}) {
		t.Errorf("DuplicateKey = %v, want a duplicate key error that names email", err)
	}
}

// Each dialect's catalog query takes the physical table and the index's
// name, in the placeholders it is given. SQLite has none.
func TestCatalogQuery(t *testing.T) {
	question := func(int) string { return "?" }
	for _, dialect := range []Dialect{DialectPostgres, DialectMySQL, DialectSQLServer} {
		if q := CatalogQuery(dialect, question); strings.Count(q, "?") != 2 {
			t.Errorf("%s: %d placeholders in %q, want 2", dialect, strings.Count(q, "?"), q)
		}
	}
	if q := CatalogQuery(DialectSQLite, question); q != "" {
		t.Errorf("sqlite: %q", q)
	}
}
