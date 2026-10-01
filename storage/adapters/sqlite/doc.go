// Package sqlite is behemoth's SQLite integration, in its own module so
// applications that don't use SQLite don't depend on it (or on cgo):
//
//   - SQLiteAdapter implements behemoth.Database (application reads/writes).
//   - SQLiteDriver implements the migration interfaces:
//     core.SchemaDriver, core.MigrationRenderer and core.SchemaIntrospector.
//
// Both take the same behemoth.SchemaResolver, so application queries and
// migrations agree on physical table and column names.
//
// The migration driver works with any database/sql SQLite driver. The adapter
// classifies errors using github.com/mattn/go-sqlite3's error codes, which is
// what makes this module depend on it, and on cgo.
package sqlite
