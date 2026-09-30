// Package postgres is behemoth's PostgreSQL integration, in its own module so
// applications that don't use PostgreSQL don't depend on it:
//
//   - PostgresAdapter implements behemoth.Database (application reads/writes).
//   - PostgreSQLDriver implements the migration interfaces:
//     core.SchemaDriver, core.MigrationRenderer and core.SchemaIntrospector.
//
// Neither imports a database/sql driver: open the *sql.DB with lib/pq,
// pgx/stdlib or any other PostgreSQL driver. Both take the same
// behemoth.SchemaResolver, so application queries and migrations agree on
// physical table and column names.
package postgres
