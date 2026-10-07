## **MySQL Adapter**

This document covers three places where `MySQLAdapter` (`storage/adapters/mysql/mysql.go`) differs from the other SQL adapters: reading values back, deciding whether a guarded update applied, and how `UpdateOne` and `DeleteOne` pick their one row. The migration driver in the same package is described in [`../../migrations/migration_design_decision.md`](../../migrations/migration_design_decision.md).

### Reading values

The adapter scans each column into an `any` and hands the row to the model's `FromMap`, which expects Go types: `string`, `int64`, `bool`, `time.Time`. The Postgres and SQLite drivers return those types. `go-sql-driver/mysql` does not:

| Statement | Protocol | What the driver returns |
| --- | --- | --- |
| with arguments (`WHERE id = ?`) | binary | `int64` for integers, `[]byte` for strings and times |
| without arguments (`FindMany` with an empty expression) | text | `[]byte` for every value, numbers included |

`scanRow` (`scan.go`) converts each value by the column's type name, which the driver reports through `sql.ColumnType`:

| Column type | Go value |
| --- | --- |
| `CHAR`, `VARCHAR`, the `TEXT` sizes, `JSON`, `DECIMAL`, `ENUM`, `SET`, `TIME` | `string` |
| `TINYINT` | `bool` |
| `UNSIGNED TINYINT`, `SMALLINT`, `MEDIUMINT`, `INT`, `BIGINT`, `YEAR` | `int64` |
| `FLOAT`, `DOUBLE` | `float64` |
| `DATETIME`, `TIMESTAMP`, `DATE` | `time.Time`, parsed as UTC |
| the `BLOB` sizes, `BINARY`, `VARBINARY`, `BIT` | `[]byte`, unchanged |

`FindOne` uses `QueryContext` and not `QueryRowContext`, because only `sql.Rows` exposes the column types.

Times are parsed as UTC because that is the zone the driver writes a `time.Time` in by default. A DSN with `parseTime=true` makes the driver return `time.Time` itself, and `scanRow` passes it through. A DSN with `loc` set to another zone and without `parseTime` would be read back shifted.

### A `TINYINT` column is read as a bool
**Context:** MySQL has no boolean type. The migration driver stores a `bool` column as `TINYINT(1)`, and the models assert `bool` in `FromMap`. The display width `(1)` is what marks the column as a boolean, but `sql.ColumnType` reports only `TINYINT`.
**Options considered:**
- *Read every signed `TINYINT` as a bool.* No extra query. An application table that uses `TINYINT` for a small number reads back `true` or `false` through the adapter.
- *Look up `COLUMN_TYPE` in `information_schema` and cache it per table.* Exact, as in the introspector. It costs a catalog query per table and a cache on the adapter that goes stale when a migration changes a column.
- *Accept `int64` for a bool in every model's `FromMap`.* Moves a MySQL detail into the models and into every plugin's model.
**Decision:** The first. Behemoth's own migrations never create a `TINYINT` for anything but a bool (`int` becomes `INT`). `UNSIGNED TINYINT` stays a number, so an application has a small integer type that is read as one.
**Revisit if:** applications commonly point the adapter at existing tables with signed `TINYINT` counters.

### The re-count after an update is a locking read
**Context:** MySQL reports the rows an `UPDATE` changed, not the rows it matched, so 0 can mean "no such row" or "the row already had these values". `ExpectOneRow` settles it by counting the rows that match the update's expression. The store relies on guarded updates for at-most-once semantics: `ConsumeToken` updates `WHERE id = ? AND consumed_at IS NULL` inside a transaction, and the loser of a race has to get `NotFound`.

Under MySQL's default isolation level (`REPEATABLE READ`) a plain `SELECT` in a transaction reads the snapshot taken at the transaction's first read. The loser's `UPDATE` reads the committed row and changes nothing, but its re-count read the snapshot, where `consumed_at` was still null. It counted one row and reported success. The store contract test consumed one single-use token 12 times this way in one run.
**Options considered:**
- *Re-count with `FOR SHARE`.* A locking read returns the committed row, as the `UPDATE` did. One keyword, and it only runs when an update changed nothing.
- *Require `clientFoundRows=true` in the DSN.* The driver then reports matched rows and no re-count is needed. The adapter can't check the flag, and forgetting it brings the bug back silently.
- *Run token consumption at `READ COMMITTED`.* Fixes this caller only; every other guarded update inside a transaction has the same problem.
**Decision:** `FOR SHARE`, in the unexported `count`. The public `Count` stays a plain read.
**Revisit if:** MySQL versions before 8.0 have to be supported (`FOR SHARE` is `LOCK IN SHARE MODE` there).

### `UpdateOne` and `DeleteOne` use `LIMIT 1`, not a subquery

Both statements let MySQL pick the row with `LIMIT 1`. Selecting the row's key in a subquery first, as the PostgreSQL and SQLite adapters do, deadlocks on MySQL under concurrency. The explanation, the deadlock report and the decision are in [`single_row_writes.md`](single_row_writes.md), which covers SQL Server as well.

`[Known limitation]` The GORM and Bun adapters use the same re-count with a plain read. They have not been tested on MySQL, see `docs/ongoing.md`.
