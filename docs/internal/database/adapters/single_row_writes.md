## **Single-Row Writes: `UpdateOne` and `DeleteOne`**

This document explains how each SQL adapter writes "one row matching an expression", why the statement differs between databases, and the deadlock that the difference avoids. It is the companion of [`transactions.md`](transactions.md): that one covers transactions the caller opens, this one the locks a single statement takes.

### The contract

`behemoth.Database` in `storage.go` asks two things of `UpdateOne` and `DeleteOne`:

- At most one row is written, even when several match the expression.
- The expression holds for the row as it is written. After waiting on a concurrent writer, the write applies only if the expression still matches. Otherwise the call returns `NotFound`.

The store builds its at-most-once operations on the second point. `ConsumeToken` updates `WHERE id = ? AND consumed_at IS NULL`, and `IncrementRateLimit` updates `WHERE limit_key = ? AND count = <the count it read>`. Of several concurrent calls one writes, and the others get `NotFound` and treat it as a lost race.

### The statement per adapter

| Adapter | Statement |
| --- | --- |
| PostgreSQL, SQLite | `UPDATE t SET ... WHERE pk = (SELECT pk FROM t WHERE <expr> LIMIT 1) AND (<expr>)` |
| MySQL | `UPDATE t SET ... WHERE <expr> LIMIT 1` |
| SQL Server | `UPDATE TOP (1) t SET ... WHERE <expr>` |

`DeleteOne` has the same three shapes with `DELETE`.

PostgreSQL and SQLite have no `LIMIT` on `UPDATE`, so the row is picked by a subquery on the primary key. The expression is repeated in the outer `WHERE` because PostgreSQL runs the subquery once, before it waits on a concurrent writer, and afterwards re-checks only the outer condition.

MySQL and SQL Server used the subquery form too, until the store contract test ran against them. The next section explains why it fails there.

### Why the subquery form deadlocks on MySQL and SQL Server

The difference is whether the database locks the rows the subquery reads.

| Database | The subquery's read | Concurrent writers of one row | Result |
| --- | --- | --- | --- |
| PostgreSQL | reads a snapshot, takes no row lock | queue on the row's write lock | the one that waited matches nothing |
| SQLite | no row locks; a write locks the whole database file | queue on the database lock (`_busy_timeout`) | the one that waited matches nothing |
| MySQL (InnoDB) | takes a shared lock on the row | both hold the shared lock, both want the exclusive lock | deadlock, error 1213 |
| SQL Server | takes a shared lock on the row | one holds the shared lock, the other the update lock | deadlock, error 1205 |

A shared lock can be held by many statements at once. An exclusive lock needs every other lock on the row gone. So the subquery form locks one row twice inside one statement, first shared and then exclusive, and two copies of the statement can each hold the first lock while waiting for the second:

| Step | Statement A | Statement B |
| --- | --- | --- |
| 1 | subquery takes the shared lock | subquery takes the shared lock |
| 2 | wants the exclusive lock, waits for B's shared lock | wants the exclusive lock, waits for A's shared lock |

Neither can continue. The database ends one of them with a deadlock error and rolls its statement back.

Both databases confirmed this in their deadlock reports, taken while 20 goroutines called `IncrementRateLimit` on one key:

- **MySQL** (`SHOW ENGINE INNODB STATUS`): both transactions run the same `UPDATE`, each holds `lock mode S locks rec but not gap` on the primary key record of `rate_limits` and waits for `lock_mode X` on that record. A standalone `SELECT` in InnoDB reads a snapshot and locks nothing. A `SELECT` nested in an `UPDATE` is a locking read.
- **SQL Server** (the `xml_deadlock_report` event of the `system_health` session): on the primary key record, one session owns the lock in mode `S` and asks to convert it to `U`, the other owns it in mode `U` and asks to convert it to `X`. SQL Server reserves a row with an update lock before writing it, and only one session can hold that lock. The first session cannot get it while the second has it, and the second cannot write while the first still holds its shared lock from the subquery. At the default isolation level (`READ COMMITTED` without row versioning) every read takes a shared lock.

Between 7 and 11 of the 20 calls failed in the runs observed, on both databases. No count was handed out twice, because the victim's statement is rolled back. The cost was an error returned to the caller where a retry was expected.

### `LIMIT 1` and `TOP (1)` instead of a subquery on MySQL and SQL Server
**Context:** The deadlock above. It affects every `UpdateOne` and `DeleteOne`, and shows wherever two calls race on one row. The rate limiter does that on purpose.
**Options considered:**
- *Let the write statement pick the row itself: `LIMIT 1` on MySQL, `TOP (1)` on SQL Server.* Without a subquery there is no shared lock. The statement asks for the write lock as it finds the row, so concurrent statements queue. The one that waited checks the expression against the committed row, matches nothing and returns `NotFound`. It works for any table and expression, and the expression appears once.
- *Keep the subquery and retry on the deadlock error in the store.* The deadlock still happens and costs a rollback each time. The adapters do not classify deadlock errors yet.
- *Keep the subquery and make it a locking read (`FOR UPDATE` on MySQL, `WITH (UPDLOCK)` on SQL Server).* Also removes the shared lock, with a longer statement and one more database-specific clause.
**Decision:** The first. PostgreSQL and SQLite keep the subquery form: they have no `LIMIT` on `UPDATE`, and it does not deadlock there.
**Revisit if:** SQL Server is run with `READ_COMMITTED_SNAPSHOT` on and the subquery form is wanted back for uniformity (reads then use row versions, as on PostgreSQL). The `TOP (1)` form is correct in both modes.

### What this does not prevent

`[Known limitation]` A deadlock is still possible where a single statement cannot avoid it:

- Two transactions of several statements that lock the same rows in a different order, such as two writes whose hook handlers write other tables.
- Two statements that reach one row through different indexes.

The store does not retry on a deadlock error, and the adapters report it as an unknown database error.

`[Known limitation]` `LIMIT 1` and `TOP (1)` run without an `ORDER BY`. When several rows match, the database chooses which one is written. MySQL also marks `UPDATE ... LIMIT` without an order as unsafe for statement-based replication; row-based replication, the default, is not affected.

Both are tracked in `docs/ongoing.md`.

### Tests

`TestStoreContract` in `tests/store/contract_test.go` runs the store's operations against every backend. Its `RateLimits` part sends 20 concurrent hits on one key and expects the counts 1 to 20, and its `Tokens` part consumes one single-use token from several goroutines and expects one success. Those two parts are what caught the deadlock. The MySQL, SQL Server and PostgreSQL backends start containers and are skipped with `-short`.
