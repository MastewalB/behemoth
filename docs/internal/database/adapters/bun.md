## **Bun Adapter on SQL Server**

This document covers two things `BunAdapter` (`storage/adapters/bun/bun.go`) does because of how Bun builds SQL for SQL Server. What the adapter does on MySQL is in [`mysql.md`](mysql.md), and how it picks the row of `UpdateOne` and `DeleteOne` is in [`single_row_writes.md`](single_row_writes.md).

The adapter never hands Bun a struct. Rows go in as a `map[string]any` and conditions as `?` arguments, and rows come out through `sql.Rows`, scanned by position. Both faults below come from that: Bun's SQL Server support is written around struct models, and the map and raw-row paths miss two of its rules.

Before these fixes `bun/sqlserver` failed five of the six parts of the store contract.

### A limited read returns one column more than was asked for

SQL Server only limits an ordered result (`ORDER BY ... OFFSET 0 ROWS FETCH NEXT n ROWS ONLY`). For a `SELECT` with a limit and no order, Bun's SQL Server dialect makes up an order: it selects a constant first and orders by it.

```sql
SELECT 0 AS _temp_sort, "id", "email", ... FROM "users" WHERE ...
ORDER BY _temp_sort OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY
```

`scan` allocated one target per column it had asked for, so `rows.Scan` failed with "sql: expected 17 destination arguments in Scan, not 16". `FindOne` always sets a limit of one, so every `FindOne` failed. `FindMany` with a limit and no order had the same fault.

### `scan` discards Bun's sort column
**Context:** The extra column above.
**Options considered:**
- *Read the result's column list in `scan` and drop a leading `_temp_sort`.* Every read goes through `scan`, so one change covers `FindOne` and `FindMany`, with or without `DISTINCT`. It depends on a name that is internal to Bun.
- *Give every limited read an order, so Bun adds nothing.* The adapter then chooses an order the caller did not ask for. `ORDER BY (SELECT NULL)` avoids a real sort but has to be checked against `SELECT DISTINCT`, where SQL Server requires order expressions to be in the select list.
- *Drop the limit on SQL Server and read only the first row.* The server still prepares the whole result.
**Decision:** The first. `scan` compares `rows.Columns()` with the columns it asked for, and when there is exactly one more and the first is `_temp_sort` (`sortColumn`), it scans that value into a discarded target. The check runs only when the dialect is SQL Server (`BunAdapter.mssql`).
**Revisit if:** Bun renames the column or stops adding it. The name check then no longer matches, `rows.Scan` fails with the destination-count error again, and the contract test shows it on the first read.

### A `false` value was sent as `FALSE`

SQL Server has no boolean literals. A `BIT` column takes 0 and 1, and `FALSE` in a statement is read as a column name: "mssql: Invalid column name 'FALSE'".

Bun's SQL Server dialect knows this. Its `AppendBool` writes 0 and 1. That method is used for struct fields, which Bun formats through reflection (`schema.AppendBoolValue`). A value passed as an `any` goes through `schema.QueryGen.Append`, whose type switch has a shortcut for a plain `bool` that calls the package-level `dialect.AppendBool` and writes `TRUE` or `FALSE` whatever the dialect is. Everything the adapter passes takes that shortcut:

| Path | Where the value enters Bun |
| --- | --- |
| insert | a map model, `NewInsert().Model(&row)` |
| update | `Set("? = ?", column, value)` |
| condition | `Where(query, args...)` |

### Bools are wrapped in a type that asks the dialect
**Context:** The shortcut above.
**Options considered:**
- *Wrap each `bool` in a type that implements Bun's `schema.QueryAppender` and calls `gen.Dialect().AppendBool`.* `dialectBool` does this. It uses the dialect's own rule, so the adapter does not need to know which databases want what. Only the SQL Server dialect overrides `AppendBool`; SQLite, PostgreSQL and MySQL write `TRUE` and `FALSE` either way, so nothing changes for them.
- *Convert a `bool` to 0 or 1 when the dialect is SQL Server.* Simple, but it adds a second dialect branch and repeats a rule the dialect already has.
- *Wait for a fix in Bun.* The shortcut looks like an oversight there. Until one is released the adapter cannot insert a `false` on SQL Server.
**Decision:** The first. `arg` wraps a plain `bool` and returns every other value unchanged. It is applied in the three helpers that feed the paths above: `row`, `set` and `whereClause`. Values read back need nothing: the SQL Server driver returns a `BIT` as a Go `bool`.
**Revisit if:** Bun's `QueryGen.Append` starts using the dialect for `bool`. The wrapper is then redundant and can be removed.

`[Limit]` Only a plain `bool` is wrapped. A `*bool`, or a bool inside a slice passed as one argument, still takes Bun's shortcut. Behemoth's models produce neither; a list condition (`OpIn`) is expanded to one argument per value before it reaches Bun.

### The subquery in `oneRow` does not deadlock here

`oneRow` picks the row of `UpdateOne` and `DeleteOne` with a subquery on every database except MySQL. On the plain SQL Server adapter a subquery deadlocked under concurrent rate limit hits. With Bun it did not, in any of the runs below, and neither did GORM. Their statement differs from the plain adapter's old one (`pk IN (SELECT pk FROM (...) AS _sub)` against `pk = (SELECT TOP 1 ...)`), which may change the locks SQL Server takes. The reason has not been traced; see `docs/ongoing.md`.

### Tests

- `TestStoreContract/bun/sqlserver` (`tests/store/contract_test.go`) runs the store contract on Bun with SQL Server. It passed 11 runs of that backend alone and 7 runs of the whole contract, without a deadlock error.
- The users part of the contract counts and reads users with a condition on a bool (`email_verified = false`) and a limit without an order. It runs on every backend. Without the wrapping in `whereClause` it fails on `bun/sqlserver` with "Invalid column name 'FALSE'".
- `TestBunAdapter` (`tests/storage/database_suite_test.go`) runs the adapter suite on SQLite only.

The SQL Server backends start a container and are skipped with `-short`.
