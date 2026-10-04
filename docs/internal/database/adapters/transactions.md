## **Adapter Transactions**

This document explains how each database adapter runs a transaction, what the adapter handed to the transaction callback is bound to, and what happens when `Transaction` is called on an adapter that is already inside one. The last part matters because the store hands its transaction-bound adapter to hook handlers (`Store.DB()`, see [`../../models/models.md`](../../models/models.md)), and a handler may call `Transaction` on it.

The code lives in `storage/adapters/<name>/`, one `Transaction` method per adapter. The contract is `behemoth.Database` in `storage.go`:

```go
Transaction(ctx context.Context, fn TransactionFunc) error

type TransactionFunc func(ctx context.Context, tx Database) (any, error)
```

`fn` receives a context and an adapter. Operations made with both are part of the transaction. If `fn` returns an error the transaction rolls back and the error is returned as-is; otherwise it commits.

---

# **Where the transaction lives**

The adapters differ in what carries the transaction. Code that uses both the `tx` adapter and the `ctx` it was given is correct on all of them.

| Adapter | The transaction is carried by | The `tx` adapter is |
| --- | --- | --- |
| Postgres, MySQL, SQLite, SQL Server | the adapter: its `DB` field holds a `*sql.Tx` | a new adapter around the `*sql.Tx` |
| GORM | the adapter: it wraps the transaction's `*gorm.DB` | a new adapter around it |
| bun | the adapter: it wraps a `bun.Tx` | a new adapter around it |
| MongoDB | the context: a `mongo.SessionContext` | the same adapter (`mdb`) |

Consequences:

- **SQL adapters.** A call on the `tx` adapter is in the transaction whatever context it is given. A call on the root adapter is outside it. After the transaction ends the `tx` adapter is dead: `database/sql` returns `sql.ErrTxDone`.
- **MongoDB.** A call is in the transaction only when it is made with the callback's context. The `tx` adapter and the root adapter are the same value, so the adapter alone says nothing. A call with another context is written immediately and is not rolled back.

---

# **`Transaction` on a bound adapter**

`[Decision]` Calling `Transaction` on an adapter that is already inside a transaction runs `fn` in that same transaction. This is the same rule `Store.Transaction` follows for a bound store.

| Adapter | How it detects the open transaction | What the inner call does |
| --- | --- | --- |
| Postgres, MySQL, SQLite, SQL Server | `DB` is a `*sql.Tx` | calls `fn(ctx, adapter)` with itself; begins, commits and rolls back nothing |
| MongoDB | `mongo.SessionFromContext(ctx)` is not nil | calls `fn(ctx, mdb)` with the same context; starts no session |
| GORM | GORM's own nesting | sets a savepoint, rolls back to it if `fn` fails |
| bun | `RunInTx` on a `bun.Tx` | sets a savepoint, rolls back to it if `fn` fails |

The SQL adapters' `Transaction` begins with a type switch on `DB`:

```go
switch q := pg.DB.(type) {
case *sql.DB:
	db = q            // root adapter: begin a transaction, as before
case *sql.Tx:
	_, err := fn(ctx, pg) // bound adapter: join
	return err
default:
	return behemotherr.NewTransactionError(...) // some other Querier
}
```

- **The root path is unchanged.** An adapter built on a `*sql.DB` begins, runs `fn`, and commits or rolls back exactly as before. The panic handler that rolls back and re-panics still wraps it.
- **A panic inside a joined `fn`** is not caught by the inner call. It unwinds to the outer `Transaction`, whose handler rolls back.
- **Another `Querier`** (a `*sql.Conn`, a wrapper) is a transaction error. Before, it was a failed type assertion and a panic.

### **What changed, and why it was needed**

Before, `Transaction` on a bound SQL adapter panicked: it asserted `DB.(*sql.DB)` on a `*sql.Tx`. On MongoDB it started a second, independent session and transaction: the inner writes committed on their own and stayed when the outer transaction aborted. Neither was reachable from Behemoth's own code, because `Store.Transaction` never calls the adapter's `Transaction` on a bound store. Handing the bound adapter to hook handlers made both reachable.

### **Joining versus savepoints**

The four SQL adapters and MongoDB join. GORM and bun nest with a savepoint, which is their libraries' behaviour and was left as it is. The two agree whenever the inner error is passed on:

| The caller of the inner `Transaction` | Join (SQL, MongoDB) | Savepoint (GORM, bun) |
| --- | --- | --- |
| returns the inner error | everything rolls back | everything rolls back |
| swallows the inner error and continues | the inner writes made before the error stay in the transaction | the inner writes are undone, the outer ones stay |

`[Convention]` Pass the inner error on. Code that swallows it behaves differently per adapter, and on Postgres the transaction is unusable anyway (see below).

---

# **Limits to know**

- **Postgres aborts the transaction on any failed statement.** Every later statement in it fails with "current transaction is aborted", and the commit turns into a rollback. A caller can't attempt an insert, classify a duplicate-key error and continue inside a transaction. The rate limiter's counter store stays outside transactions for this reason (see [`../../ratelimit/rate_limiter.md`](../../ratelimit/rate_limiter.md)). The plain adapters have no savepoint API to work around it.
- **MongoDB may run `fn` more than once.** `session.WithTransaction` retries the callback on a transient transaction error. Writes made with the callback's context are rolled back between attempts. Any other effect of `fn` repeats.
- **MongoDB transactions need a replica set or a sharded cluster.** On a standalone server `Transaction` fails.
- **SQLite has one writer.** While a transaction holds the write lock, a write through the root adapter waits for `busy_timeout` and then fails.
- **The `tx` adapter must not outlive `fn`.** On the SQL adapters it returns `sql.ErrTxDone`. On MongoDB it is the root adapter, so a late call succeeds outside any transaction.

---

# **Tests**

`tests/storage/database_suite.go` runs against every adapter. `TestNestedTransaction` calls `Transaction` on the adapter a transaction hands out and checks three cases: both writes commit together, an outer failure after the inner call undoes the inner write, and an inner error passed on undoes both. It also checks that the inner call can read the outer transaction's uncommitted row.
