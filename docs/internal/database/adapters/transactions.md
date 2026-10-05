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

`[Convention]` Pass the inner error on. Code that swallows it behaves differently per adapter, and on Postgres the transaction is unusable anyway (see below). The decision to keep the difference, and the alternatives, are recorded under [Nested transactions keep each library's behaviour](#nested-transactions-keep-each-librarys-behaviour).

---

# **Limits to know**

- **Postgres aborts the transaction on any failed statement.** Every later statement in it fails with "current transaction is aborted", and the commit turns into a rollback. A caller can't attempt an insert, classify a duplicate-key error and continue inside a transaction. The rate limiter's counter store stays outside transactions for this reason (see [`../../ratelimit/rate_limiter.md`](../../ratelimit/rate_limiter.md)). The plain adapters have no savepoint API to work around it.
- **MongoDB may run `fn` more than once.** `session.WithTransaction` retries the callback on a transient transaction error. Writes made with the callback's context are rolled back between attempts. Any other effect of `fn` repeats.
- **MongoDB transactions need a replica set or a sharded cluster.** On a standalone server `Transaction` fails. `MongoAdapter.CheckTransactions` detects this and `Boot` calls it, see the decision below.
- **SQLite has one writer.** While a transaction holds the write lock, a write through the root adapter waits for `busy_timeout` and then fails.
- **The `tx` adapter must not outlive `fn`.** On the SQL adapters it returns `sql.ErrTxDone`. On MongoDB it is the root adapter, so a late call succeeds outside any transaction.

---

# **Tests**

`tests/storage/database_suite.go` runs against every adapter. `TestNestedTransaction` calls `Transaction` on the adapter a transaction hands out and checks three cases: both writes commit together, an outer failure after the inner call undoes the inner write, and an inner error passed on undoes both. It also checks that the inner call can read the outer transaction's uncommitted row.

### The MongoDB adapter requires a replica set
**Context:** The store runs every write to a table that fires data hooks in a transaction (`Store.hooked`). A standalone MongoDB server has no transactions, so `CreateUser` and `UpdateUser` failed there, on the first sign-up and with the driver's own error message.
**Options considered:**
- *Require a replica set or sharded cluster.* Data hooks keep one contract on every database: an after-hook error rolls the write back, and a hook's writes through `HookContext.Tx` are atomic with the row. Standalone MongoDB is not supported. A single-node replica set covers local development.
- *Let an adapter report that it has no transactions and have the store run hooked writes without one.* Standalone MongoDB works. An after-hook error can no longer undo the write, a hook's own writes stay behind when the main write fails, and sign-up can leave a user without a credential account. What a data hook may rely on would then depend on how the application's database is deployed.
**Decision:** Require it, and check it at boot. `behemoth.TransactionChecker` is an optional interface of a `Database`. `Boot` calls `CheckTransactions` before anything is written and fails when it returns an error. `MongoAdapter` implements it with the `hello` command: a replica set member reports `setName`, a `mongos` reports `msg: "isdbgrid"`, and anything else is a standalone server and a configuration error that says how to fix it. The SQL adapters don't implement the interface. The check runs only in `Boot`; code that uses the adapter without `Boot` still gets the driver's error from `Transaction`.
**Revisit if:** standalone MongoDB has to be supported in production. The second option would then be an explicit opt-in on the adapter, not automatic.

### Nested transactions keep each library's behaviour
**Context:** Hook handlers get the transaction-bound adapter (`HookContext.Tx.DB()`) and may call `Transaction` on it. The plain SQL adapters and MongoDB join the open transaction. GORM and bun set a savepoint and roll back to it when the inner function fails. The results are the same when the inner error is passed on. They differ when the caller swallows it:

```go
err := hctx.Tx.DB().Transaction(hctx.Ctx, func(ctx context.Context, db behemoth.Database) (any, error) {
	if err := db.Create(ctx, &Profile{UserID: id}); err != nil { // succeeds
		return nil, err
	}
	return nil, errors.New("second step failed")
})
if err != nil {
	// swallowed: the handler returns nil and the outer write commits
}
```

| Adapter | The profile row after the outer commit |
| --- | --- |
| Postgres, MySQL, SQLite, SQL Server, MongoDB | stored: it was written in the outer transaction and nothing undid it |
| GORM, bun | not stored: the savepoint rollback removed it |

On Postgres through the plain adapter there is a third outcome when the inner failure was a failed statement: the whole transaction is aborted and the outer commit fails.

**Options considered:**
- *1. Keep the difference and document "pass the inner error on".* No code. Code that follows the rule behaves the same on every adapter, and `Store.Transaction` always joins, so everything that goes through the store is already uniform. A plugin that swallows the error leaves different data depending on the application's adapter.
- *2. Make GORM and bun join.* On an adapter that is already bound to a transaction, `Transaction` calls `fn(ctx, adapter)` and starts nothing, as the SQL adapters do. All adapters then behave the same, and the change is small:
  - bun: the adapter holds a `bun.IDB`. When it is a `bun.Tx`, call `fn(ctx, ba)` instead of `RunInTx`.
  - GORM: `*gorm.DB` does not say whether it is inside a transaction through its type. `Transaction` would mark the adapter it hands to `fn` (a field on `GormAdapter`), and an adapter built from a `*gorm.DB` the application put in a transaction itself would be recognised by its connection pool (`db.Statement.ConnPool` implementing `gorm.TxCommitter`).
  
  The cost is that partial rollback is no longer available through these two adapters. Behemoth does not use it. An application that relies on GORM's or bun's savepoints inside a Behemoth callback would lose them.
- *3. Add savepoints to the plain SQL adapters.* Every SQL adapter would support partial rollback, and rolling back to a savepoint also clears Postgres's aborted state, so a handler could survive a failed statement. Each dialect needs its own syntax (`SAVEPOINT` / `ROLLBACK TO SAVEPOINT`, `SAVE TRANSACTION` on SQL Server) and unique savepoint names for deeper nesting. MongoDB has no savepoints, so the adapters would still not be uniform.

**Decision:** Option 1. The rule is what correct code does anyway, and nothing in Behemoth swallows an inner transaction error. The API docs state the rule where handlers are told about `Tx.DB()`, and the GORM and bun `Transaction` methods carry a comment about the difference.
**Revisit if:** a plugin bug is traced to the difference, or uniform behaviour across adapters becomes a stated guarantee. Option 2 is then the recommended fix: it is the smaller change and gives one behaviour on every adapter, MongoDB included. Option 3 is worth its cost only if handlers need to recover from a failed statement on Postgres.
