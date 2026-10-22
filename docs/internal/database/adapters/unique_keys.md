# Duplicate keys: which key a write broke

This document explains how an adapter tells which unique key a failed write broke, and how the store turns a duplicate value of a column declared unique into that column's conflict. Before this, a duplicate key error named the table and nothing else. A taken email and a taken username were the same `409` with the code `users_already_exists`, so a flow could answer neither with its own code when a concurrent write took the value after the flow's check.

The code lives in:

- `errs/adapters.go`: `NewDuplicateKeyOn`, `DuplicateKeyColumns`, `NewTaken`, and `IsDuplicateKey`, which looks through the chain
- `storage.go`: `UniqueKeyResolver` and `UniqueKey`
- `migration/migration.go`: `DefaultSchemaResolver.UniqueKeys`, built from the registry in `BuildSchemaResolverTable`
- `schema/schema.go`: `Column.ConflictCode`
- `storage/adapters/unique.go`: `KeyFinder`, `UniqueViolation`, `UniqueKeyName`, `CatalogQuery`, `CatalogOn`
- each adapter's error mapping: `mapErrors` (PostgreSQL, MySQL, SQLite, MongoDB), `mapError` (SQL Server, Bun), and `GormAdapter.err`
- `store/create.go`: `Store.taken`

## Two steps

1. **The adapter names the key's columns.** A duplicate key error carries `Columns`: the canonical names of the columns of the key, in the key's order, or nil when the adapter can't tell.
2. **The store answers a column declared unique with its code.** When the columns are one column that the schema declares unique, `Store.create` and `Store.update` return `errs.NewTaken`. That error is a conflict (409) with the column's code, `<column>_taken` unless the column's `ConflictCode` says otherwise. The duplicate key error stays in the chain as its `Original`.

Every write through the store gets the column's code: a sign-up, `SetUsername`, `UpdateUser`, another plugin's write. No flow needs to know the unique columns other plugins contribute.

## How each adapter names the key

A unique violation names the key in one of two forms, depending on the engine:

| Engine | What the error carries | Read from |
| --- | --- | --- |
| SQLite | the physical columns: `UNIQUE constraint failed: users.email` | the message, which SQLite does not translate |
| PostgreSQL | the constraint's name (SQLSTATE `23505`) | the error's constraint field: `Get('n')` on lib/pq, `Field('n')` on bun's pgdriver, the `ConstraintName` field on pgx. The message is not read: the server may translate it. |
| MySQL | the key's name: `Duplicate entry '...' for key 'users.users_email_key'` | the message. MySQL 8.0.19 and later put the table before the name. |
| SQL Server | the index's or constraint's name: `... with unique index 'users_email_key'`, `Violation of UNIQUE KEY constraint '...'` | the message |
| MongoDB | the index's key pattern, `{email: 1}`, physical field names | the write error's or the command error's raw document (`keyPattern`). Without it, the index's name in the message, matched against the names `DeclaredIndexes` gives. |

`UniqueViolation` reads the first four. It knows no driver's type, so the GORM and Bun adapters use it whatever driver the application chose. The MongoDB adapter reads its errors itself (`keyColumns`).

Physical columns are mapped back to canonical names through the resolver (`CanonicalColumns`). A name goes through two steps:

1. **The declared keys.** The resolver lists each table's unique keys (`UniqueKeys`). A unique index is matched by its declared name. A column declared unique is matched by the name the migration drivers give its key, `<table>_<column>_key` from physical names (`UniqueKeyName`). PostgreSQL cuts the name to 63 bytes, and MySQL (64) and SQL Server (128) end a name over their limit with a hash of the full name. The MySQL and SQL Server drivers name their keys with `UniqueKeyName`, so the two can't drift apart. The PostgreSQL driver passes the full name and lets the server cut it.
2. **The catalog.** A name that matches no declared key belongs to a key the application or the database named, such as the primary key or a table created by hand. `CatalogQuery` reads its columns from `pg_index`, `information_schema.STATISTICS`, or `sys.index_columns`. The lookup runs only on such an error, so nothing is cached.

When neither step explains the name, `Columns` stays nil and the error is the duplicate key error it was before.

## Where the catalog lookup runs

PostgreSQL aborts a transaction on any failed statement, so a lookup in the transaction of the failed write fails too. The PostgreSQL, GORM and Bun adapters keep the database a transaction was begun on (`pool`) and run the lookup there. MySQL and SQL Server leave the transaction usable after a duplicate key (SQL Server with `XACT_ABORT` off, its default), and run it on the adapter's own connection. An adapter built over a transaction the application began has no pool. A PostgreSQL lookup then fails, and the error names no columns.

The mapping functions have no context, so the lookup gets its own, with a timeout of five seconds (`catalogTimeout`).

## GORM

The GORM adapter applies the dialect's `ErrorTranslator`, which replaces the driver's error with `gorm.ErrDuplicatedKey`. The adapter keeps the driver's error to read the key from, and joins the two in the duplicate key error's `Original`.

## What the store's conflict keeps

`errs.NewTaken` is a conflict, so `errs.IsRejection` holds for it. A flow's failed point fires for it as it does for a hook's veto (`FailIfRejected`, with `rejected_by_hook`). `errs.IsDuplicateKey` looks through the chain and holds too, so code that branched on a duplicate key before still does: the email change flow, the phone number plugin, and the OAuth sign-up, which resolves the user again after it loses a race. `errs.IsCategory(err, errs.CategoryDuplicateKey)` does not hold for the conflict; use `IsDuplicateKey`.

The email/password sign-up answers a taken email itself: when the insert's duplicate key names `email`, it fires `auth.signUp.failed` with `user_exists` and returns `email_taken`, as when its lookup finds the user.

A unique index, a primary key, and a key the adapter could not name stay duplicate key errors, with the table's code (`users_already_exists`).

## Limits to know

- **A message can change.** SQLite's, MySQL's and SQL Server's errors are read from their text. A server that translates its messages (MySQL's `lc_messages`, SQL Server's `SET LANGUAGE`) can make the name unreadable, and the error then names no columns.
- **A direct write gets no conflict.** A plugin that writes through the adapter gets the duplicate key error with its columns, not the column's code.
- **The public message is generic:** "username is already taken". A flow that wants its own message checks first, as the username plugin does, and the store's answer covers the race.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestUniqueViolation` | `storage/adapters/unique_test.go` | each engine's error, the three PostgreSQL drivers' ways, MySQL with and without the table, a value that looks like a key |
| `TestUniqueKeyName` | same | the names, PostgreSQL's cut, the hash of a long name |
| `TestKeyFinder` | same | physical columns, a declared column and index by name, physical names, the catalog asked with the physical table and the name, no catalog, a failed lookup |
| `TestCatalogQuery` | same | each dialect's query takes two arguments in the given placeholders |
| `TestDuplicateKeyColumns` | `errs/duplicate_key_test.go` | the columns through the store's conflict, a wrapping and a join; `IsDuplicateKey` through them |
| `TestStoreContract/*/UniqueKeys` | `tests/store/contract_test.go` | on every backend: a core column and a contributed one under another physical name with its own code, on create and update; a unique index's columns in order; the primary key from the catalog, in a transaction |
| `TestSignUpThatLosesTheRaceForAnEmail` | `tests/plugins/signup_race_test.go` | a sign-up that loses the race for an email gets `email_taken` and `auth.signUp.failed` |
| `TestSignUpThatLosesTheRaceForAUsername`, `TestSetUsernameThatLosesTheRace` | same | the loser of a race for a username gets `username_taken` |

## Design decisions

### The adapter names the columns, the schema gives the code

**Context:** A flow checks a value before it writes, and a concurrent write can take the value in between. The database then refuses the write, and the error has to tell the flow which value was taken. The email/password sign-up can't know the unique columns other plugins add to `users`.

**Options considered:**

- *Map every duplicate key of the sign-up to `email_taken`.* Wrong as soon as a plugin adds another unique column, such as the username.
- *Have each flow map the columns it knows.* The sign-up would still answer a taken username with the store's code.
- *Name the columns in the error, and let the schema say what a duplicate value of a column means.* The adapter knows its engine, and the column's declaration knows its code. The store, which every write goes through, joins the two.

**Decision:** The third. The code is derived as `<column>_taken`, which the three existing codes already followed (`email_taken`, `username_taken`, `phone_number_taken`), with `ConflictCode` to set another.

**Revisit if:** a unique column needs a message of its own in the store's answer, not only a code.

### Names are matched first, the catalog second

**Context:** PostgreSQL, MySQL and SQL Server name the key, not its columns.

**Options considered:**

- *Read the columns from the message* (PostgreSQL's detail, `Key (email)=(...)`). PostgreSQL translates it.
- *Always ask the catalog.* Right for any table, at the cost of a query on every duplicate key.
- *Match the names the drivers give, and ask the catalog for the rest.* No query for a key Behemoth declared.

**Decision:** The third. Every key a Behemoth migration created matches by name. A table the application created, or a primary key, costs one query.

**Revisit if:** applications commonly adopt tables they created themselves, where every duplicate key would cost a query. The lookups could then be cached per table and name.

### The conflict keeps the duplicate key in its chain

**Context:** Plugins branch on `errs.IsDuplicateKey` for a taken email, and the OAuth sign-up retries on it.

**Decision:** `NewTaken` keeps the duplicate key error as its `Original`, and `IsDuplicateKey` looks through the chain. The conflict is the category a client and `IsRejection` see, and the duplicate key is still there for code that asks.
