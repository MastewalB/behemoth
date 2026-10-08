## **MongoDB Adapter: Indexes**

This document explains how a MongoDB database gets the indexes a schema declares: which indexes the adapter derives from a table, what `EnsureIndexes` does in each state it can find a collection in, what `Boot` checks, and why it is built this way and not as a migration driver. The last part describes how that driver can be written later and what changes when it is.

The code is in `storage/adapters/mongo/indexes.go`. Decoding of stored values is covered in [`mongo.md`](mongo.md), transactions in [`transactions.md`](transactions.md).

### Why MongoDB needs this

On the SQL databases a migration driver creates each table with its primary key, its unique constraints and its indexes. An application that never ran its migrations finds out on the first query: the table does not exist.

MongoDB has no migration driver, and it has no "missing table" either. A collection is created by the first insert, without any index except the one on `_id`. Everything keeps working, and what the missing indexes were meant to refuse is stored:

| Declared | Relied on by | Without the index |
| --- | --- | --- |
| `users.email` unique | sign-up looks the email up and then inserts; the index decides between two sign-ups at the same moment | both users are created |
| primary keys | every lookup by id | a scan of the collection. The adapter stores a model's id in a field named `id`, not in `_id`, so MongoDB's built-in index does not cover it |
| `rate_limits.key` primary key | `Store.IncrementRateLimit` treats a duplicate-key error as "another call created the row first" | two rows for one key, and the count is split between them |
| `accounts(provider_id, account_id)` unique | linking an OAuth account | the same provider account is linked twice |
| the plain indexes on `sessions`, `tokens`, `audit_log` | lookups by user, by kind and subject, audit queries | a scan of the collection |

The adapter did map MongoDB's duplicate-key error (`E11000`) to Behemoth's duplicate error, but that error can only come from a unique index, and nothing created one.

### The three functions

| Function | Reads the database | Writes the database | Called by |
| --- | --- | --- | --- |
| `DeclaredIndexes(tables)` | no | no | the other two; an application that wants to see the list |
| `EnsureIndexes(ctx, tables)` | lists indexes | creates the missing ones | the application, before `Boot` |
| `CheckIndexes(ctx, tables)` | lists indexes | no | `Boot` |

The order in an application:

```go
app, err := bmth.Prepare(plugins, prepareCfg)
db := mongoAdapter.NewMongoAdapter(client, "auth", app.Resolver)

// From a deploy step, or at startup. Safe to repeat.
if err := db.EnsureIndexes(ctx, app.Schemas.All()); err != nil {
	return err
}
ac, err := bmth.Boot(ctx, app, db, bootCfg) // calls db.CheckIndexes
```

`app.Schemas.All()` is every declared table with the contributions of other declarers merged in, so an index a plugin adds with `ExtendIndex` and a unique column it adds with `ExtendColumn` are covered without the application listing them.

### From a table to its indexes

`DeclaredIndexes` turns each `schema.Table` into a list of `IndexSpec`, in this order:

| Declared as | Index | Created under the name |
| --- | --- | --- |
| the columns with `PrimaryKey` | one unique index on them | `pk_<table>` |
| a column with `Unique` | a unique index on it | `uq_<table>_<column>` |
| an entry of `Table.Indexes` | that index, unique if it says so | the entry's own name |

For core's `users` and `tokens` that gives:

| Collection | Name | Fields | Unique |
| --- | --- | --- | --- |
| `users` | `pk_users` | `id` | yes |
| `users` | `uq_users_email` | `email` | yes |
| `tokens` | `pk_tokens` | `id` | yes |
| `tokens` | `uq_tokens_kind_lookup_hash` | `kind`, `lookup_hash` | yes |
| `tokens` | `idx_tokens_kind_subject` | `kind`, `subject` | no |

Rules:

- **Names are physical.** Collection and field names go through the adapter's own `Resolver`, the one its reads and writes use, so an index always lands on the field the adapter writes. `Table.PhysicalName` is not read directly. The index names use the canonical table and column names.
- **One index per field list.** Two declarations over the same fields in the same order become one index, unique if either is. A plain index on `email` next to a `Unique` column `email` adds nothing, because the unique index serves the same lookups. A partial index (next section) is the exception: it is kept apart from a full index on the same fields.
- **`_id` needs nothing.** A unique index on `_id` alone is left out. MongoDB always has it.
- **What has no counterpart is ignored.** Foreign keys, column types, lengths, defaults and auto-increment produce nothing. See *Limits to know* for what that means for deletes.

#### Nullable unique columns get a partial index

On the SQL databases a unique index does not compare `NULL` with `NULL`: any number of rows may have no value (SQL Server is the exception, and its driver uses a filtered index to get the same result). A plain unique index on MongoDB treats null and a missing field as one value, so a second document without a value is refused.

To keep the SQL meaning, a unique index over a nullable column is created as a partial index that only covers documents where the column has a value:

```js
{ nickname: 1 }, {
  unique: true,
  partialFilterExpression: {
    nickname: { $type: ["number", "string", "object", "array", "binData", "objectId", "bool", "date", "timestamp"] }
  }
}
```

The type list is every BSON type the adapter can produce from a model's Go value, and not null. A partial filter can't say "not null" directly (`$ne` and `$not` are not allowed in one). For an index over several columns, each nullable column gets its own condition, so a document is left out when any of them has no value. That is the SQL rule for a multi-column unique index too.

`IndexSpec.NullableFields` lists the affected fields. Core's unique columns are all non-nullable, so this only concerns contributed columns and plugin tables.

A sparse index was not used: it skips documents that lack the field, but a field stored as null is still indexed, and the adapter stores a nil value as null.

MongoDB does not read through this partial index. A query uses a partial index only when it can prove that every match is inside the filter, and it does not prove that for a `$type` filter: `find({nickname: "ada"})` scans the collection with only the partial index present (probed). So each partial unique index is followed by a plain index on the same fields, named `<name>_lookup`:

| Index | Does | Missing means |
| --- | --- | --- |
| `uq_members_nickname`, unique, partial | refuses a second document with the same nickname | duplicates are stored; `Boot` fails |
| `uq_members_nickname_lookup`, plain | serves lookups by nickname | lookups scan; `Boot` warns |

On the SQL databases one unique index does both jobs. A nullable unique column therefore costs two indexes on MongoDB.

### When a live index counts as the declared one

`liveIndex.satisfies` decides whether an index the collection already has does the declared job. The name is not compared.

| The live index has | Counts? | Why |
| --- | --- | --- |
| the same fields in the same order, ascending, and the same uniqueness | yes | it is the declared index, whatever its name |
| the same fields and is unique, where a plain index is declared | yes | it serves the same lookups |
| the same fields and is plain, where a unique one is declared | no | it refuses nothing |
| the fields in another order, or fewer or more fields | no | another index |
| a descending, hashed or text key | no | not compared; kept simple |
| `sparse`, or a collation | no | it covers other documents, or compares values another way |
| a partial filter other than the declared one (including none where one is declared, and the reverse) | no | it covers other documents |
| `expireAfterSeconds` (a TTL index) | yes | not looked at. A TTL index on `expires_at` still serves lookups by it |

The partial filter is compared as bytes: the declared filter is marshalled to BSON and compared with what `listIndexes` returns. MongoDB returns the filter as it was given, so an index `EnsureIndexes` created is recognized on the next run. A filter written another way by hand, even with the same meaning, does not match, and the declared index is created next to it.

### What `EnsureIndexes` does, case by case

`EnsureIndexes` lists the indexes of each collection once, skips every declared index that a live one satisfies, and creates the rest one by one. The middle column is what MongoDB does on its own when asked to create the index, as probed (see *Probe table*).

| # | State of the collection | MongoDB on its own | `EnsureIndexes` |
| --- | --- | --- | --- |
| 1 | The collection does not exist | creates the collection with the index | creates the index. `listIndexes` on a missing collection counts as "no indexes" |
| 2 | The collection exists, the index does not | builds it | creates it |
| 3 | The same index exists: name, fields, options | accepts the request and does nothing | does not ask. Nothing changes |
| 4 | An equivalent index exists under another name (made by hand, `email_1`) | refuses: code 85, `IndexOptionsConflict` | does not ask. The hand-made index counts, and no second one is created |
| 5 | A unique index exists on the fields of a declared plain index | (not asked) | does not ask. The unique index counts |
| 6 | A plain index exists on the fields of a declared unique one | builds the unique index next to it | creates the unique index. The plain one stays |
| 7 | A descending, sparse, collated or differently filtered index exists on the same fields | builds the declared one next to it | creates the declared index. The other one stays |
| 8 | The declared name is taken by an index with other fields or options | refuses: code 86, `IndexKeySpecsConflict` | reports it, naming the index in the way. Goes on with the other indexes |
| 9 | The documents already hold duplicates of a unique index's fields | the build fails: code 11000 | reports it, naming the collection and fields. No document is removed. Goes on with the other indexes |
| 10 | The primary key is physically `_id` | (always indexed) | nothing to do |
| 11 | The context carries a transaction | accepts it on a new collection (probed); documented as refused on a collection that holds documents | returns a configuration error before doing anything |

Cases 4 and 6 are the reason for comparing before creating. Left to MongoDB, a deploy would fail in case 4 although the rule is already enforced.

What it does not do:

| Situation | Result | Who handles it |
| --- | --- | --- |
| A table or index is no longer declared | its index stays in the database | by hand, until the driver exists |
| A declared index changed its columns and kept its name | case 8: reported as a conflict | drop the old index by hand, then run again |
| A column went from `Unique` to not unique | the unique index stays and still refuses duplicates | by hand |
| A unique column went from nullable to not nullable, or back | the old index keeps the name, so the new one, which differs in its partial filter, is reported as a conflict (case 8) | drop the old index by hand, then run again |
| A column was renamed physically | indexes on the old field stay; indexes on the new field are created | by hand; the documents keep the old field name too |
| Any other database | not called. It is a method of `MongoAdapter`, not of `behemoth.Database` | the SQL migration drivers |

Errors:

- A failure to list indexes (the server can't be reached) is returned at once, wrapped with the function's name.
- Failures to create an index are collected. The function tries every index and returns one `behemotherr` migration error (`CategoryMigration`, code `apply_failed`) that joins them, so a deploy log shows every collection that needs attention in one run.
- Each message says what the index is, where it was declared (`from unique column email`), what is in the way and what to do.

### `CheckIndexes` and `Boot`

`Boot` asks the adapter whether it implements `IndexChecker`:

```go
type IndexChecker interface {
	CheckIndexes(ctx context.Context, tables []schema.Table) (warnings []string, err error)
}
```

It is the same pattern as `behemoth.TransactionChecker`, which `Boot` uses to refuse a standalone MongoDB server. The interface is declared in `types/init` and not in the root package, because it names `schema.Table` and `types/schema` imports the root package.

Order in `Boot`: the transaction check, then telemetry is resolved, then the index check, then everything else. Nothing has been written at that point.

`CheckIndexes` uses the same comparison as `EnsureIndexes` and creates nothing:

| A declared index is missing and it is | `CheckIndexes` | `Boot` |
| --- | --- | --- |
| unique | returns a configuration error that lists every missing unique index and names `EnsureIndexes` | fails: `database index check failed: ...` |
| not unique | returns one warning line for it | logs each at Warn under the `boot` component, with the line in the `index` field, and starts |

A hand-made index that satisfies a declared one passes, under any name. An index that has the declared name or fields but does not satisfy it is named in the message.

The SQL adapters do not implement the interface. For them the check is skipped and `Boot` is unchanged.

### Limits to know

- **Indexes are never dropped or changed.** See the table above. This is the main thing a migration driver adds.
- **Nothing records what ran.** There is no ledger. The database's own index list is the only state.
- **Building an index takes time.** On a large collection `EnsureIndexes` blocks until the build is done. That is why `Boot` does not call it.
- **`Boot` has no switch to skip the check.** An application that can't create a declared unique index (duplicates it has to clean up first) can't start on MongoDB until it has.
- **The check costs one `listIndexes` per collection at startup.**
- **A nullable unique column has two indexes**, one that enforces and one that serves reads. See *Nullable unique columns get a partial index*.
- **Field types are not checked.** A unique index compares BSON values: the string `"1"` and the number `1` are different values.
- **Probed on MongoDB 6.0 only.** Cases 6 and 7 depend on MongoDB accepting two indexes on the same fields with different options. A version that refuses them returns code 85, which `EnsureIndexes` reports as a conflict naming the existing index. Nothing is dropped in either case.
- **Concurrent calls were not probed.** Two instances calling `EnsureIndexes` at the same time ask for identical indexes, which MongoDB is expected to treat as one build.
- **Foreign keys do nothing.** A cascade declared with `OnDelete` does not happen on MongoDB. `Store.DeleteUser` does not depend on it: it deletes the user's sessions, accounts and tokens itself (see [`../../hooks/6. Data Hooks.md`](<../../hooks/6. Data Hooks.md>)). A plugin's own rows that reference a user are the plugin's to delete, from a handler on `data.user.beforeDelete`.

### Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestMongoIndexes/DeclaredIndexes` | `tests/storage/mongo_indexes_test.go` | the derived list: order, names, merging of equal field lists, `_id`, nullable fields and their lookup indexes, physical names |
| `TestMongoIndexes/EnsureIndexes` | `tests/storage/mongo_indexes_test.go` | cases 1 to 9 and 11 against a container, what the created indexes refuse and allow (null in a nullable unique column), and `CheckIndexes` before and after |
| `TestBootChecksMongoIndexes` | `tests/store/contract_test.go` | `Boot` fails without the unique indexes, starts after `EnsureIndexes`, warns about a plain index, fails again when a unique one is dropped |
| `TestStoreContract/mongo` | `tests/store/contract_test.go` | the whole store contract on MongoDB, with the indexes from `EnsureIndexes` |

All start a MongoDB container and are skipped with `-short`.

### Probe table

Observed on MongoDB 6.0.27 (a single-node replica set), following the "probe before encoding" rule of [`../../migrations/migration_design_decision.md`](../../migrations/migration_design_decision.md).

| Probe | Result |
| --- | --- |
| `listIndexes` on a collection that does not exist | error 26 `NamespaceNotFound` in the shell. Through the Go driver the adapter ends up with no indexes, whether the driver returns an empty list or that error (`liveIndexes` handles both) |
| create the same index twice (name, key, options) | accepted, nothing done |
| create the same key and options under another name | error 85 `IndexOptionsConflict` |
| create a plain index on the key of a unique one, another name | accepted; both exist |
| create a unique index on the key of a plain one, another name | accepted; both exist |
| create an index whose name is taken by another key | error 86 `IndexKeySpecsConflict` |
| create an index whose name is taken by the same key with other options | error 86 `IndexKeySpecsConflict` |
| unique partial index with `$type: [...]` | accepted; `listIndexes` returns the filter as given |
| a full unique index next to a partial one on the same key | accepted; both exist |
| two documents with null under the partial unique index | both stored |
| two documents with null under a full unique index | the second is refused, `E11000` |
| equality, `$in` and null queries on a field that only has the `$type` partial index | collection scan; the partial index is not used |
| a plain index next to a partial unique one on the same key | accepted; both exist |
| unique index over a collection with duplicates | error 11000; the index is not created |
| `createIndexes` inside a transaction | accepted on a new collection |

---

### Design decisions

### The adapter creates the indexes; there is no migration driver yet
**Context:** Nothing created MongoDB's indexes, and their absence was silent (see *Why MongoDB needs this*).
**Options considered:**
- *Document the indexes for the user to create by hand.* No code. A static list can't include the indexes plugins contribute or names changed through the resolver, and a user who misses one gets no signal.
- *An idempotent function on the adapter that creates them from the declared schema.* About 400 lines with its check and comments. It reads the same declarations the SQL drivers do, so contributed indexes are covered. It is a second path next to the migration engine: it never removes an index and keeps no record.
- *A migration driver and introspector for MongoDB.* Consistent with the SQL databases, with a ledger and the ability to drop and change indexes. It is several times larger, most of its operations (columns, foreign keys) have nothing to do on MongoDB, and it does not by itself make a missing index loud: an application that never runs its migrations still stores duplicates.

**Decision:** The function, `EnsureIndexes`, together with the check at `Boot` below. It closes the correctness gap with the least code, and the driver can be built on it later (see *The future migration driver*).
**Revisit if:** schemas on MongoDB start to change in ways that need an index dropped or replaced often enough that doing it by hand is a burden.

### `Boot` fails when a declared unique index is missing
**Context:** Creating the indexes is a step the application has to call. Forgetting it brings the silent failure back.
**Options considered:**
- *Do nothing more.* The docs say to call `EnsureIndexes`. A deployment that skips it stores duplicate users.
- *Create the indexes in `Boot`.* Nothing to forget. `Boot` would run schema changes, which it does on no other database, and an index build on a large collection would become a side effect of starting a server, on every instance at once.
- *Check in `Boot` and warn.* Visible in the logs of an application that reads them. Duplicates are still stored.
- *Check in `Boot` and fail on a missing unique index, warn on a missing plain one.* A missing table on SQL fails the first query; this gives MongoDB the same property at startup. A plain index only affects speed, so it does not stop the application.

**Decision:** Fail on unique, warn on plain. There is no option to turn the check off: the state it refuses is the one in which Behemoth stores wrong data.
**Revisit if:** an application has a legitimate reason to start without a declared unique index. An explicit `BootConfig` field would then be the place, not a silent default.

### Live indexes are compared by fields and options, not by name
**Context:** A MongoDB database often has indexes made by hand or by another tool, under MongoDB's generated names (`email_1`).
**Options considered:**
- *Create by name and let MongoDB answer.* The least code. MongoDB refuses an equivalent index under another name (code 85), so a database that already enforces the rule would fail the deploy.
- *Compare by name.* Simple to explain. A hand-made index is "missing", with the same result.
- *Compare by fields, order, uniqueness and partial filter.* A hand-made index counts. It needs the rules in *When a live index counts as the declared one*, and they have to be conservative: anything that changes which documents are covered does not count.

**Decision:** Compare by shape. `Boot`'s check uses the same comparison, so what `EnsureIndexes` accepts, `Boot` accepts.

### `EnsureIndexes` never drops an index
**Context:** An index can be in the way of a declared one (case 8), or left over from an earlier schema.
**Options considered:**
- *Drop what is in the way and create the declared index.* The deploy always converges. The function can't tell an index Behemoth created from one the application or a DBA made, and dropping a live index can remove a uniqueness rule or slow production queries.
- *Never drop; report and continue.* A human decides. A conflicting index needs a manual step.

**Decision:** Never drop. Without a record of which indexes Behemoth created there is no safe rule for dropping one. The migration driver's snapshot is that record.

### A nullable unique column gets a partial unique index and a plain one
**Context:** A unique index on MongoDB counts null and a missing field as a value, so only one document may lack one. The SQL databases allow any number of rows without a value.
**Options considered:**
- *A plain unique index.* One index. The second row without a value is refused, which breaks an optional unique column (a username that is not set yet) on MongoDB only.
- *A sparse unique index.* One index. It leaves out documents that lack the field, but the adapter writes a nil value as null, and null is indexed. The adapter would have to stop writing null fields, which changes what every read returns.
- *A partial unique index filtered with `$exists: true`.* Queries can use it. It includes null, so it has the first option's problem.
- *A partial unique index filtered on the non-null types, plus a plain index.* The SQL meaning is kept. Queries don't use the partial index (probed), so a second, plain index is needed for lookups.

**Decision:** The last one. Correct uniqueness is worth one more index, and only nullable unique columns pay for it; core has none.
**Revisit if:** MongoDB's planner starts using a `$type`-filtered partial index for equality matches. The plain index can then go.

### Failures are collected, not returned one at a time
**Context:** Several indexes can fail for unrelated reasons (duplicates in one collection, a taken name in another).
**Options considered:**
- *Stop at the first failure.* The usual shape. Each deploy attempt reveals one problem, and indexes after the failing one are not created although nothing is wrong with them.
- *Try every index and join the errors.* One run shows everything, and every index that can exist does.

**Decision:** Collect. The indexes are independent of each other, so there is nothing to protect by stopping.

### The primary key gets its own unique index
**Context:** The adapter writes a model's id to a field named `id`. MongoDB adds its own `_id` (an ObjectID) to every document, and only `_id` is indexed.
**Options considered:**
- *Store the id in `_id`.* One index less per collection, and MongoDB enforces uniqueness without help. Every existing document would have to be rewritten, and reads, filters and the resolver would need a special case for one field.
- *Create a unique index on the id field.* No change to stored data. One more index per collection.

**Decision:** The index. A resolver that maps the primary key to `_id` is respected: no index is created for it.
**Revisit if:** the adapter's document layout is reworked for another reason.

---

### The future migration driver

This section is for whoever writes `MongoDriver`. It says how the pieces above fit into the migration engine, what the engine needs from the driver, and what in today's code changes then.

#### What the engine asks of a driver

| Path | When | Needs from MongoDB |
| --- | --- | --- |
| Managed, later runs (`runOngoing`) | a ledger and snapshot exist | nothing read from the database: the plan is the difference between the snapshot and the declared schema (`RunIntrospectionFromSnapshotDiff`, chosen in `generator.go`). The driver applies operations and stores the ledger entry and the snapshot |
| Managed, first run on an empty database | no collection exists | `TableExists` answers false for every table; the first migration is all `create_table` |
| Managed, first run on a database with collections (baseline) | collections exist, no ledger | `Introspect` has to describe each existing collection as a table. This is the hard part, below |
| Generate only | the developer's own tool applies | `Introspect` on every run, and a `MigrationRenderer` that writes a `mongosh` script (`.js`). Can be left unsupported at first |

So the snapshot carries the driver on every run after the first. A document store can't report its fields, and on those runs nobody asks.

#### Operations

| Operation | On MongoDB |
| --- | --- |
| `create_table` | create the collection, then ensure the indexes `DeclaredIndexes` gives for the table's primary key and unique columns. Indexes in `Table.Indexes` arrive as their own `add_index` operations |
| `drop_table` | drop the collection |
| `add_index` | ensure one index: skip when a live index satisfies it, create otherwise. Not a bare `createIndexes`, or case 4 fails the migration |
| `drop_index` | drop by name, but only the index the snapshot recorded. See *Ownership* |
| `add_column` | nothing for the field. If the column is `Unique`, ensure its index |
| `alter_column` | nothing for type, length or default. A change of `Unique` creates or drops the column's index. A change of `Nullable` on a unique column replaces the index, because the partial filter changes |
| `rename_column` | `$rename` over every document, then replace every index that names the old field |
| `drop_column` | drop the indexes that name the field, then `$unset` over every document |
| `add_foreign_key`, `drop_foreign_key` | nothing. Say so in the rendered script |

`AtomicityLevel` is `AtomicityBestEffort`, as on MySQL: index builds and collection changes happen outside any transaction, and the ledger entry and snapshot are written in one transaction afterwards. The adapter already requires a replica set, so that transaction is available.

`NormalizeColumn` clears `Default`, `AutoInc` and `Length`, as the guidance in `migration_design_decision.md` says, so that columns compare equal where the database stores nothing.

#### What to reuse

- `DeclaredIndexes` is the mapping from a table to its indexes. The driver needs the same mapping per operation, so split it: a function that turns one table into its primary key and unique column specs, and one that turns one `schema.Index` into a spec.
- `liveIndexes` and `liveIndex.satisfies` are the comparison.
- The body of the loop in `EnsureIndexes` (build the keys and options, create, explain a failure with `createFailure`) becomes an `ensureIndex(ctx, spec)` that both `EnsureIndexes` and the driver's `add_index` call.

#### The introspector

`Introspect(ctx, name)` gets a table name and has to return columns, indexes and foreign keys. MongoDB can answer for indexes only.

- **Indexes.** Map each live index back to a `schema.Index`: fields through the canonical names, `Unique` from the index. The indexes that stand for a primary key or a unique column are not `schema.Index` entries in a declaration, so they have to be folded back into the columns (next point) and left out of the list, or the baseline reports them as extra.
- **Columns.** The introspector has to be built with the declared tables (`NewMongoIntrospector(db, resolver, tables)`) and return the declared columns for the name it is asked about. For each one it sets `Unique` and `PrimaryKey` from the live indexes and not from the declaration. A collection that lacks the unique index on `email` then reports `email` as differing, and the plan contains the operation that creates it. Every other attribute is echoed, because there is nothing to read.
- **Foreign keys.** Report none. A declared foreign key is then planned as missing wherever the plan comes from introspection: after a baseline, and on every run of the generate-only path. The driver does nothing for the operation, and on the managed path the snapshot records the key afterwards, so it is planned once. This was read from the planner, not run. If the empty operations are a nuisance, the engine needs a way for a driver to say "this database has no foreign keys" (an optional interface next to `ColumnNormalizer`), which is a small change in `migration/core`.
- **`TableExists`.** `listCollections` with a name filter.

What this cannot do: detect a field that was renamed or removed outside Behemoth. On the managed path that does not matter after the baseline, since the snapshot is compared and not the database.

#### Ownership: what makes dropping safe

`EnsureIndexes` never drops because it can't tell whose index it is looking at. The snapshot answers that. The driver should record, for each index it creates or adopts at baseline, the name the index has in the database (a hand-made `email_1` keeps its name). `drop_index`, and the replace steps of `alter_column` and `rename_column`, then act only on names the snapshot holds. An index nobody recorded is never touched.

Replacing an index leaves a moment without it. For a unique index, create the new one first under a temporary name where MongoDB allows two indexes on the same fields (it does when the options differ, see the probe table), then drop the old one. Where the old and new index are identical apart from the name, nothing needs replacing.

#### Baseline on a database that used `EnsureIndexes`

This is the upgrade path for every application that runs today's code. The collections and indexes exist, there is no ledger. The first managed run sees baseline candidates, introspects them, and records a baseline without running anything (`RecordBaseline`). With the introspector above, the indexes `EnsureIndexes` created come back as the declared columns and indexes, and the baseline equals the declaration. Test this path first: it is the one existing users take.

#### What changes in today's code then

| Today | With the driver |
| --- | --- |
| `EnsureIndexes` is the only way to create the indexes | it stays, for applications that don't use the managed path, and its loop body is shared with the driver. Applications on the managed path stop calling it |
| `CheckIndexes` and the `Boot` check | unchanged. They don't depend on how the indexes were made. The error text should name the migration command next to `EnsureIndexes` |
| "Never dropped or changed" in *Limits to know* | true for `EnsureIndexes` only. The driver drops and replaces what the snapshot owns |
| `TestStoreContract`'s `mongo` backend calls `EnsureIndexes` | it calls `createTables` with the driver, like the SQL backends |
| no driver tests | the four tests of *Contract for implementers* in `migration_design_decision.md`, on a container, plus the baseline path above |
| the README says migrations exist for four databases | five, with the limits of a document store stated |
| `docs/api/mongodb.md` tells the user to call `EnsureIndexes` | it describes both ways |
| the entry "MongoDB indexes are created but never dropped or changed" in `docs/ongoing.md` | removed |

The driver does not give MongoDB foreign keys. Deleting a user does not depend on them (`Store.DeleteUser` removes the dependent rows itself); a sign-in that races a delete is the case left open, and has its own entry in `docs/ongoing.md`.
