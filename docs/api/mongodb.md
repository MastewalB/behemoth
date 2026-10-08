# MongoDB

This page covers what is different when Behemoth runs on MongoDB: what the server needs, and how the indexes your schema declares get created.

## Setup

```go
import mongoAdapter "github.com/MastewalB/behemoth/storage/adapters/mongo"

app, err := bmth.Prepare(plugins, prepareCfg)
if err != nil {
	return err
}
db := mongoAdapter.NewMongoAdapter(client, "auth", app.Resolver)

// Create the indexes the schema declares. Safe to call on every start.
if err := db.EnsureIndexes(ctx, app.Schemas.All()); err != nil {
	return err
}

ac, err := bmth.Boot(ctx, app, db, bootCfg)
```

Two things are required, and `Boot` checks both:

| Requirement | Why | If it is missing |
| --- | --- | --- |
| A replica set or a sharded cluster | Behemoth writes users in a transaction, and a standalone server has none. A single-node replica set is enough. | `Boot` returns a configuration error. |
| The unique indexes the schema declares | Without them MongoDB stores what they were declared to refuse, for example two users with one email. | `Boot` returns a configuration error that lists them. |

## Indexes

There are no migrations for MongoDB. On the SQL databases a migration creates each table with its keys and indexes. On MongoDB you call `EnsureIndexes` instead.

### What `EnsureIndexes` creates

It reads the tables you pass and creates, for each one:

| Declared | Index | Name |
| --- | --- | --- |
| the primary key | a unique index | `pk_<table>` |
| a column with `Unique` | a unique index | `uq_<table>_<column>` |
| an index of the table | that index | the name it was declared with |

- Pass `app.Schemas.All()`. It holds every table, including the columns and indexes that plugins added to tables they do not own.
- A unique index on a nullable column only covers documents that have a value, so any number of documents may have none. This matches how the SQL databases treat `NULL`. MongoDB does not use such an index for lookups, so a second, plain index named `<name>_lookup` is created with it.
- Collection and field names are the physical ones the adapter writes.
- To see the list without touching the database, call `db.DeclaredIndexes(app.Schemas.All())`.

### What it does with indexes that already exist

`EnsureIndexes` compares by fields and options, not by name, and it never drops or changes an index.

| The collection has | Result |
| --- | --- |
| the index already | nothing happens |
| the same index under another name, for example an `email_1` you created | nothing happens; yours counts |
| a unique index where a plain one is declared | nothing happens; it serves the same lookups |
| a plain index where a unique one is declared | the unique index is created next to yours |
| another index under the declared name | an error that names it. Drop or rename that index, then call `EnsureIndexes` again |
| documents with the same value in a field that should be unique | an error that names the collection and fields. Remove the duplicates, then call `EnsureIndexes` again. No document is deleted for you |

When an index can't be created, the others are still created, and one error reports every failure.

### When to call it

- Call it before `Boot`, from a deploy step or at startup. Calling it again when everything exists costs one index listing per collection.
- Call it again after adding a plugin or changing your schema, so new indexes are created.
- Call it outside a transaction.
- Building an index on a large collection takes time, and the call returns when the build is done. For a large existing database, run it from a deploy step and not on the request path of a starting server.

### What `Boot` checks

`Boot` compares the declared indexes with the database and creates nothing.

- A missing unique index stops `Boot`. The error lists each one and where it was declared.
- A missing plain index only makes reads slower. `Boot` starts and logs a warning for each.

### What you still do by hand

`EnsureIndexes` only adds. These changes need a manual step in MongoDB:

- removing the index of a table, column or index you no longer declare
- replacing an index after you changed its columns, made a unique column not unique, or changed whether a unique column is nullable
- moving indexes after you renamed a field

## Other differences

- **Foreign keys are not enforced.** MongoDB has none, so a row that references a missing user is stored, and deleting a row does not delete the rows that reference it.
- **Hook handlers can run more than once.** The driver retries a transaction on a transient error. See [Hooks](hooks.md#other-things-to-know).
- **Dates are stored in milliseconds** and read back in UTC.
