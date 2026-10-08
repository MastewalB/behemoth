## **MongoDB Adapter: Decoding Values**

This document explains how `MongoAdapter` (`storage/adapters/mongo/mongo.go`) turns a stored document into the Go values a model reads, and what to do when a model stores a type the adapter does not convert yet. Transactions on MongoDB are covered in [`transactions.md`](transactions.md), and the indexes a schema declares in [`mongo_indexes.md`](mongo_indexes.md).

### How a read works

`FindOne` and `FindMany` decode each document into a `map[string]any`, map its keys back to canonical names, and hand it to the model's `FromMap`. `FromMap` asserts Go types:

```go
a.CreatedAt, _ = m[AuditLogCreatedAt].(time.Time)
```

When the driver decodes into an untyped value it has to pick a Go type for each BSON type. Its defaults are its own types, not the standard library's:

| BSON type | Driver default | What a model asserts | Handled |
| --- | --- | --- | --- |
| string, bool, int64, double | `string`, `bool`, `int64`, `float64` | the same | yes, nothing to do |
| date | `primitive.DateTime` | `time.Time` | yes, by the registry |
| int32 | `int32` | `int64` | yes, by the registry |
| embedded document | `primitive.M` | `map[string]any` or `behemoth.M` | no |
| array | `primitive.A` | `[]any` | no |
| binary | `primitive.Binary` | `[]byte` | no |
| ObjectID | `primitive.ObjectID` | `string` | no |

A failed assertion in `FromMap` is silent: the field keeps its zero value. Before the registry, every timestamp read from MongoDB was the zero time. `TestStoreAuditLogMongo` in `tests/store/contract_test.go` caught it on an audit event's timestamp; the same assertion reads `created_at`, `updated_at` and a session's `expires_at`.

### Dates are decoded by a registry, not converted after the read
**Context:** A BSON date has to reach `FromMap` as a `time.Time`.
**Options considered:**
- *Convert after decoding.* Walk each decoded map and replace `primitive.DateTime` values. The MySQL adapter works this way (`adapters.ScanMySQLRow`), because its driver offers nothing else. Every read path has to call the conversion, and nested documents need a recursive walk.
- *A BSON registry with a type map entry.* `RegisterTypeMapEntry(bson.TypeDateTime, reflect.TypeOf(time.Time{}))` tells the driver which Go type to produce when it decodes a date into an untyped value. It applies wherever the driver decodes, nested documents and arrays included, and to both read paths in `FindMany` (the plain find and the distinct pipeline) without either calling a conversion.
**Decision:** The registry. `newRegistry` builds it and `NewMongoAdapter` opens the database handle with it:

```go
db: client.Database(dbName, options.Database().SetRegistry(newRegistry())),
```

The decoded time is in UTC. MongoDB stores a date in milliseconds, so anything finer is lost on write; that is the database's precision, not the adapter's.
**Revisit if:** the adapter moves to `mongo-driver` v2, where registries are set up differently.

### A 32-bit integer is decoded as an `int64`
**Context:** The driver stores a Go `int` as a BSON int32 when the value fits, and decodes an int32 into an untyped value as `int32`. Models assert `int64`, the type the SQL adapters hand them. `Session.KeyVersion` and `Token.KeyVersion` are `int`s, so on MongoDB both read back as zero, and no session or token could be verified: `no key material for version 0, purpose "token_hash"`. The store contract found it when it first ran on MongoDB.
**Options considered:**
- *Accept `int32` in the two `FromMap` methods*, as `RateLimit.FromMap` already does. Small. It fixes core's models and leaves the same trap in every plugin model with an `int` field.
- *Write every `int` as a 64-bit integer.* New documents then read back as `int64`. Documents already stored keep their int32, so a read-side rule is still needed.
- *A type map entry in the registry*, like the one for dates: `RegisterTypeMapEntry(bson.TypeInt32, reflect.TypeOf(int64(0)))`. One line, for every model, and stored data is untouched. A model that asserts `int32` no longer matches on MongoDB.

**Decision:** The registry entry. A model sees the same integer type on MongoDB as on the SQL databases, and existing documents read correctly without being rewritten. Nothing in the repository asserts `int32` alone; the `int32` case in `RateLimit.FromMap` stays and is no longer reached on MongoDB.

Filters are not affected: MongoDB compares numbers across integer types, so a condition built from a Go `int` matches a value stored either way.

### Scenarios to watch for

**An application that set its own registry on the client.** The adapter's database handle uses the adapter's registry and not the client's. The application's own use of its client is unchanged. The adapter's reads and writes do not see the application's custom codecs. Behemoth writes its models through `ToMap`, which produces plain Go values, so a custom codec has nothing to act on there. If an application needs one for a model it stores through the adapter, `NewMongoAdapter` needs a way to take a registry and add the adapter's entries to it. That option does not exist yet.

**A model that stores a nested document, an array, binary data or an ObjectID.** The value arrives as the driver type in the table above, the assertion in `FromMap` fails silently and the field is empty after a read. Note that `primitive.M` is a named type: a `case map[string]any` in a type switch does not match it. Behemoth's own models avoid this by storing metadata as JSON text (`AuditLog.Metadata`, `Token.MetadataJSON`). The symptom is a field that is written correctly (visible in the database) and comes back empty.

The fix is one more entry in `newRegistry` per type, for example:

```go
registry.RegisterTypeMapEntry(bson.TypeEmbeddedDocument, reflect.TypeOf(map[string]any{}))
registry.RegisterTypeMapEntry(bson.TypeArray, reflect.TypeOf([]any{}))
```

These two are not registered today because no model needs them and they have not been run against the test suites. Add a round-trip test with the entry: a model that stores the type, written and read back through the adapter.

**A collection written by another program.** A number stored as int32 (the default for small integers in some drivers and in the shell) is read as `int64`, like one the adapter stored. A number stored as a double (the old shell's default for every number) still arrives as `float64`, and a model asserting `int64` reads zero. This only concerns data that did not come from Behemoth.

### Tests

- `TestStoreAuditLogMongo` (`tests/store/contract_test.go`) runs the audit log part of the store contract on MongoDB, then reads one event through the adapter and checks that its timestamp is not zero and is in UTC. It also stores a session, checks that its key version is an int32 in the database, and reads it back as the same number.
- `TestStoreContract/mongo` (same file) runs the whole store contract on MongoDB. Its Sessions and Tokens parts fail without the integer rule.
- `TestMongoAdapter` (`tests/storage/database_suite_test.go`) runs the adapter suite. Its test models have no time fields, which is why it did not catch the zero timestamps.

All start a MongoDB container with a replica set. The two in `tests/store` are skipped with `-short`.
