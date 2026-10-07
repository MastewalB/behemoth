## **MongoDB Adapter: Decoding Values**

This document explains how `MongoAdapter` (`storage/adapters/mongo/mongo.go`) turns a stored document into the Go values a model reads, and what to do when a model stores a type the adapter does not convert yet. Transactions on MongoDB are covered in [`transactions.md`](transactions.md).

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
| embedded document | `primitive.M` | `map[string]any` or `behemoth.M` | no |
| array | `primitive.A` | `[]any` | no |
| binary | `primitive.Binary` | `[]byte` | no |
| ObjectID | `primitive.ObjectID` | `string` | no |
| int32 | `int32` | `int64` | no |

A failed assertion in `FromMap` is silent: the field keeps its zero value. Before the registry, every timestamp read from MongoDB was the zero time. `TestStoreAuditLogMongo` in `tests/store/contract_test.go` caught it on an audit event's timestamp; the same assertion reads `created_at`, `updated_at` and a session's `expires_at`.

### Dates are decoded by a registry, not converted after the read
**Context:** A BSON date has to reach `FromMap` as a `time.Time`.
**Options considered:**
- *Convert after decoding.* Walk each decoded map and replace `primitive.DateTime` values. The MySQL adapter works this way (`scanRow`), because its driver offers nothing else. Every read path has to call the conversion, and nested documents need a recursive walk.
- *A BSON registry with a type map entry.* `RegisterTypeMapEntry(bson.TypeDateTime, reflect.TypeOf(time.Time{}))` tells the driver which Go type to produce when it decodes a date into an untyped value. It applies wherever the driver decodes, nested documents and arrays included, and to both read paths in `FindMany` (the plain find and the distinct pipeline) without either calling a conversion.
**Decision:** The registry. `newRegistry` builds it and `NewMongoAdapter` opens the database handle with it:

```go
db: client.Database(dbName, options.Database().SetRegistry(newRegistry())),
```

The decoded time is in UTC. MongoDB stores a date in milliseconds, so anything finer is lost on write; that is the database's precision, not the adapter's.
**Revisit if:** the adapter moves to `mongo-driver` v2, where registries are set up differently.

### Scenarios to watch for

**An application that set its own registry on the client.** The adapter's database handle uses the adapter's registry and not the client's. The application's own use of its client is unchanged. The adapter's reads and writes do not see the application's custom codecs. Behemoth writes its models through `ToMap`, which produces plain Go values, so a custom codec has nothing to act on there. If an application needs one for a model it stores through the adapter, `NewMongoAdapter` needs a way to take a registry and add the adapter's entries to it. That option does not exist yet.

**A model that stores a nested document, an array, binary data or an ObjectID.** The value arrives as the driver type in the table above, the assertion in `FromMap` fails silently and the field is empty after a read. Note that `primitive.M` is a named type: a `case map[string]any` in a type switch does not match it. Behemoth's own models avoid this by storing metadata as JSON text (`AuditLog.Metadata`, `Token.MetadataJSON`). The symptom is a field that is written correctly (visible in the database) and comes back empty.

The fix is one more entry in `newRegistry` per type, for example:

```go
registry.RegisterTypeMapEntry(bson.TypeEmbeddedDocument, reflect.TypeOf(map[string]any{}))
registry.RegisterTypeMapEntry(bson.TypeArray, reflect.TypeOf([]any{}))
```

These two are not registered today because no model needs them and they have not been run against the test suites. Add a round-trip test with the entry: a model that stores the type, written and read back through the adapter.

**A collection written by another program.** A number stored as int32 (the default for small integers in some drivers and in the shell) arrives as `int32`, and a model asserting `int64` reads zero. Documents written through the adapter store Go's `int64` as a BSON int64, so this only concerns data that did not come from Behemoth.

### Tests

- `TestStoreAuditLogMongo` (`tests/store/contract_test.go`) runs the audit log part of the store contract on MongoDB, then reads one event through the adapter and checks that its timestamp is not zero and is in UTC.
- `TestMongoAdapter` (`tests/storage/database_suite_test.go`) runs the adapter suite. Its test models have no time fields, which is why it did not catch the zero timestamps.

Both start a MongoDB container with a replica set. `TestStoreAuditLogMongo` is skipped with `-short`.
