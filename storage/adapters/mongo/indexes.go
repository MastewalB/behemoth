package mongo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// This file gives a MongoDB database the indexes a schema declares.
//
// The SQL databases get them from their migration drivers. MongoDB has no
// migration driver, and a missing index there is silent: a query on a
// collection without one returns the same documents more slowly, and an
// insert that a unique index would have refused succeeds. EnsureIndexes
// creates the indexes, and CheckIndexes, which Boot calls, refuses to start
// without the unique ones.
//
// Indexes are created and never dropped or changed. Removing an index that a
// schema no longer declares, and replacing one whose columns changed, are a
// migration driver's work and are not built. docs/internal/database/adapters/
// mongo_indexes.md has the rules, the cases and the plan for that driver.

// IndexSpec is one index the adapter derives from a declared table: where it
// goes and what it enforces. DeclaredIndexes returns them, EnsureIndexes
// creates them and CheckIndexes looks for them.
type IndexSpec struct {
	Table      string // canonical table name
	Collection string // physical collection name
	// Name is the name the index is created with. An existing index with
	// another name and the same fields and options also counts as this one.
	Name string
	// Fields are the physical field names, in index order. All are ascending.
	Fields []string
	Unique bool
	// NullableFields are the fields of a unique index whose columns are
	// declared nullable. A document in which one of them is null or missing
	// is left out of the index, so any number of documents may have no
	// value, as with NULL in a unique SQL index. MongoDB does not use such
	// a partial index for lookups, so DeclaredIndexes pairs it with a plain
	// index on the same fields.
	NullableFields []string
	// Source says what declared the index: "primary key", "unique column
	// email" or "index idx_sessions_user_id".
	Source string
}

// nonNullTypes are the BSON types a field of a partial unique index may
// have: every type the adapter can write from a model's Go value, and not
// null. "number" covers int, long, double and decimal.
var nonNullTypes = bson.A{"number", "string", "object", "array", "binData", "objectId", "bool", "date", "timestamp"}

// partialFilter returns the partialFilterExpression of s: one $type
// condition per nullable field, or nil when s is not partial.
func (s IndexSpec) partialFilter() bson.D {
	if len(s.NullableFields) == 0 {
		return nil
	}
	filter := make(bson.D, 0, len(s.NullableFields))
	for _, f := range s.NullableFields {
		filter = append(filter, bson.E{Key: f, Value: bson.D{{Key: "$type", Value: nonNullTypes}}})
	}
	return filter
}

// describe names the index for a message: unique index on "users" (email).
func (s IndexSpec) describe() string {
	kind := "index"
	if s.Unique {
		kind = "unique index"
	}
	return fmt.Sprintf("%s on %q (%s), from %s", kind, s.Collection, strings.Join(s.Fields, ", "), s.Source)
}

// DeclaredIndexes returns the indexes tables declare, with the names the
// adapter reads and writes under (its Resolver). It reads no database.
//
// A table gives, in this order:
//   - a unique index on its primary key columns. The adapter stores a
//     model's id in its own field, not in _id, so MongoDB's built-in index
//     does not cover it;
//   - a unique index for each column declared Unique;
//   - each index in Table.Indexes.
//
// A unique index over a nullable column is partial (IndexSpec.NullableFields)
// and is followed by a plain index on the same fields, named with the suffix
// "_lookup", which is the one reads use.
//
// Two of them on the same fields become one, unique if either is; a partial
// index and a full one are kept apart. A unique index on _id alone is left
// out: MongoDB always has it. Foreign keys, column types, lengths and
// defaults have no counterpart and are ignored.
func (mdb *MongoAdapter) DeclaredIndexes(tables []schema.Table) []IndexSpec {
	r := mdb.names()
	var out []IndexSpec
	for _, t := range tables {
		nullable := map[string]bool{}
		var primary []string
		for _, c := range t.Columns {
			nullable[c.Name] = c.Nullable
			if c.PrimaryKey {
				primary = append(primary, c.Name)
			}
		}

		var specs []IndexSpec
		add := func(name, source string, columns []string, unique bool) {
			if len(columns) == 0 {
				return
			}
			s := IndexSpec{Table: t.Name, Collection: r.Resolve(t.Name), Name: name, Unique: unique, Source: source}
			for _, c := range columns {
				field := r.ResolveColumn(t.Name, c)
				s.Fields = append(s.Fields, field)
				if unique && nullable[c] {
					s.NullableFields = append(s.NullableFields, field)
				}
			}
			if unique && len(s.Fields) == 1 && s.Fields[0] == "_id" {
				return
			}
			put := func(s IndexSpec) {
				for i, other := range specs {
					if !slices.Equal(other.Fields, s.Fields) || (len(other.NullableFields) > 0) != (len(s.NullableFields) > 0) {
						continue
					}
					if s.Unique && !other.Unique {
						specs[i] = s // the unique one serves the same lookups
					}
					return
				}
				specs = append(specs, s)
			}
			put(s)
			if len(s.NullableFields) > 0 {
				put(IndexSpec{
					Table: s.Table, Collection: s.Collection, Name: name + "_lookup",
					Fields: s.Fields, Source: source + ", for lookups",
				})
			}
		}

		add("pk_"+t.Name, "primary key", primary, true)
		for _, c := range t.Columns {
			if c.Unique {
				add("uq_"+t.Name+"_"+c.Name, "unique column "+c.Name, []string{c.Name}, true)
			}
		}
		for _, idx := range t.Indexes {
			add(idx.Name, "index "+idx.Name, idx.Columns, idx.Unique)
		}
		out = append(out, specs...)
	}
	return out
}

// liveIndex is an index a collection has, as listIndexes reports it.
type liveIndex struct {
	name string
	// fields are the key's field names. ascending is false when one of them
	// is not a plain ascending key (descending, hashed, text, ...); such an
	// index never stands in for a declared one.
	fields    []string
	ascending bool
	unique    bool
	sparse    bool
	collation bool
	partial   bson.Raw // nil when the index is not partial
}

// satisfies reports whether the live index does what s asks for: the same
// fields in the same order, over the same documents, and unique when s is.
// The name is not compared, so an index created by hand counts.
//
// A unique index satisfies a declared non-unique one, because it serves the
// same lookups. A sparse index, one with a collation, and one whose partial
// filter differs from s's cover other documents or compare values another
// way, and do not count.
func (l liveIndex) satisfies(s IndexSpec) bool {
	if !l.ascending || !slices.Equal(l.fields, s.Fields) || l.sparse || l.collation {
		return false
	}
	if s.Unique && !l.unique {
		return false
	}
	want := s.partialFilter()
	if want == nil {
		return l.partial == nil
	}
	raw, err := bson.Marshal(want)
	return err == nil && bytes.Equal(raw, l.partial)
}

// Server error codes EnsureIndexes and liveIndexes tell apart.
const (
	codeNamespaceNotFound     = 26 // listIndexes on a collection that does not exist
	codeIndexOptionsConflict  = 85 // the same fields and options exist under another name
	codeIndexKeySpecsConflict = 86 // the name is taken by an index with other fields or options
)

// liveIndexes lists the indexes of a collection. A collection that does not
// exist has none.
func (mdb *MongoAdapter) liveIndexes(ctx context.Context, collection string) ([]liveIndex, error) {
	cursor, err := mdb.db.Collection(collection).Indexes().List(ctx)
	if err != nil {
		if ce, ok := errors.AsType[mongo.CommandError](err); ok && ce.Code == codeNamespaceNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("list the indexes of collection %q: %w", collection, err)
	}
	var specs []struct {
		Name      string   `bson:"name"`
		Key       bson.Raw `bson:"key"`
		Unique    bool     `bson:"unique"`
		Sparse    bool     `bson:"sparse"`
		Collation bson.Raw `bson:"collation"`
		Partial   bson.Raw `bson:"partialFilterExpression"`
	}
	if err := cursor.All(ctx, &specs); err != nil {
		if ce, ok := errors.AsType[mongo.CommandError](err); ok && ce.Code == codeNamespaceNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("list the indexes of collection %q: %w", collection, err)
	}

	out := make([]liveIndex, 0, len(specs))
	for _, spec := range specs {
		l := liveIndex{
			name: spec.Name, ascending: true,
			unique: spec.Unique, sparse: spec.Sparse, collation: len(spec.Collation) > 0,
		}
		if len(spec.Partial) > 0 {
			l.partial = spec.Partial
		}
		elems, err := spec.Key.Elements()
		if err != nil {
			return nil, fmt.Errorf("read the key of index %q on collection %q: %w", spec.Name, collection, err)
		}
		for _, e := range elems {
			l.fields = append(l.fields, e.Key())
			if !isAscending(e.Value()) {
				l.ascending = false
			}
		}
		out = append(out, l)
	}
	return out, nil
}

// isAscending reports whether an index key's value is 1. Drivers send it as
// an int32, an int64 or a double, and the server returns it as it was sent.
func isAscending(v bson.RawValue) bool {
	if n, ok := v.AsInt64OK(); ok {
		return n == 1
	}
	if f, ok := v.DoubleOK(); ok {
		return f == 1
	}
	return false
}

// indexState is a declared index and what the database has for it.
type indexState struct {
	spec    IndexSpec
	present bool
	// near is a live index that is not the declared one but has its name or
	// its fields, for a message. Empty when there is none.
	near string
}

// indexStates compares the indexes tables declare with the ones the database
// has.
func (mdb *MongoAdapter) indexStates(ctx context.Context, tables []schema.Table) ([]indexState, error) {
	live := map[string][]liveIndex{}
	var states []indexState
	for _, spec := range mdb.DeclaredIndexes(tables) {
		indexes, listed := live[spec.Collection]
		if !listed {
			var err error
			if indexes, err = mdb.liveIndexes(ctx, spec.Collection); err != nil {
				return nil, err
			}
			live[spec.Collection] = indexes
		}
		state := indexState{spec: spec}
		for _, l := range indexes {
			if l.satisfies(spec) {
				state.present, state.near = true, ""
				break
			}
			if state.near == "" && (l.name == spec.Name || slices.Equal(l.fields, spec.Fields)) {
				state.near = l.name
			}
		}
		states = append(states, state)
	}
	return states, nil
}

// EnsureIndexes creates the indexes tables declare that the database does not
// have yet. Pass the tables of the prepared application
// (PreparedApp.Schemas.All()), before Boot, from a deploy step or at startup.
// It is safe to call on every start: an index that exists is left alone.
//
// It compares by fields and options, not by name, so an index created by hand
// counts as the declared one. It never drops or changes an index. When an
// index can't be created it goes on with the others and returns every
// failure together:
//   - the collection holds documents with the same value, so a unique index
//     can't be built. The duplicates have to be removed first;
//   - the index's name is taken by an index with other fields or options,
//     or MongoDB refuses it next to an existing one. That index has to be
//     dropped or renamed by hand.
//
// An index of a table that is no longer declared, and an index the schema
// used to declare under other columns, stay in the database.
//
// Call it outside a transaction: with a context that carries one it returns
// a configuration error. Building an index on a large collection takes time
// and holds the call until it is done.
func (mdb *MongoAdapter) EnsureIndexes(ctx context.Context, tables []schema.Table) error {
	const op = "MongoAdapter.EnsureIndexes"
	if mongo.SessionFromContext(ctx) != nil {
		return behemotherr.NewConfigurationError(op, "indexes can't be created inside a transaction; call EnsureIndexes with a context that carries none", nil)
	}
	states, err := mdb.indexStates(ctx, tables)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	var failed []error
	for _, state := range states {
		if state.present {
			continue
		}
		spec := state.spec
		keys := make(bson.D, len(spec.Fields))
		for i, f := range spec.Fields {
			keys[i] = bson.E{Key: f, Value: 1}
		}
		opts := options.Index().SetName(spec.Name)
		if spec.Unique {
			opts.SetUnique(true)
		}
		if filter := spec.partialFilter(); filter != nil {
			opts.SetPartialFilterExpression(filter)
		}
		if _, err := mdb.db.Collection(spec.Collection).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: keys, Options: opts}); err != nil {
			failed = append(failed, createFailure(state, err))
		}
	}
	if len(failed) > 0 {
		return behemotherr.NewMigrationError(op, behemotherr.ErrorCodeMigrationApplyFailed, errors.Join(failed...))
	}
	return nil
}

// createFailure says why an index could not be created and what to do.
func createFailure(state indexState, err error) error {
	spec := state.spec
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("%s: the collection holds documents with the same value; remove the duplicates and call EnsureIndexes again: %w",
			spec.describe(), err)
	}
	if ce, ok := errors.AsType[mongo.CommandError](err); ok && (ce.Code == codeIndexOptionsConflict || ce.Code == codeIndexKeySpecsConflict) {
		existing := "an existing index"
		if state.near != "" {
			existing = fmt.Sprintf("the existing index %q", state.near)
		}
		return fmt.Errorf("%s: it conflicts with %s, which EnsureIndexes does not drop; drop or rename that index and call EnsureIndexes again: %w",
			spec.describe(), existing, err)
	}
	return fmt.Errorf("%s: %w", spec.describe(), err)
}

// CheckIndexes compares the indexes tables declare with the ones the database
// has, and creates nothing. Boot calls it with the application's tables.
//
// A missing unique index is an error: without it MongoDB stores what the
// index was declared to refuse (two users with one email), and nothing else
// in behemoth notices. A missing index that is not unique only makes reads
// slower, and is returned as a warning for Boot to log.
func (mdb *MongoAdapter) CheckIndexes(ctx context.Context, tables []schema.Table) (warnings []string, err error) {
	const op = "MongoAdapter.CheckIndexes"
	states, err := mdb.indexStates(ctx, tables)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var missing []string
	for _, state := range states {
		if state.present {
			continue
		}
		line := state.spec.describe()
		if state.near != "" {
			line += fmt.Sprintf(" (the index %q has its name or its fields, with other options)", state.near)
		}
		if state.spec.Unique {
			missing = append(missing, line)
		} else {
			warnings = append(warnings, line)
		}
	}
	if len(missing) > 0 {
		return warnings, behemotherr.NewConfigurationError(op, fmt.Sprintf(
			"%d unique index(es) the schema declares are missing, so MongoDB would store duplicates: %s. "+
				"Create them with MongoAdapter.EnsureIndexes(ctx, app.Schemas.All()) before Boot",
			len(missing), strings.Join(missing, "; ")), nil)
	}
	return warnings, nil
}
