package models

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	mongoAdapter "github.com/MastewalB/behemoth/storage/adapters/mongo"
	"github.com/MastewalB/behemoth/tests/testutils"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/MastewalB/behemoth/types/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Boot finds the adapter's index check through this interface.
var _ bmth.IndexChecker = (*mongoAdapter.MongoAdapter)(nil)

// memberTables declares one table with every kind of index the adapter
// derives: a primary key, a unique column, a nullable unique column, a plain
// index, a unique index over a nullable column, and an index that repeats
// the unique column's fields.
func memberTables() []schema.Table {
	return []schema.Table{{
		Name: "members",
		Columns: []schema.Column{
			{Name: "id", Type: schema.ColTypeString, PrimaryKey: true},
			{Name: "email", Type: schema.ColTypeString, Unique: true},
			{Name: "nickname", Type: schema.ColTypeString, Unique: true, Nullable: true},
			{Name: "team", Type: schema.ColTypeString},
			{Name: "badge", Type: schema.ColTypeString, Nullable: true},
		},
		Indexes: []schema.Index{
			{Name: "idx_members_team", Columns: []string{"team"}},
			{Name: "uq_members_team_badge", Columns: []string{"team", "badge"}, Unique: true},
			{Name: "idx_members_email", Columns: []string{"email"}},
		},
	}}
}

// TestMongoIndexes covers the adapter's index support on one MongoDB
// container. Each subtest uses a database of its own.
func TestMongoIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a MongoDB container")
	}
	client, cleanup := testutils.SetupMongoTestDB(context.Background(), t)
	t.Cleanup(cleanup)
	t.Run("DeclaredIndexes", func(t *testing.T) { declaredIndexes(t, client) })
	t.Run("EnsureIndexes", func(t *testing.T) { ensureIndexes(t, client) })
}

// The indexes a table gives, with no database read: one per distinct field
// list, unique when any declaration of those fields is, under the names the
// adapter's resolver gives.
func declaredIndexes(t *testing.T, client *mongo.Client) {
	adapter := mongoAdapter.NewMongoAdapter(client, "declared", nil)
	assert.Equal(t, []mongoAdapter.IndexSpec{
		{Table: "members", Collection: "members", Name: "pk_members", Fields: []string{"id"}, Unique: true, Source: "primary key"},
		{Table: "members", Collection: "members", Name: "uq_members_email", Fields: []string{"email"}, Unique: true, Source: "unique column email"},
		{Table: "members", Collection: "members", Name: "uq_members_nickname", Fields: []string{"nickname"}, Unique: true,
			NullableFields: []string{"nickname"}, Source: "unique column nickname"},
		{Table: "members", Collection: "members", Name: "uq_members_nickname_lookup", Fields: []string{"nickname"},
			Source: "unique column nickname, for lookups"},
		{Table: "members", Collection: "members", Name: "idx_members_team", Fields: []string{"team"}, Source: "index idx_members_team"},
		{Table: "members", Collection: "members", Name: "uq_members_team_badge", Fields: []string{"team", "badge"}, Unique: true,
			NullableFields: []string{"badge"}, Source: "index uq_members_team_badge"},
		{Table: "members", Collection: "members", Name: "uq_members_team_badge_lookup", Fields: []string{"team", "badge"},
			Source: "index uq_members_team_badge, for lookups"},
	}, adapter.DeclaredIndexes(memberTables()),
		"idx_members_email repeats the unique column's fields and adds nothing; a partial unique index comes with a plain one for lookups")

	// A plain index declared before a unique one on the same fields is
	// replaced by it, and a primary key stored in _id needs no index.
	tables := []schema.Table{{
		Name:    "notes",
		Columns: []schema.Column{{Name: "_id", PrimaryKey: true}, {Name: "slug"}},
		Indexes: []schema.Index{
			{Name: "idx_notes_slug", Columns: []string{"slug"}},
			{Name: "uq_notes_slug", Columns: []string{"slug"}, Unique: true},
		},
	}}
	assert.Equal(t, []mongoAdapter.IndexSpec{
		{Table: "notes", Collection: "notes", Name: "uq_notes_slug", Fields: []string{"slug"}, Unique: true, Source: "index uq_notes_slug"},
	}, adapter.DeclaredIndexes(tables))

	// Physical names come from the adapter's resolver, the one it writes with.
	mapped := mongoAdapter.NewMongoAdapter(client, "declared", physicalNamesResolver(t))
	users := []schema.Table{{
		Name: "users",
		Columns: []schema.Column{
			{Name: "id", PrimaryKey: true}, {Name: "email"}, {Name: "username", Unique: true},
		},
	}}
	assert.Equal(t, []mongoAdapter.IndexSpec{
		{Table: "users", Collection: "app_users", Name: "pk_users", Fields: []string{"user_id"}, Unique: true, Source: "primary key"},
		{Table: "users", Collection: "app_users", Name: "uq_users_username", Fields: []string{"handle"}, Unique: true, Source: "unique column username"},
	}, mapped.DeclaredIndexes(users))
}

// indexNames lists the index names of a collection, sorted, without _id_.
func indexNames(t *testing.T, coll *mongo.Collection) []string {
	t.Helper()
	cursor, err := coll.Indexes().List(context.Background())
	require.NoError(t, err)
	var specs []struct {
		Name string `bson:"name"`
	}
	require.NoError(t, cursor.All(context.Background(), &specs))
	var names []string
	for _, s := range specs {
		if s.Name != "_id_" {
			names = append(names, s.Name)
		}
	}
	sort.Strings(names)
	return names
}

func handMadeIndex(t *testing.T, coll *mongo.Collection, name string, keys bson.D, unique bool) {
	t.Helper()
	opts := options.Index().SetName(name)
	if unique {
		opts.SetUnique(true)
	}
	_, err := coll.Indexes().CreateOne(context.Background(), mongo.IndexModel{Keys: keys, Options: opts})
	require.NoError(t, err)
}

// allMemberIndexes are the names EnsureIndexes creates for memberTables on an
// empty database.
var allMemberIndexes = []string{
	"idx_members_team", "pk_members", "uq_members_email",
	"uq_members_nickname", "uq_members_nickname_lookup", "uq_members_team_badge", "uq_members_team_badge_lookup",
}

// EnsureIndexes creates what is missing and CheckIndexes reports it. The
// behaviours of MongoDB these tests pin (an equivalent index under another
// name is refused, a unique index may sit next to a plain one) were probed
// on MongoDB 6.0; docs/internal/database/adapters/mongo_indexes.md lists them.
func ensureIndexes(t *testing.T, client *mongo.Client) {
	ctx := context.Background()
	tables := memberTables()
	open := func(db string) (*mongoAdapter.MongoAdapter, *mongo.Collection) {
		require.NoError(t, client.Database(db).Drop(ctx))
		return mongoAdapter.NewMongoAdapter(client, db, nil), client.Database(db).Collection("members")
	}

	t.Run("an empty database", func(t *testing.T) {
		adapter, members := open("idx_empty")

		warnings, err := adapter.CheckIndexes(ctx, tables)
		require.Error(t, err)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
		for _, name := range []string{"primary key", "unique column email", "unique column nickname", "index uq_members_team_badge", "EnsureIndexes"} {
			assert.Contains(t, err.Error(), name)
		}
		require.Len(t, warnings, 3, "a plain index is a warning, not an error")
		assert.Contains(t, strings.Join(warnings, "\n"), "idx_members_team")
		assert.Contains(t, strings.Join(warnings, "\n"), "unique column nickname, for lookups")

		require.NoError(t, adapter.EnsureIndexes(ctx, tables))
		assert.Equal(t, allMemberIndexes, indexNames(t, members))
		warnings, err = adapter.CheckIndexes(ctx, tables)
		require.NoError(t, err)
		assert.Empty(t, warnings)

		require.NoError(t, adapter.EnsureIndexes(ctx, tables), "a second call finds everything in place")
		assert.Equal(t, allMemberIndexes, indexNames(t, members))

		insert := func(doc bson.M) error { _, err := members.InsertOne(ctx, doc); return err }
		require.NoError(t, insert(bson.M{"id": "1", "email": "a@x", "nickname": nil, "team": "red", "badge": nil}))
		require.NoError(t, insert(bson.M{"id": "2", "email": "b@x", "nickname": nil, "team": "red", "badge": nil}),
			"null in a nullable unique column is not a value: any number of rows may have none")
		require.NoError(t, insert(bson.M{"id": "3", "email": "c@x", "team": "red"}), "a missing field is no value either")
		assert.True(t, mongo.IsDuplicateKeyError(insert(bson.M{"id": "1", "email": "d@x", "team": "red"})), "primary key")
		assert.True(t, mongo.IsDuplicateKeyError(insert(bson.M{"id": "4", "email": "a@x", "team": "red"})), "unique column")
		require.NoError(t, insert(bson.M{"id": "5", "email": "e@x", "nickname": "ada", "team": "red", "badge": "gold"}))
		assert.True(t, mongo.IsDuplicateKeyError(insert(bson.M{"id": "6", "email": "f@x", "nickname": "ada", "team": "blue"})), "nullable unique column, with a value")
		assert.True(t, mongo.IsDuplicateKeyError(insert(bson.M{"id": "7", "email": "g@x", "team": "red", "badge": "gold"})), "unique index over two columns")
		require.NoError(t, insert(bson.M{"id": "8", "email": "h@x", "team": "blue", "badge": "gold"}))
	})

	t.Run("an index made by hand under another name counts", func(t *testing.T) {
		adapter, members := open("idx_handmade")
		handMadeIndex(t, members, "email_1", bson.D{{Key: "email", Value: 1}}, true)
		// A unique index serves the lookups a plain one was declared for.
		handMadeIndex(t, members, "team_unique", bson.D{{Key: "team", Value: 1}}, true)

		require.NoError(t, adapter.EnsureIndexes(ctx, tables))
		assert.Equal(t, []string{"email_1", "pk_members", "team_unique",
			"uq_members_nickname", "uq_members_nickname_lookup", "uq_members_team_badge", "uq_members_team_badge_lookup"}, indexNames(t, members),
			"nothing is created for the two that exist, and nothing is dropped")
		warnings, err := adapter.CheckIndexes(ctx, tables)
		require.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("an index on the same fields that enforces less does not count", func(t *testing.T) {
		adapter, members := open("idx_weaker")
		handMadeIndex(t, members, "email_plain", bson.D{{Key: "email", Value: 1}}, false)
		handMadeIndex(t, members, "nickname_desc", bson.D{{Key: "nickname", Value: -1}}, true)
		_, err := members.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: bson.D{{Key: "id", Value: 1}}, Options: options.Index().SetName("id_sparse").SetUnique(true).SetSparse(true),
		})
		require.NoError(t, err)

		_, err = adapter.CheckIndexes(ctx, tables)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"email_plain"`, "the message names the index that is in the way")

		// MongoDB 6 keeps a unique index next to a plain one on the same
		// fields, so the declared ones are created beside the hand-made ones.
		require.NoError(t, adapter.EnsureIndexes(ctx, tables))
		assert.ElementsMatch(t, append([]string{"email_plain", "id_sparse", "nickname_desc"}, allMemberIndexes...), indexNames(t, members))
		_, err = adapter.CheckIndexes(ctx, tables)
		require.NoError(t, err)
	})

	t.Run("a name taken by another index is reported, and the rest is created", func(t *testing.T) {
		adapter, members := open("idx_name_taken")
		handMadeIndex(t, members, "uq_members_email", bson.D{{Key: "badge", Value: 1}}, false)

		err := adapter.EnsureIndexes(ctx, tables)
		require.Error(t, err)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryMigration), "%v", err)
		assert.Contains(t, err.Error(), `conflicts with the existing index "uq_members_email"`)
		assert.Equal(t, allMemberIndexes, indexNames(t, members), "the hand-made index keeps the name; the others are created")

		_, err = adapter.CheckIndexes(ctx, tables)
		require.Error(t, err, "users.email is still not unique")
		assert.Contains(t, err.Error(), "unique column email")
		assert.NotContains(t, err.Error(), "primary key")
	})

	t.Run("duplicates in the data are reported, and the rest is created", func(t *testing.T) {
		adapter, members := open("idx_duplicates")
		_, err := members.InsertMany(ctx, []any{
			bson.M{"id": "1", "email": "a@x", "team": "red"},
			bson.M{"id": "2", "email": "a@x", "team": "blue"},
		})
		require.NoError(t, err)

		err = adapter.EnsureIndexes(ctx, tables)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "remove the duplicates")
		assert.Contains(t, err.Error(), "unique column email")
		assert.Equal(t, slices.DeleteFunc(slices.Clone(allMemberIndexes), func(n string) bool { return n == "uq_members_email" }), indexNames(t, members))
		n, err := members.CountDocuments(ctx, bson.M{})
		require.NoError(t, err)
		assert.EqualValues(t, 2, n, "no document is removed")

		_, err = members.DeleteOne(ctx, bson.M{"id": "2"})
		require.NoError(t, err)
		require.NoError(t, adapter.EnsureIndexes(ctx, tables))
		assert.Equal(t, allMemberIndexes, indexNames(t, members))
	})

	t.Run("inside a transaction", func(t *testing.T) {
		adapter, members := open("idx_transaction")
		err := adapter.Transaction(ctx, func(ctx context.Context, _ behemoth.Database) (any, error) {
			return nil, adapter.EnsureIndexes(ctx, tables)
		})
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "%v", err)
		assert.Empty(t, indexNames(t, members))
	})

	t.Run("under physical names", func(t *testing.T) {
		require.NoError(t, client.Database("idx_physical").Drop(ctx))
		adapter := mongoAdapter.NewMongoAdapter(client, "idx_physical", physicalNamesResolver(t))
		users := []schema.Table{{
			Name:    "users",
			Columns: []schema.Column{{Name: "id", PrimaryKey: true}, {Name: "email"}, {Name: "username", Unique: true}},
		}}
		require.NoError(t, adapter.EnsureIndexes(ctx, users))
		assert.Equal(t, []string{"pk_users", "uq_users_username"}, indexNames(t, client.Database("idx_physical").Collection("app_users")))

		// The adapter's own writes now meet the index.
		require.NoError(t, adapter.Create(ctx, testutils.NewTestUser("dup")))
		assert.True(t, behemotherr.IsDuplicateKey(adapter.Create(ctx, testutils.NewTestUser("dup"))))
	})
}
