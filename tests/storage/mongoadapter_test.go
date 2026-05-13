package models

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MongoDBName = "testdb"
var mongoClient *mongo.Client
var cleanupMongo func()

func setupMongoTestDB(ctx context.Context, t *testing.T) (*mongo.Client, func()) {
	mongodbContainer, err := mongodb.Run(ctx, "mongo:6")

	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}

	host, _ := mongodbContainer.Host(ctx)
	port, _ := mongodbContainer.MappedPort(ctx, "27017")
	mongoURI := fmt.Sprintf("mongodb://%s:%s", host, port.Port())

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))

	if err != nil {
		t.Fatalf("failed to connect to MongoDB: %v", err)
	}

	cleanup := func() {
		if err := testcontainers.TerminateContainer(mongodbContainer); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}
	return mongoClient, cleanup
}

func CleanupMongoTestDB(ctx context.Context, t *testing.T, client *mongo.Client) error {
	collections, err := client.Database(MongoDBName).ListCollectionNames(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	for _, coll := range collections {
		err := client.Database(MongoDBName).Collection(coll).Drop(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to drop collection %s: %w", coll, err)
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	mongoClient, cleanupMongo = setupMongoTestDB(ctx, nil)

	code := m.Run()

	if err := CleanupMongoTestDB(ctx, nil, mongoClient); err != nil {
		log.Fatalf("failed to clean up MongoDB: %v", err)
	}

	cleanupMongo()
	os.Exit(code)
}

func TestCreateMongo(t *testing.T) {
	ctx := context.Background()
	defer CleanupMongoTestDB(ctx, t, mongoClient)

	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)

	user := testutils.NewTestUser("1")
	err := adapter.Create(ctx, user)
	assert.NoError(t, err)

	collection := mongoClient.Database(MongoDBName).Collection("users")
	var result bson.M
	err = collection.FindOne(ctx, bson.M{"id": "1"}).Decode(&result)
	assert.NoError(t, err)

	if result["email"] != user.Email || result["username"] != user.Username {
		t.Fatalf("retrieved user does not match created user")
	}
}

func TestFindOneMongo(t *testing.T) {
	ctx := context.Background()
	defer CleanupMongoTestDB(ctx, t, mongoClient)

	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)
	user := *testutils.NewTestUser("1")
	err := adapter.Create(ctx, &user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestFindManyMongo(t *testing.T) {
	ctx := context.Background()
	defer CleanupMongoTestDB(ctx, t, mongoClient)

	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)
	user1 := testutils.NewTestUser("7")
	user2 := testutils.NewTestUser("6")
	err := adapter.Create(ctx, user1)
	assert.NoError(t, err)
	err = adapter.Create(context.Background(), user2)
	assert.NoError(t, err)

	found, err := adapter.FindMany(context.Background(),
		&testutils.TestUser{},
		clause.Expression{
			Logic: clause.OpOr,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpIn, Value: []string{"7", "0"}},       // condition true for user1
				{Field: "email", Operator: clause.OpIn, Value: []string{user2.Email}}, // condition true for user2
			},
		},
	)
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Len(t, found, 2)

	foundUser1 := found[0].(*testutils.TestUser)
	foundUser2 := found[1].(*testutils.TestUser)

	assert.Greater(t, foundUser1.ID, "4")
	assert.Greater(t, foundUser2.ID, "4")
}

func TestUpdateMongo(t *testing.T) {
	ctx := context.Background()
	defer CleanupMongoTestDB(ctx, t, mongoClient)

	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)
	user := testutils.NewTestUser("1")
	err := adapter.Create(ctx, user)
	assert.NoError(t, err)

	user.Email = "updated@email.com"
	err = adapter.Update(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	updatedUser := found.(*testutils.TestUser)
	assert.Equal(t, user.Email, updatedUser.Email)
}

func TestDeleteMongo(t *testing.T) {
	ctx := context.Background()
	defer CleanupMongoTestDB(ctx, t, mongoClient)

	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)
	user := testutils.NewTestUser("4")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err, "failed to create user")

	err = adapter.Delete(context.Background(), user)
	assert.NoError(t, err, "failed to delete user")

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "4"))
	assert.Error(t, err)
	assert.Nil(t, found, "expected no user found after delete")
}

func TestBuildMongoFilter(t *testing.T) {
	tests := []struct {
		name     string
		expr     *clause.Expression
		expected bson.M
	}{
		{
			name:     "nil expression returns empty filter",
			expr:     nil,
			expected: bson.M{},
		},
		{
			name: "single condition - eq",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpEqual, Value: "john"},
				},
			},
			expected: bson.M{"name": "john"},
		},
		{
			name: "single condition - ne",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpNotEqual, Value: 30},
				},
			},
			expected: bson.M{"age": bson.M{"$ne": 30}},
		},
		{
			name: "single condition - gt",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterThan, Value: 18},
				},
			},
			expected: bson.M{"age": bson.M{"$gt": 18}},
		},
		{
			name: "single condition - gte",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
				},
			},
			expected: bson.M{"age": bson.M{"$gte": 18}},
		},
		{
			name: "single condition - lt",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpLessThan, Value: 65},
				},
			},
			expected: bson.M{"age": bson.M{"$lt": 65}},
		},
		{
			name: "single condition - lte",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpLessEq, Value: 65},
				},
			},
			expected: bson.M{"age": bson.M{"$lte": 65}},
		},
		{
			name: "single condition - in",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpIn, Value: []string{"active", "pending"}},
				},
			},
			expected: bson.M{"status": bson.M{"$in": []string{"active", "pending"}}},
		},
		{
			name: "single condition - nin",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpNotIn, Value: []string{"deleted", "archived"}},
				},
			},
			expected: bson.M{"status": bson.M{"$nin": []string{"deleted", "archived"}}},
		},
		{
			name: "single condition - contains",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "description", Operator: clause.OpContains, Value: "test"},
				},
			},
			expected: bson.M{"description": bson.M{"$regex": "test"}},
		},
		{
			name: "single condition - starts_with",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpStartsWith, Value: "john"},
				},
			},
			expected: bson.M{"name": bson.M{"$regex": "^john"}},
		},
		{
			name: "single condition - ends_with",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "email", Operator: clause.OpEndsWith, Value: "@gmail.com"},
				},
			},
			expected: bson.M{"email": bson.M{"$regex": "@gmail.com$"}},
		},
		{
			name: "single condition - is_null",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "deleted_at", Operator: clause.OpIsNull, Value: nil},
				},
			},
			expected: bson.M{"deleted_at": nil},
		},
		{
			name: "single condition - not_null",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "email", Operator: clause.OpNotNull, Value: nil},
				},
			},
			expected: bson.M{"email": bson.M{"$ne": nil}},
		},
		{
			name: "multiple conditions with AND logic",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
					{Field: "status", Operator: clause.OpEqual, Value: "active"},
				},
			},
			expected: bson.M{
				"$and": []bson.M{
					{"age": bson.M{"$gte": 18}},
					{"status": "active"},
				},
			},
		},
		{
			name: "multiple conditions with OR logic",
			expr: &clause.Expression{
				Logic: clause.OpOr,
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpEqual, Value: "pending"},
					{Field: "status", Operator: clause.OpEqual, Value: "active"},
				},
			},
			expected: bson.M{
				"$or": []bson.M{
					{"status": "pending"},
					{"status": "active"},
				},
			},
		},
		{
			name: "single child expression",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Children: []*clause.Expression{
					{
						Conditions: []clause.Condition{
							{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
						},
					},
				},
			},
			expected: bson.M{"age": bson.M{"$gte": 18}},
		},
		{
			name: "nested expressions with AND and OR",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "active", Operator: clause.OpEqual, Value: true},
				},
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Conditions: []clause.Condition{
							{Field: "role", Operator: clause.OpEqual, Value: "admin"},
							{Field: "role", Operator: clause.OpEqual, Value: "moderator"},
						},
					},
				},
			},
			expected: bson.M{
				"$and": []bson.M{
					{
						"$or": []bson.M{
							{"role": "admin"},
							{"role": "moderator"},
						},
					},
					{"active": true},
				},
			},
		},
		{
			name: "deeply nested expressions",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Children: []*clause.Expression{
							{
								Conditions: []clause.Condition{
									{Field: "priority", Operator: clause.OpGreaterThan, Value: 5},
								},
							},
							{
								Conditions: []clause.Condition{
									{Field: "urgent", Operator: clause.OpEqual, Value: true},
								},
							},
						},
					},
					{
						Conditions: []clause.Condition{
							{Field: "status", Operator: clause.OpNotEqual, Value: "archived"},
						},
					},
				},
			},
			expected: bson.M{
				"$and": []bson.M{
					{
						"$or": []bson.M{
							{"priority": bson.M{"$gt": 5}},
							{"urgent": true},
						},
					},
					{"status": bson.M{"$ne": "archived"}},
				},
			},
		},
		{
			name: "empty conditions and no children",
			expr: &clause.Expression{
				Logic:      clause.OpAnd,
				Conditions: []clause.Condition{},
				Children:   []*clause.Expression{},
			},
			expected: bson.M{},
		},
		{
			name: "complex filter with mixed data types",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
					{Field: "tags", Operator: clause.OpIn, Value: []string{"premium", "vip"}},
					{Field: "name", Operator: clause.OpContains, Value: "john"},
				},
			},
			expected: bson.M{
				"$and": []bson.M{
					{"age": bson.M{"$gte": 18}},
					{"tags": bson.M{"$in": []string{"premium", "vip"}}},
					{"name": bson.M{"$regex": "john"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapters.BuildMongoFilter(tt.expr)
			assert.Equal(t, tt.expected, result)
		})
	}

}

func TestBuildMongoFilterEdgeCases(t *testing.T) {
	t.Run("empty values in conditions", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "name", Operator: clause.OpEqual, Value: ""},
				{Field: "age", Operator: clause.OpEqual, Value: 0},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{
			"$and": []bson.M{
				{"name": ""},
				{"age": 0},
			},
		}
		assert.Equal(t, expected, result)
	})

	t.Run("nil values in conditions", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "deleted_at", Operator: clause.OpIsNull, Value: nil},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{"deleted_at": nil}
		assert.Equal(t, expected, result)
	})

	t.Run("empty slice in IN operator", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "ids", Operator: clause.OpIn, Value: []string{}},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{"ids": bson.M{"$in": []string{}}}
		assert.Equal(t, expected, result)
	})

	t.Run("multiple children with same level", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpOr,
			Children: []*clause.Expression{
				{
					Conditions: []clause.Condition{
						{Field: "a", Operator: clause.OpEqual, Value: 1},
					},
				},
				{
					Conditions: []clause.Condition{
						{Field: "b", Operator: clause.OpEqual, Value: 2},
					},
				},
				{
					Conditions: []clause.Condition{
						{Field: "c", Operator: clause.OpEqual, Value: 3},
					},
				},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{
			"$or": []bson.M{
				{"a": 1},
				{"b": 2},
				{"c": 3},
			},
		}
		assert.Equal(t, expected, result)
	})

	t.Run("mixed children and conditions", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "active", Operator: clause.OpEqual, Value: true},
			},
			Children: []*clause.Expression{
				{
					Conditions: []clause.Condition{
						{Field: "score", Operator: clause.OpGreaterThan, Value: 50},
					},
				},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{
			"$and": []bson.M{
				{"score": bson.M{"$gt": 50}},
				{"active": true},
			},
		}
		assert.Equal(t, expected, result)
	})
}

func TestBuildMongoFilterUnsupportedOperator(t *testing.T) {
	t.Run("unsupported operator returns empty bson.M", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "test", Operator: "unsupported", Value: "value"},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{}
		assert.Equal(t, expected, result)
	})
}

func TestBuildMongoFilterNilValueHandling(t *testing.T) {
	t.Run("condition with nil value for eq", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "field", Operator: clause.OpEqual, Value: nil},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{"field": nil}
		assert.Equal(t, expected, result)
	})

	t.Run("condition with nil value for ne", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "field", Operator: clause.OpNotEqual, Value: nil},
			},
		}
		result := adapters.BuildMongoFilter(expr)
		expected := bson.M{"field": bson.M{"$ne": nil}}
		assert.Equal(t, expected, result)
	})
}