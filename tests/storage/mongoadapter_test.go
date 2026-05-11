package models

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
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
	adapter := adapters.NewMongoAdapter(mongoClient, MongoDBName)

	user := testutils.NewTestUser("1")
	err := adapter.Create(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	collection := mongoClient.Database(MongoDBName).Collection("users")
	var result bson.M
	err = collection.FindOne(ctx, bson.M{"id": "1"}).Decode(&result)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	if result["email"] != user.Email || result["username"] != user.Username {
		t.Fatalf("retrieved user does not match created user")
	}
}
