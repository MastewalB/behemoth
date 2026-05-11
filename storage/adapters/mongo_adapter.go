package adapters

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoAdapter struct {
	db *mongo.Database
}

func NewMongoAdapter(client *mongo.Client, dbName string) *MongoAdapter {
	return &MongoAdapter{
		db: client.Database(dbName),
	}
}

func (mdb *MongoAdapter) Create(ctx context.Context, m behemoth.Model) error {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return fmt.Errorf("model does not implement Serializable interface")
	}

	doc, err := ser.ToMap()
	if err != nil {
		return err
	}

	collection := mdb.db.Collection(m.SchemaName())
	_, err = collection.InsertOne(ctx, doc)
	return err
}
