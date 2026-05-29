package adapters

import (
	"context"
	"errors"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"go.mongodb.org/mongo-driver/bson"
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

	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {

	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, errors.New("model must implement Serializable")
	}

	filter := BuildMongoFilter(&expr)
	collection := mdb.db.Collection(m.SchemaName())

	result := collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, WrapWithCaller(result.Err(), m.SchemaName(), mapMongoErrors)
	}

	var raw map[string]any
	if err := result.Decode(&raw); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}

	model := m.New()
	if err := model.(behemoth.Serializable).FromMap(raw); err != nil {
		return nil, err
	}

	return model, nil
}

func (mdb *MongoAdapter) FindMany(ctx context.Context, m behemoth.Model, expr clause.Expression) ([]behemoth.Model, error) {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, errors.New("model must implement Serializable")
	}

	filter := BuildMongoFilter(&expr)
	collection := mdb.db.Collection(m.SchemaName())

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}

	defer cursor.Close(ctx)

	var results []behemoth.Model
	for cursor.Next(ctx) {
		var raw map[string]any
		if err := cursor.Decode(&raw); err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
		}
		model := m.New()
		if err := model.(behemoth.Serializable).FromMap(raw); err != nil {
			return nil, err
		}
		results = append(results, model)
	}

	return results, nil

}

func (mdb *MongoAdapter) Update(ctx context.Context, m behemoth.Model) error {
	collection := mdb.db.Collection(m.SchemaName())
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return fmt.Errorf("model does not implement Serializable")
	}

	filter := bson.M{
		m.PrimaryKeyName(): m.PrimaryKeyField(),
	}

	doc, err := ser.ToMap()
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": doc,
	}

	_, err = collection.UpdateOne(ctx, filter, update)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) UpdateField(ctx context.Context, m behemoth.Model, fieldName string, value any) error {
	collection := mdb.db.Collection(m.SchemaName())

	filter := bson.M{
		m.PrimaryKeyName(): m.PrimaryKeyField(),
	}

	update := bson.M{
		"$set": bson.M{
			fieldName: value,
		},
	}

	_, err := collection.UpdateOne(ctx, filter, update)

	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	collection := mdb.db.Collection(m.SchemaName())
	filter := bson.M{
		m.PrimaryKeyName(): m.PrimaryKeyField(),
	}

	_, err := collection.DeleteOne(ctx, filter)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {

	return nil
}

func (mdb *MongoAdapter) Transaction(ctx context.Context, fn behemoth.TransactionFunc) error {
	// Create a new session using the Mongo Client that the database was created from
	session, err := mdb.db.Client().StartSession()
	if err != nil {
		return err
	}

	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(ctx mongo.SessionContext) (any, error) {
		return fn(ctx, mdb)
	})

	if err != nil {
		return err
	}

	return nil
}

func BuildMongoFilter(expr *clause.Expression) bson.M {
	if expr == nil {
		return bson.M{}
	}

	var conditions []bson.M
	if len(expr.Children) > 0 {
		for _, child := range expr.Children {
			conditions = append(conditions, BuildMongoFilter(child))
		}
	}
	for _, cond := range expr.Conditions {
		conditions = append(conditions, buildMongoCondition(cond))
	}

	if len(conditions) == 1 {
		return conditions[0]
	} else if len(conditions) > 1 {
		return bson.M{
			mapLogicalOperator(expr.Logic): conditions,
		}
	}

	return bson.M{}
}

func buildMongoCondition(cond clause.Condition) bson.M {
	switch cond.Operator {
	case clause.OpEqual:
		return bson.M{cond.Field: cond.Value}
	case clause.OpNotEqual:
		return bson.M{cond.Field: bson.M{"$ne": cond.Value}}

	case clause.OpGreaterThan:
		return bson.M{cond.Field: bson.M{"$gt": cond.Value}}

	case clause.OpGreaterEq:
		return bson.M{cond.Field: bson.M{"$gte": cond.Value}}

	case clause.OpLessThan:
		return bson.M{cond.Field: bson.M{"$lt": cond.Value}}

	case clause.OpLessEq:
		return bson.M{cond.Field: bson.M{"$lte": cond.Value}}

	// MongoDB requires the value for $in and $nin to be an array, so we use the ToSlice helper to ensure it's always a slice, even if a single value is provided.
	case clause.OpIn:
		valueSlice := ToSlice(cond.Value)
		return bson.M{cond.Field: bson.M{"$in": valueSlice}}

	case clause.OpNotIn:
		valueSlice := ToSlice(cond.Value)
		return bson.M{cond.Field: bson.M{"$nin": valueSlice}}

	case clause.OpStartsWith:
		return bson.M{cond.Field: bson.M{"$regex": fmt.Sprintf("^%s", cond.Value)}}

	case clause.OpEndsWith:
		return bson.M{cond.Field: bson.M{"$regex": fmt.Sprintf("%s$", cond.Value)}}

	case clause.OpContains:
		return bson.M{cond.Field: bson.M{"$regex": fmt.Sprintf("%s", cond.Value)}}

	case clause.OpIsNull:
		return bson.M{cond.Field: nil}

	case clause.OpNotNull:
		return bson.M{cond.Field: bson.M{"$ne": nil}}
	}

	return bson.M{}
}

func mapLogicalOperator(logic clause.Logic) string {
	switch logic {
	case clause.OpAnd:
		return "$and"
	case clause.OpOr:
		return "$or"
	default:
		return "$and"
	}
}

func mapMongoErrors(op, entity string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		return behemotherr.NewNotFound(op, entity, err)
	case errors.Is(err, mongo.ErrEmptySlice) || errors.Is(err, mongo.ErrNilValue) || errors.Is(err, mongo.ErrNilDocument):
		return behemotherr.NewValidationError(op, entity, err)
	default:
		return behemotherr.NewDatabaseError(op, err)
	}
}
