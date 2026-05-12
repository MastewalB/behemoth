package adapters

import (
	"context"
	"errors"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
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
	return err
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
		return nil, result.Err()
	}

	var raw map[string]any
	if err := result.Decode(&raw); err != nil {
		return nil, err
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
		return nil, err
	}

	defer cursor.Close(ctx)

	var results []behemoth.Model
	for cursor.Next(ctx) {
		var raw map[string]any
		if err := cursor.Decode(&raw); err != nil {
			return nil, err
		}
		model := m.New()
		if err := model.(behemoth.Serializable).FromMap(raw); err != nil {
			return nil, err
		}
		results = append(results, model)
	}

	return results, nil

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

	if len(conditions) > 1 {
		return bson.M{
			mapLogicalOperator(expr.Logic): conditions,
		}
	} else if len(conditions) == 0 {
		return bson.M{}
	}
	return conditions[0]
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

	case clause.OpIn:
		return bson.M{cond.Field: bson.M{"$in": cond.Value}}

	case clause.OpNotIn:
		return bson.M{cond.Field: bson.M{"$nin": cond.Value}}

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
