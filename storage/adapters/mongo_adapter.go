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
	"go.mongodb.org/mongo-driver/mongo/options"
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
		return behemotherr.SerializableNotImplemented()
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

func (mdb *MongoAdapter) FindMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	options *behemoth.QueryOptions,
) ([]behemoth.Model, error) {
	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, errors.New("model must implement Serializable")
	}
	var cursor *mongo.Cursor
	var err error
	filter := BuildMongoFilter(&expr)
	collection := mdb.db.Collection(m.SchemaName())

	defer func() {
		cursor.Close(ctx)
	}()

	if options != nil && options.Distinct {
		pipeline := buildDistinctPipeline(filter, options)
		cursor, err = collection.Aggregate(ctx, pipeline)

	} else {
		mongoOpts := optionsToMongoFindOptions(options)
		cursor, err = collection.Find(ctx, filter, mongoOpts)
	}

	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}

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
		return behemotherr.SerializableNotImplemented()
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

func (mdb *MongoAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates map[string]any,
) error {

	if len(updates) == 0 {
		return nil
	}

	collection := mdb.db.Collection(m.SchemaName())
	filter := BuildMongoFilter(&expr)

	_, err := collection.UpdateMany(
		ctx,
		filter,
		bson.M{
			"$set": updates,
		},
	)
	return err
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

func (mdb *MongoAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	collection := mdb.db.Collection(m.SchemaName())
	filter := BuildMongoFilter(&expr)

	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}
	return count, nil
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

func optionsToMongoFindOptions(queryOptions *behemoth.QueryOptions) *options.FindOptions {
	if queryOptions == nil {
		return nil
	}

	findOptions := &options.FindOptions{}

	if queryOptions.OrderBy.Field != "" {
		dir := 1
		if queryOptions.OrderBy.Direction == behemoth.Desc {
			dir = -1
		}
		findOptions.SetSort(bson.D{{Key: queryOptions.OrderBy.Field, Value: dir}})
	}
	if queryOptions.Limit != 0 {
		findOptions.SetLimit(int64(queryOptions.Limit))
	}
	if queryOptions.Offset != 0 {
		findOptions.SetSkip(int64(queryOptions.Offset))
	}
	if len(queryOptions.Select) > 0 {
		projection := bson.M{"_id": 0} // Suppress the default _id field unless it's explicitly included in the select fields
		for _, field := range queryOptions.Select {
			projection[field] = 1
		}
		findOptions.SetProjection(projection)
	}

	return findOptions
}

func buildDistinctPipeline(filter bson.M, options *behemoth.QueryOptions) mongo.Pipeline {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
	}

	// Group by all selected fields to achieve DISTINCT
	groupID := bson.M{}
	if len(options.Select) > 0 {
		for _, field := range options.Select {
			groupID[field] = "$" + field
		}
	} else {
		// If no select fields, group by the whole document (using _id as fallback)
		groupID["_id"] = "$_id"
	}

	pipeline = append(pipeline, bson.D{{Key: "$group", Value: bson.M{
		"_id": groupID,
		"doc": bson.M{"$first": "$$ROOT"},
	}}})

	pipeline = append(pipeline, bson.D{{Key: "$replaceRoot", Value: bson.M{"newRoot": "$doc"}}})

	// Apply sorting, limit, skip after distinct
	if options.OrderBy.Field != "" {
		sortDir := 1
		if options.OrderBy.Direction == behemoth.Desc {
			sortDir = -1
		}
		pipeline = append(pipeline, bson.D{{Key: "$sort", Value: bson.M{options.OrderBy.Field: sortDir}}})
	}
	if options.Offset != 0 {
		pipeline = append(pipeline, bson.D{{Key: "$skip", Value: options.Offset}})
	}
	if options.Limit != 0 {
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: options.Limit}})
	}
	return pipeline
}
