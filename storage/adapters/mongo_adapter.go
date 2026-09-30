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

// MongoAdapter implements behemoth.Database for MongoDB.
//
// Models are addressed by canonical names; collection names and document
// field names go through Resolver first. Unlike the SQL adapters — which read
// rows back by column position — stored documents come back keyed by their
// physical field names, so reads map those keys back to canonical ones before
// FromMap. A nil Resolver maps every name to itself.
//
// There is no "missing table" condition: querying a collection that doesn't
// exist simply returns no documents.
type MongoAdapter struct {
	db       *mongo.Database
	Resolver behemoth.SchemaResolver
}

func NewMongoAdapter(client *mongo.Client, dbName string, resolver behemoth.SchemaResolver) *MongoAdapter {
	return &MongoAdapter{
		db:       client.Database(dbName),
		Resolver: resolver,
	}
}

func (mdb *MongoAdapter) names() behemoth.SchemaResolver {
	return resolverOrIdentity(mdb.Resolver)
}

func (mdb *MongoAdapter) collection(m behemoth.Model) *mongo.Collection {
	return mdb.db.Collection(physicalTable(mdb.names(), m))
}

// filter renders expr with its fields resolved to physical field names.
func (mdb *MongoAdapter) filter(m behemoth.Model, expr *clause.Expression) bson.M {
	return BuildMongoFilter(physicalExpression(mdb.names(), m, expr))
}

// byPrimaryKey matches m's own document.
func (mdb *MongoAdapter) byPrimaryKey(m behemoth.Model) bson.M {
	return bson.M{physicalColumn(mdb.names(), m, m.PrimaryKeyName()): m.PrimaryKeyField()}
}

// decode turns a stored document into a new model, mapping physical keys back
// to the canonical ones FromMap expects.
func (mdb *MongoAdapter) decode(m behemoth.Model, canonical map[string]string, raw map[string]any) (behemoth.Model, error) {
	model := m.New()
	if err := model.(behemoth.Serializable).FromMap(canonicalDocument(canonical, raw)); err != nil {
		return nil, err
	}
	return model, nil
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

	_, err = mdb.collection(m).InsertOne(ctx, physicalDocument(mdb.names(), m, doc))
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) FindOne(ctx context.Context, m behemoth.Model, expr clause.Expression) (behemoth.Model, error) {

	_, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, errors.New("model must implement Serializable")
	}

	result := mdb.collection(m).FindOne(ctx, mdb.filter(m, &expr))
	if result.Err() != nil {
		return nil, WrapWithCaller(result.Err(), m.SchemaName(), mapMongoErrors)
	}

	var raw map[string]any
	if err := result.Decode(&raw); err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}

	return mdb.decode(m, canonicalFields(mdb.names(), m), raw)
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
	filter := mdb.filter(m, &expr)
	collection := mdb.collection(m)
	physicalOptions := mdb.physicalQueryOptions(m, options)

	if options != nil && options.Distinct {
		pipeline := buildDistinctPipeline(filter, physicalOptions)
		cursor, err = collection.Aggregate(ctx, pipeline)

	} else {
		mongoOpts := optionsToMongoFindOptions(physicalOptions)
		cursor, err = collection.Find(ctx, filter, mongoOpts)
	}

	if err != nil {
		return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
	}
	defer cursor.Close(ctx) // only once cursor is known to be non-nil

	canonical := canonicalFields(mdb.names(), m)
	var results []behemoth.Model
	for cursor.Next(ctx) {
		var raw map[string]any
		if err := cursor.Decode(&raw); err != nil {
			return nil, WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
		}
		model, err := mdb.decode(m, canonical, raw)
		if err != nil {
			return nil, err
		}
		results = append(results, model)
	}

	return results, nil

}

// physicalQueryOptions returns a copy of options with the sort field and the
// selected fields resolved to physical names.
func (mdb *MongoAdapter) physicalQueryOptions(m behemoth.Model, options *behemoth.QueryOptions) *behemoth.QueryOptions {
	if options == nil {
		return nil
	}
	out := *options
	if out.OrderBy.Field != "" {
		out.OrderBy.Field = physicalColumn(mdb.names(), m, out.OrderBy.Field)
	}
	if len(out.Select) > 0 {
		out.Select = physicalColumns(mdb.names(), m, out.Select)
	}
	return &out
}

func (mdb *MongoAdapter) Update(ctx context.Context, m behemoth.Model) error {
	ser, ok := m.(behemoth.Serializable)
	if !ok {
		return behemotherr.SerializableNotImplemented()
	}

	doc, err := ser.ToMap()
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": physicalDocument(mdb.names(), m, doc),
	}

	_, err = mdb.collection(m).UpdateOne(ctx, mdb.byPrimaryKey(m), update)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) UpdateOne(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {
	if len(updates) == 0 {
		return nil
	}

	update := bson.M{
		"$set": physicalDocument(mdb.names(), m, updates),
	}

	_, err := mdb.collection(m).UpdateOne(ctx, mdb.filter(m, &expr), update)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) UpdateMany(
	ctx context.Context,
	m behemoth.Model,
	expr clause.Expression,
	updates behemoth.M,
) error {

	if len(updates) == 0 {
		return nil
	}

	_, err := mdb.collection(m).UpdateMany(
		ctx,
		mdb.filter(m, &expr),
		bson.M{
			"$set": physicalDocument(mdb.names(), m, updates),
		},
	)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) Delete(ctx context.Context, m behemoth.Model) error {
	_, err := mdb.collection(m).DeleteOne(ctx, mdb.byPrimaryKey(m))
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) DeleteOne(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	filter := mdb.filter(m, &expr)

	if len(filter) == 0 {
		return behemotherr.NewValidationError(OpDeleteOne, "clause", nil)
	}
	_, err := mdb.collection(m).DeleteOne(ctx, filter)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) DeleteMany(ctx context.Context, m behemoth.Model, expr clause.Expression) error {
	filter := mdb.filter(m, &expr)

	if len(filter) == 0 {
		return behemotherr.NewValidationError(OpDeleteMany, "clause", nil)
	}
	_, err := mdb.collection(m).DeleteMany(ctx, filter)
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) DeleteAll(ctx context.Context, m behemoth.Model) error {
	_, err := mdb.collection(m).DeleteMany(ctx, bson.M{})
	return WrapWithCaller(err, m.SchemaName(), mapMongoErrors)
}

func (mdb *MongoAdapter) Count(ctx context.Context, m behemoth.Model, expr clause.Expression) (int64, error) {
	count, err := mdb.collection(m).CountDocuments(ctx, mdb.filter(m, &expr))
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
		return classify(op, entity, sentinelNotFound, err)
	case mongo.IsDuplicateKeyError(err): // E11000, from a unique index
		return classify(op, entity, sentinelDuplicateKey, err)
	case errors.Is(err, mongo.ErrEmptySlice) || errors.Is(err, mongo.ErrNilValue) || errors.Is(err, mongo.ErrNilDocument):
		return behemotherr.NewValidationError(op, entity, err)
	default:
		return classify(op, entity, sentinelUnknown, err)
	}
}

// optionsToMongoFindOptions converts query options whose field names are
// already physical (see MongoAdapter.physicalQueryOptions).
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

// buildDistinctPipeline builds a DISTINCT aggregation from a physical filter
// and query options whose field names are already physical.
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
