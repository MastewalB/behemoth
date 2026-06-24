package models

import (
	"context"
	"errors"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/stretchr/testify/assert"
)

// ModelManager interface provides control over the concrete type for testing.
type ModelManager interface {
	Create(id string) behemoth.Model
	Update(M behemoth.Model) behemoth.Model
	Compare(T, U behemoth.Model) bool

	// Create a deepcopy of the model. Some adapters (like GORM) update the original model instance,
	// so the original state is needed to verify that updates actually occurred.
	Clone(M behemoth.Model) behemoth.Model

	// Drop all rows from the test tables.
	CleanupTables()

	// Close and dispose all database connections & containers.
	// This method will be used after all tests have ran.
	CleanupDatabase()
}

type DatabaseTestSuite struct {
	t            *testing.T
	adapter      behemoth.Database
	modelManager ModelManager
	ctx          context.Context
}

func NewDatabaseTestSuite(
	t *testing.T,
	adapter behemoth.Database,
	modelManager ModelManager,
) *DatabaseTestSuite {
	return &DatabaseTestSuite{
		t:            t,
		adapter:      adapter,
		modelManager: modelManager,
		ctx:          context.Background(),
	}
}

func (s *DatabaseTestSuite) Run() {
	s.t.Run("Create", s.TestCreate)
	s.t.Run("FindOne", s.TestFindOne)
	s.t.Run("FindMany", s.TestFindMany)
	s.t.Run("Update", s.TestUpdate)
	s.t.Run("UpdateField", s.TestUpdateOne)
	s.t.Run("UpdateMany", s.TestUpdateMany)
	s.t.Run("Delete", s.TestDelete)
	s.t.Run("DeleteOne", s.TestDeleteOne)
	s.t.Run("DeleteAll", s.TestDeleteAll)
	s.t.Run("DeleteMany", s.TestDeleteMany)
	s.t.Run("Transaction", s.TestTransaction)
	s.t.Run("QueryOptions", s.TestQueryOptions)
	s.t.Run("Count", s.TestCount)

	s.modelManager.CleanupDatabase()
}

// PopulateTableWithTestData creates multiple records in the database for testing Bulk operations and query options.
// It returns the created models for reference in tests.
//
// CAUTION: The returned models will have different email and username fields since they are updated after creation.
func (s *DatabaseTestSuite) PopulateTableWithTestData(t *testing.T) []behemoth.Model {
	var models []behemoth.Model
	testData := []struct {
		id       string
		email    string
		username string
	}{
		{"1", "alpha@test.com", "user1"},
		{"2", "beta@test.com", "user2"},
		{"3", "gamma@test.com", "user3"},
		{"4", "delta@test.com", "user4"},
		{"5", "epsilon@test.com", "user5"},
		{"update6", "old1@test.com", "user6"},
		{"update7", "old2@test.com", "user7"},
	}

	for _, data := range testData {
		model := s.modelManager.Create(data.id)
		err := s.adapter.Create(s.ctx, model)
		assert.NoError(t, err)

		err = s.adapter.UpdateOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, data.id), behemoth.M{"email": data.email})
		assert.NoError(t, err)
		err = s.adapter.UpdateOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, data.id), behemoth.M{"username": data.username})
		assert.NoError(t, err)
		models = append(models, model)
	}

	return models
}

func (s *DatabaseTestSuite) TestCreate(t *testing.T) {
	defer s.modelManager.CleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.True(t, s.modelManager.Compare(model, found))
}

func (s *DatabaseTestSuite) TestFindOne(t *testing.T) {
	defer s.modelManager.CleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	assert.True(t, s.modelManager.Compare(model, found))
}

func (s *DatabaseTestSuite) TestFindMany(t *testing.T) {
	defer s.modelManager.CleanupTables()

	models := s.PopulateTableWithTestData(t)
	model := models[0]

	found, err := s.adapter.FindMany(s.ctx, model, getWhereExpr("id", clause.OpGreaterThan, "4"), nil)
	assert.NoError(t, err)
	assert.Len(t, found, 3, "5, update6, update7 should be returned")

	found, err = s.adapter.FindMany(s.ctx, model, clause.Expression{
		Logic: clause.OpOr,
		Conditions: []clause.Condition{
			{Field: "email", Operator: clause.OpContains, Value: "old"},
			{Field: "username", Operator: clause.OpEqual, Value: "user5"},
		},
	}, nil)
	assert.NoError(t, err)
	assert.Len(t, found, 3, "Should find records with 'old' in email or username 'user5'")

}

func (s *DatabaseTestSuite) TestUpdate(t *testing.T) {
	defer s.modelManager.CleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	updatedModel := s.modelManager.Update(model)
	err = s.adapter.Update(s.ctx, updatedModel)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

}

func (s *DatabaseTestSuite) TestUpdateOne(t *testing.T) {
	defer s.modelManager.CleanupTables()

	t.Run("UpdateOneSingleRecordMatchesCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)
		model := models[0]
		copy := s.modelManager.Clone(model)
		id := getModelID(model)

		err := s.adapter.UpdateOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, id), behemoth.M{"email": "Updated@email.com"})
		assert.NoError(t, err)
		found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, id))
		assert.NoError(t, err)
		assert.NotNil(t, found)

		t.Log(found)
		assert.False(t, s.modelManager.Compare(copy, found), "Model should have been updated and not match original")
		assert.NotEqual(t, getModelEmail(copy), getModelEmail(found), "Email should be changed")
	})

	t.Run("UpdateOneMultipleRecordsMatchCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)

		model := models[0]
		err := s.adapter.UpdateOne(s.ctx, model, getWhereExpr("username", clause.OpStartsWith, "user"), behemoth.M{"username": "singleUpdatedUsername"})
		assert.NoError(t, err)

		found, err := s.adapter.FindMany(s.ctx, model, getWhereExpr("username", clause.OpEqual, "singleUpdatedUsername"), nil)
		assert.NoError(t, err)
		assert.Len(t, found, 1, "Only one record should be updated even if multiple match the condition")
	})
}

func (s *DatabaseTestSuite) TestUpdateMany(t *testing.T) {
	defer s.modelManager.CleanupTables()

	models := s.PopulateTableWithTestData(t)

	t.Run("UpdateMultipleRecordsWithCondition", func(t *testing.T) {

		// Update all records with email containing "old" to new email
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "email", Operator: clause.OpContains, Value: "old"},
			},
		}

		updates := map[string]any{
			"email": "updated@newdomain.com",
		}

		err := s.adapter.UpdateMany(s.ctx, models[0], expr, updates)
		assert.NoError(t, err)

		// Verify records were updated
		found, err := s.adapter.FindMany(s.ctx, models[0], clause.Expression{}, nil)
		assert.NoError(t, err)

		updatedCount := 0
		for _, m := range found {
			email := getModelEmail(m)
			if email == "updated@newdomain.com" {
				updatedCount++
			}
		}

		// Should update 2 records (update1, update2)
		assert.Equal(t, 2, updatedCount, "Should update 2 records with 'old' in email")

		// Verify the record that shouldn't be updated remains unchanged
		unchangedFound, err := s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, "1"))
		assert.NoError(t, err)
		assert.Equal(t, "alpha@test.com", getModelEmail(unchangedFound))
		assert.Equal(t, "user1", getModelUsername(unchangedFound))
	})

	t.Run("UpdateWithMultipleConditions", func(t *testing.T) {
		// Reset one record for this test
		resetModel := s.modelManager.Create("reset1")

		// Update records with specific conditions
		expr := clause.Expression{
			Logic: clause.OpOr,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "1"},
				{Field: "username", Operator: clause.OpEqual, Value: "user6"},
			},
		}

		updates := map[string]any{
			"email": "specific_update@test.com",
		}

		err := s.adapter.UpdateMany(s.ctx, resetModel, expr, updates)
		assert.NoError(t, err)

		// Verify only 2 records were updated
		found, err := s.adapter.FindMany(
			s.ctx,
			resetModel,
			getWhereExpr("email", clause.OpEqual, "specific_update@test.com"),
			nil,
		)
		assert.NoError(t, err)
		assert.Len(t, found, 2, "Should update 2 records matching the OR conditions")
		assert.Equal(t, "specific_update@test.com", getModelEmail(found[0]))

	})

	t.Run("UpdateWithEmptyMap", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "update1"},
			},
		}

		updates := map[string]any{}

		err := s.adapter.UpdateMany(s.ctx, models[0], expr, updates)
		assert.NoError(t, err)
	})
}

func (s *DatabaseTestSuite) TestDelete(t *testing.T) {

	defer s.modelManager.CleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	err = s.adapter.Delete(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.Error(t, err)
	assert.Nil(t, found)
}

func (s *DatabaseTestSuite) TestDeleteOne(t *testing.T) {
	defer s.modelManager.CleanupTables()

	t.Run("DeleteOneWithEqualCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)

		expr := getWhereExpr("id", clause.OpEqual, "1")
		err := s.adapter.DeleteOne(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Verify record is deleted
		_, err = s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, "1"))
		assert.Error(t, err, "Deleted record should not be found")

		// Verify other records remain
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(6), count, "Should have 6 remaining records")

		// Verify specific other records still exist
		for _, id := range []string{"2", "3", "4", "5", "update6", "update7"} {
			found, err := s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, id))
			assert.NoError(t, err)
			assert.NotNil(t, found)
		}
	})

	t.Run("DeleteOneWithMultipleMatchingRecords", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)

		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "email", Operator: clause.OpContains, Value: "old"},
			},
		}

		// Should delete only ONE record even though multiple match
		err := s.adapter.DeleteOne(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Count remaining records with 'old' email
		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count, "Should have only 1 record with 'old' email remaining (one was deleted)")

		// Total records should be 6
		totalCount, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(6), totalCount, "Total records should be 6 after deleting one")
	})

	t.Run("DeleteOneWithNoMatchingRecords", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)
		expr := getWhereExpr("id", clause.OpEqual, "nonexistent")

		err := s.adapter.DeleteOne(s.ctx, models[0], expr)
		// assert.Error(t, err, "DeleteOne should return error when no records match")

		// Verify all records still exist
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count, "All records should remain when no match found")
	})

	t.Run("DeleteOneWithOrLogic", func(t *testing.T) {
		defer s.modelManager.CleanupTables()

		models := s.PopulateTableWithTestData(t)

		expr := clause.Expression{
			Logic: clause.OpOr,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "1"},
				{Field: "id", Operator: clause.OpEqual, Value: "2"},
				{Field: "email", Operator: clause.OpEqual, Value: "old1@test.com"},
			},
		}

		err := s.adapter.DeleteOne(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Total records should be 6
		totalCount, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(6), totalCount)
	})
}

func (s *DatabaseTestSuite) TestDeleteAll(t *testing.T) {
	defer s.modelManager.CleanupTables()

	t.Run("DeleteAllFromPopulatedTable", func(t *testing.T) {
		models := s.PopulateTableWithTestData(t)

		// Verify records exist
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count, "Should have 7 records before deletion")

		// Delete all records
		err = s.adapter.DeleteAll(s.ctx, models[0])
		assert.NoError(t, err)

		// Verify table is empty
		count, err = s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count, "Table should be empty after DeleteAll")

		// Try to find any record - should return error or empty result
		_, err = s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, "1"))
		assert.Error(t, err, "FindOne should return error when no records exist")
	})

	t.Run("DeleteAllMultipleTimes", func(t *testing.T) {
		models := s.PopulateTableWithTestData(t)

		// First deletion
		err := s.adapter.DeleteAll(s.ctx, models[0])
		assert.NoError(t, err)

		// Second deletion on empty table
		err = s.adapter.DeleteAll(s.ctx, models[0])
		assert.NoError(t, err, "Second DeleteAll on empty table should not error")

		// Verify still empty
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func (s *DatabaseTestSuite) TestDeleteMany(t *testing.T) {
	defer s.modelManager.CleanupTables()

	t.Run("DeleteManyWithEqualCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()
		models := s.PopulateTableWithTestData(t)

		// Delete single record
		expr := getWhereExpr("id", clause.OpEqual, "1")
		err := s.adapter.DeleteMany(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Verify record is deleted
		_, err = s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, "1"))
		assert.Error(t, err, "Deleted record should not be found")

		// Verify other records remain
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(6), count, "Should have 6 remaining records")
	})

	t.Run("DeleteManyWithLikeCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()
		models := s.PopulateTableWithTestData(t)

		// Delete records with 'old' in email
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "email", Operator: clause.OpContains, Value: "old"},
			},
		}

		err := s.adapter.DeleteMany(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Verify deleted records are gone
		for _, id := range []string{"update6", "update7"} {
			_, err := s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, id))
			assert.Error(t, err, "Record with ID %s should be deleted", id)
		}

		// Verify remaining count
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(5), count, "Should have 5 remaining records")
	})

	t.Run("DeleteManyWithInCondition", func(t *testing.T) {
		defer s.modelManager.CleanupTables()
		models := s.PopulateTableWithTestData(t)

		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpIn, Value: []string{"1", "3", "5", "update7"}},
			},
		}

		err := s.adapter.DeleteMany(s.ctx, models[0], expr)
		assert.NoError(t, err)

		// Verify deleted records
		for _, id := range []string{"1", "3", "5", "update7"} {
			_, err := s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, id))
			assert.Error(t, err, "Record with ID %s should be deleted", id)
		}

		// Verify remaining records
		remainingIds := []string{"2", "4", "update6"}
		for _, id := range remainingIds {
			found, err := s.adapter.FindOne(s.ctx, models[0], getWhereExpr("id", clause.OpEqual, id))
			assert.NoError(t, err)
			assert.NotNil(t, found)
		}

		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})

	t.Run("DeleteManyWithNoMatchingRecordsOrEmptyExpression", func(t *testing.T) {
		defer s.modelManager.CleanupTables()
		models := s.PopulateTableWithTestData(t)

		expr := getWhereExpr("id", clause.OpEqual, "nonexistent")

		err := s.adapter.DeleteMany(s.ctx, models[0], expr)
		assert.NoError(t, err, "DeleteMany should not error when no records match")

		// Verify all records still exist
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count, "All records should remain when no match found")

		// Delete with empty expression - should return an error
		err = s.adapter.DeleteMany(s.ctx, models[0], clause.Expression{})
		assert.Error(t, err)

	})
}

func (s *DatabaseTestSuite) TestTransaction(t *testing.T) {
	defer s.modelManager.CleanupTables()

	// Rollback scenario: create inside transaction but return error to force rollback
	rollbackModel := s.modelManager.Create("tx_rollback")
	err := s.adapter.Transaction(context.Background(), func(ctx context.Context, tx behemoth.Database) (any, error) {
		if err := tx.Create(ctx, rollbackModel); err != nil {
			return nil, err
		}
		return nil, errors.New("force rollback")
	})
	assert.Error(t, err)

	found, err := s.adapter.FindOne(s.ctx, rollbackModel, getWhereExpr("id", clause.OpEqual, "tx_rollback"))
	assert.Error(t, err)
	assert.Nil(t, found)

	// Commit scenario: create inside transaction and return nil to commit
	commitModel := s.modelManager.Create("tx_commit")
	err = s.adapter.Transaction(context.Background(), func(ctx context.Context, tx behemoth.Database) (any, error) {
		if err := tx.Create(ctx, commitModel); err != nil {
			return nil, err
		}
		return nil, nil
	})
	assert.NoError(t, err)

	found, err = s.adapter.FindOne(s.ctx, commitModel, getWhereExpr("id", clause.OpEqual, "tx_commit"))
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.True(t, s.modelManager.Compare(commitModel, found))

}

func (s *DatabaseTestSuite) TestQueryOptions(t *testing.T) {
	defer s.modelManager.CleanupTables()

	models := s.PopulateTableWithTestData(t)

	t.Run("Limit", func(t *testing.T) {
		model := s.modelManager.Create("1")

		options := &behemoth.QueryOptions{
			Limit: 2,
		}

		found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
		assert.NoError(t, err)
		assert.Len(t, found, 2, "Should return exactly 2 records due to limit")
	})

	t.Run("Offset", func(t *testing.T) {
		model := s.modelManager.Create("1")

		// Get first 3 records
		options1 := &behemoth.QueryOptions{
			Limit:   3,
			OrderBy: behemoth.Order{Field: "id", Direction: behemoth.Asc},
		}
		firstBatch, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options1)
		assert.NoError(t, err)
		assert.Len(t, firstBatch, 3)

		// Get records with offset 2 (skip first 2)
		options2 := &behemoth.QueryOptions{
			Offset:  2,
			Limit:   3,
			OrderBy: behemoth.Order{Field: "id", Direction: behemoth.Asc},
		}
		secondBatch, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options2)
		assert.NoError(t, err)

		// Second batch should not include the first 2 records
		// Compare IDs to verify offset works
		if len(secondBatch) > 0 {
			firstID := getModelID(firstBatch[0])
			secondBatchFirstID := getModelID(secondBatch[0])
			assert.NotEqual(t, firstID, secondBatchFirstID, "Offset should skip the first record")
		}
	})

	t.Run("OrderBy", func(t *testing.T) {
		model := s.modelManager.Create("1")

		t.Run("Default Ascending", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				OrderBy: behemoth.Order{Field: "id"},
			}

			found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
			assert.NoError(t, err)
			assert.Equal(t, len(found), len(models), "Should have all records for ordering test")

			// Verify ascending order by ID
			for i := 1; i < len(found); i++ {
				prevID := getModelID(found[i-1])
				currentID := getModelID(found[i])
				assert.Less(t, prevID, currentID, "Records should be in ascending order by ID")
			}
		})

		t.Run("Ascending", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				OrderBy: behemoth.Order{Field: "id", Direction: behemoth.Asc},
			}

			found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
			assert.NoError(t, err)
			assert.Equal(t, len(found), len(models), "Should have all records for ordering test")

			// Verify ascending order by ID
			for i := 1; i < len(found); i++ {
				prevID := getModelID(found[i-1])
				currentID := getModelID(found[i])
				assert.Less(t, prevID, currentID, "Records should be in ascending order by ID")
			}
		})

		t.Run("Descending", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				OrderBy: behemoth.Order{Field: "id", Direction: behemoth.Desc},
			}

			found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
			assert.NoError(t, err)
			assert.Equal(t, len(found), len(models), "Should have all records for ordering test")

			// Verify descending order by ID
			for i := 1; i < len(found); i++ {
				prevID := getModelID(found[i-1])
				currentID := getModelID(found[i])
				assert.Greater(t, prevID, currentID, "Records should be in descending order by ID")
			}
		})

		t.Run("OrderByEmail", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				OrderBy: behemoth.Order{Field: "email", Direction: behemoth.Asc},
			}

			found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
			assert.NoError(t, err)
			assert.Equal(t, len(found), len(models), "Should have all records for ordering test")

			// Verify ascending order by email (lexicographically)
			for i := 1; i < len(found); i++ {
				prevEmail := getModelEmail(found[i-1])
				currentEmail := getModelEmail(found[i])
				assert.LessOrEqual(t, prevEmail, currentEmail, "Records should be in ascending order by email")
			}
		})

	})

	t.Run("Distinct", func(t *testing.T) {
		s.modelManager.CleanupTables()
		defer s.PopulateTableWithTestData(t)

		// Create duplicate email records
		model1 := s.modelManager.Create("dup1")
		err := s.adapter.Create(s.ctx, model1)
		assert.NoError(t, err)
		err = s.adapter.UpdateOne(s.ctx, model1, getWhereExpr("id", clause.OpEqual, "dup1"), behemoth.M{"email": "duplicate@test.com"})
		assert.NoError(t, err)

		model2 := s.modelManager.Create("dup2")
		err = s.adapter.Create(s.ctx, model2)
		assert.NoError(t, err)
		err = s.adapter.UpdateOne(s.ctx, model2, getWhereExpr("id", clause.OpEqual, "dup2"), behemoth.M{"email": "duplicate@test.com"})
		assert.NoError(t, err)

		model3 := s.modelManager.Create("dup3")
		err = s.adapter.Create(s.ctx, model3)
		assert.NoError(t, err)
		err = s.adapter.UpdateOne(s.ctx, model3, getWhereExpr("id", clause.OpEqual, "dup3"), behemoth.M{"email": "unique@test.com"})
		assert.NoError(t, err)

		t.Run("WithoutDistinct", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				Select: []string{"email"},
			}

			found, err := s.adapter.FindMany(s.ctx, model1, clause.Expression{}, options)
			assert.NoError(t, err)

			// Count emails to verify duplicates exist
			emailCount := make(map[string]int)
			for _, m := range found {
				email := getModelEmail(m)
				emailCount[email]++
			}

			// Without distinct, should get duplicate emails
			assert.Equal(t, emailCount["duplicate@test.com"], 2, "Should have duplicate emails without DISTINCT")
		})

		t.Run("WithDistinct", func(t *testing.T) {
			options := &behemoth.QueryOptions{
				Select:   []string{"email"},
				Distinct: true,
			}

			found, err := s.adapter.FindMany(s.ctx, model1, clause.Expression{}, options)
			assert.NoError(t, err)

			// We have only "duplicate@test.com" and "unique@test.com"
			assert.Equal(t, len(found), 2, "Should have 2 unique emails")
		})
	})

	t.Run("CombinedOptions", func(t *testing.T) {
		model := s.modelManager.Create("1")

		options := &behemoth.QueryOptions{
			Limit:   2,
			Offset:  1,
			OrderBy: behemoth.Order{Field: "id", Direction: behemoth.Asc},
		}

		found, err := s.adapter.FindMany(s.ctx, model, clause.Expression{}, options)
		assert.NoError(t, err)
		assert.Len(t, found, 2, "Should respect limit")

		if len(found) >= 2 {
			// With offset 1 and ascending order, we should get IDs "2" and "3"
			firstID := getModelID(found[0])
			secondID := getModelID(found[1])
			assert.Equal(t, "2", firstID, "First record after offset 1 should be ID 2")
			assert.Equal(t, "3", secondID, "Second record after offset 1 should be ID 3")
		}
	})

}

func (s *DatabaseTestSuite) TestCount(t *testing.T) {
	defer s.modelManager.CleanupTables()

	models := s.PopulateTableWithTestData(t)

	count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
	assert.NoError(t, err)
	assert.Equal(t, count, int64(7))

	t.Run("CountAllRecords", func(t *testing.T) {
		count, err := s.adapter.Count(s.ctx, models[0], clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count, "Should count all 7 records")
	})

	t.Run("CountWithEqualCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "1"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count, "Should count exactly 1 record with ID '1'")
	})

	t.Run("CountWithLikeCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "email", Operator: clause.OpContains, Value: "@test.com"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(7), count, "Should count all records with @test.com email")
	})

	t.Run("CountWithMultipleConditions", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "email", Operator: clause.OpContains, Value: "old"},
				{Field: "username", Operator: clause.OpContains, Value: "user"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count, "Should count 2 records with 'old' in email and 'user' in username")
	})

	t.Run("CountWithGreaterThanCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpGreaterThan, Value: "3"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(4), count, "Should count 4 records with ID > 3 (4,5,update6,update7)")
	})

	t.Run("CountWithLessThanCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpLessThan, Value: "3"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count, "Should count 2 records with ID < 3 (1,2)")
	})

	t.Run("CountWithInCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpIn, Value: []string{"1", "3", "5", "update7"}},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(4), count, "Should count 4 records with IDs in the given list")
	})

	t.Run("CountWithNotEqualCondition", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "username", Operator: clause.OpNotEqual, Value: "user1"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(6), count, "Should count 6 records where username is not 'user1'")
	})

	t.Run("CountWithNoMatchingRecords", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "nonexistent"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count, "Should return 0 when no records match")
	})

	t.Run("CountWithEmptyTable", func(t *testing.T) {
		// Clean up all records
		s.modelManager.CleanupTables()
		defer s.PopulateTableWithTestData(t)

		// Create a fresh model instance for the empty table
		emptyModel := s.modelManager.Create("temp")

		count, err := s.adapter.Count(s.ctx, emptyModel, clause.Expression{})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count, "Should return 0 for empty table")
	})

	t.Run("CountWithOrLogic", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpOr,
			Conditions: []clause.Condition{
				{Field: "id", Operator: clause.OpEqual, Value: "1"},
				{Field: "id", Operator: clause.OpEqual, Value: "3"},
				{Field: "id", Operator: clause.OpEqual, Value: "5"},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), count, "Should count records with ID 1, 3, or 5")
	})

	t.Run("CountWithComplexAndOrLogic", func(t *testing.T) {
		expr := clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "username", Operator: clause.OpContains, Value: "user"},
			},
			Children: []*clause.Expression{
				{
					Logic: clause.OpOr,
					Conditions: []clause.Condition{
						{Field: "email", Operator: clause.OpContains, Value: "alpha"},
						{Field: "email", Operator: clause.OpContains, Value: "beta"},
					},
				},
			},
		}

		count, err := s.adapter.Count(s.ctx, models[0], expr)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count, "Should count records with email starting with 'alpha' or 'beta' AND username starting with 'user'")
	})
}

func getModelID(m behemoth.Model) string {
	switch v := m.(type) {
	case interface{ GetID() string }:
		return v.GetID()

	case interface{ PrimaryKeyField() any }:
		return v.PrimaryKeyField().(string)

	default:
		return ""
	}
}

func getModelEmail(m behemoth.Model) string {
	switch v := m.(type) {
	case interface{ GetEmail() string }:
		return v.GetEmail()

	default:
		return ""
	}
}

func getModelUsername(m behemoth.Model) string {
	switch v := m.(type) {
	case interface{ GetUsername() string }:
		return v.GetUsername()

	default:
		return ""
	}
}

func getWhereExpr(field string, operator clause.Operator, value any) clause.Expression {
	return clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: field, Operator: operator, Value: value},
		},
	}
}
