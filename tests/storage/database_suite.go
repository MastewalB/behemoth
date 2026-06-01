package models

import (
	"context"
	"errors"
	"testing"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/stretchr/testify/assert"
)

type ModelManager struct {
	Create  func(id string) behemoth.Model
	Update  func(M behemoth.Model) behemoth.Model
	Compare func(T, U behemoth.Model) bool

	// Create a deepcopy of the model. Some adapters (like GORM) update the original model instance,
	// so the original state is needed to verify that updates actually occurred.
	Clone func(M behemoth.Model) behemoth.Model
}

type DatabaseTestSuite struct {
	t               *testing.T
	adapter         behemoth.Database
	modelManager    ModelManager
	ctx             context.Context
	cleanupTables   func()
	cleanupDatabase func()
}

func NewDatabaseTestSuite(
	t *testing.T,
	adapter behemoth.Database,
	modelManager ModelManager,
	cleanupTables func(),
	cleanupDatabase func(),
) *DatabaseTestSuite {
	return &DatabaseTestSuite{
		t:               t,
		adapter:         adapter,
		modelManager:    modelManager,
		ctx:             context.Background(),
		cleanupTables:   cleanupTables,
		cleanupDatabase: cleanupDatabase,
	}
}

func (s *DatabaseTestSuite) Run() {
	s.t.Run("Create", s.TestCreate)
	s.t.Run("FindOne", s.TestFindOne)
	s.t.Run("FindMany", s.TestFindMany)
	s.t.Run("Update", s.TestUpdate)
	s.t.Run("UpdateField", s.TestUpdateField)
	s.t.Run("UpdateMany", s.TestUpdateMany)
	s.t.Run("Delete", s.TestDelete)
	s.t.Run("Transaction", s.TestTransaction)
	s.t.Run("QueryOptions", s.TestQueryOptions)

	s.cleanupDatabase()
}

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

		err = s.adapter.UpdateField(s.ctx, model, "email", data.email)
		assert.NoError(t, err)
		err = s.adapter.UpdateField(s.ctx, model, "username", data.username)
		assert.NoError(t, err)
		models = append(models, model)
	}

	return models
}

func (s *DatabaseTestSuite) TestCreate(t *testing.T) {
	defer s.cleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.True(t, s.modelManager.Compare(model, found))
}

func (s *DatabaseTestSuite) TestFindOne(t *testing.T) {
	defer s.cleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	assert.True(t, s.modelManager.Compare(model, found))
}

func (s *DatabaseTestSuite) TestFindMany(t *testing.T) {
	defer s.cleanupTables()

	model1 := s.modelManager.Create("5")
	model2 := s.modelManager.Create("6")
	err := s.adapter.Create(s.ctx, model1)
	assert.NoError(t, err)
	err = s.adapter.Create(s.ctx, model2)
	assert.NoError(t, err)

	found, err := s.adapter.FindMany(s.ctx, model1, getWhereExpr("id", clause.OpGreaterThan, "4"), nil)
	assert.NoError(t, err)
	assert.Len(t, found, 2)

}

func (s *DatabaseTestSuite) TestUpdate(t *testing.T) {
	defer s.cleanupTables()

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

func (s *DatabaseTestSuite) TestUpdateField(t *testing.T) {
	defer s.cleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)
	copy := s.modelManager.Clone(model)

	err = s.adapter.UpdateField(s.ctx, model, "email", "Updated@email.com")
	// t.Log(err.(*behemotherr.DomainError).Original
	assert.NoError(t, err)
	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	assert.False(t, s.modelManager.Compare(copy, found), "Model should have been updated and not match original")
}

func (s *DatabaseTestSuite) TestUpdateMany(t *testing.T) {
	defer s.cleanupTables()

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
	defer s.cleanupTables()

	model := s.modelManager.Create("1")
	err := s.adapter.Create(s.ctx, model)
	assert.NoError(t, err)

	err = s.adapter.Delete(s.ctx, model)
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.Error(t, err)
	assert.Nil(t, found)
}

func (s *DatabaseTestSuite) TestTransaction(t *testing.T) {
	defer s.cleanupTables()

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
	defer s.cleanupTables()

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
		// t.Log(err.(*behemotherr.DomainError).Original)
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
		s.cleanupTables()
		defer s.PopulateTableWithTestData(t)

		// Create duplicate email records
		model1 := s.modelManager.Create("dup1")
		err := s.adapter.Create(s.ctx, model1)
		assert.NoError(t, err)
		err = s.adapter.UpdateField(s.ctx, model1, "email", "duplicate@test.com")
		assert.NoError(t, err)

		model2 := s.modelManager.Create("dup2")
		err = s.adapter.Create(s.ctx, model2)
		assert.NoError(t, err)
		err = s.adapter.UpdateField(s.ctx, model2, "email", "duplicate@test.com")
		assert.NoError(t, err)

		model3 := s.modelManager.Create("dup3")
		err = s.adapter.Create(s.ctx, model3)
		assert.NoError(t, err)
		err = s.adapter.UpdateField(s.ctx, model3, "email", "unique@test.com")
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
