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
	s.t.Run("Delete", s.TestDelete)
	s.t.Run("Transaction", s.TestTransaction)

	s.cleanupDatabase()
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

	found, err := s.adapter.FindMany(s.ctx, model1, getWhereExpr("id", clause.OpGreaterThan, "4"))
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

	err = s.adapter.UpdateField(s.ctx, model, "email", "Updated@email.com")
	// t.Log(err.(*behemotherr.DomainError).Original
	assert.NoError(t, err)

	found, err := s.adapter.FindOne(s.ctx, model, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	assert.False(t, s.modelManager.Compare(model, found), "Model should have been updated and not match original")
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

func getWhereExpr(field string, operator clause.Operator, value any) clause.Expression {
	return clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: field, Operator: operator, Value: value},
		},
	}
}
