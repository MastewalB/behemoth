package models

import (
	"context"

	"testing"

	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/storage/adapters"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"
)

/*
Tests for the SQLLiteAdapter implementing the behemoth.Database interface.
*/

func getWhereExpr(field string, operator clause.Operator, value any) clause.Expression {
	return clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: field, Operator: operator, Value: value},
		},
	}
}

func TestCreate(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("1")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestFind(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("2")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "2"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestUpdate(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("3")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	user.Email = "updated@email.com"
	err = adapter.Update(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "3"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	updatedUser := found.(*testutils.TestUser)
	assert.Equal(t, user.Email, updatedUser.Email)
}

func TestDelete(t *testing.T) {
	db := testutils.SetupTestDB(t, testutils.TestUserSchema)
	adapter := &adapters.SQLiteAdapter{DB: db}

	user := testutils.NewTestUser("4")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	err = adapter.Delete(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.Find(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "4"))
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestBuildSQLiteWhereClause(t *testing.T) {
	tests := []struct {
		name           string
		expr           *clause.Expression
		expectedClause string
		expectedArgs   []any
	}{
		{
			name: "Simple equality condition",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpEqual, Value: "Alice"},
				},
			},
			expectedClause: "(name = ?)",
			expectedArgs:   []any{"Alice"},
		},
		{
			name: "Multiple conditions with AND",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterThan, Value: 30},
					{Field: "name", Operator: clause.OpStartsWith, Value: "J"},
				},
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Conditions: []clause.Condition{
							{Field: "status", Operator: clause.OpEqual, Value: "active"},
							{Field: "status", Operator: clause.OpEqual, Value: "pending"},
						},
					},
				},
			},
			expectedClause: "((status = ?) OR (status = ?)) AND (age > ?) AND (name LIKE ?)",
			expectedArgs:   []any{"active", "pending", 30, "J%"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			whereClause, args := adapters.BuildSQLiteWhereClause(tc.expr)
			assert.Equal(t, tc.expectedClause, whereClause)
			assert.Equal(t, tc.expectedArgs, args)
		})
	}
}
