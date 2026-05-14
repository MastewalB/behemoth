package models

import (
	"context"
	"fmt"

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
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := *testutils.SetupSQLiteAdapter(t, db)

	user := testutils.NewTestUser("1")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "1"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	fmt.Println(found)
	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestFind(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := *testutils.SetupSQLiteAdapter(t, db)

	user := testutils.NewTestUser("2")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "2"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	foundUser := found.(*testutils.TestUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Username, foundUser.Username)
}

func TestFindMany(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := *testutils.SetupSQLiteAdapter(t, db)

	user1 := testutils.NewTestUser("5")
	user2 := testutils.NewTestUser("6")
	err := adapter.Create(context.Background(), user1)
	assert.NoError(t, err)
	err = adapter.Create(context.Background(), user2)
	assert.NoError(t, err)

	found, err := adapter.FindMany(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpGreaterThan, "4"))
	assert.NoError(t, err)
	assert.Len(t, found, 2)

	foundUser1 := found[0].(*testutils.TestUser)
	foundUser2 := found[1].(*testutils.TestUser)

	assert.Greater(t, foundUser1.ID, "4")
	assert.Greater(t, foundUser2.ID, "4")
}

func TestUpdate(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := *testutils.SetupSQLiteAdapter(t, db)

	user := testutils.NewTestUser("3")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	user.Email = "updated@email.com"
	err = adapter.Update(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "3"))
	assert.NoError(t, err)
	assert.NotNil(t, found)

	updatedUser := found.(*testutils.TestUser)
	assert.Equal(t, user.Email, updatedUser.Email)
}

func TestDelete(t *testing.T) {
	db := testutils.SetupTestDB(t, &testutils.TestUserSchema)
	adapter := *testutils.SetupSQLiteAdapter(t, db)

	user := testutils.NewTestUser("4")
	err := adapter.Create(context.Background(), user)
	assert.NoError(t, err)

	err = adapter.Delete(context.Background(), user)
	assert.NoError(t, err)

	found, err := adapter.FindOne(context.Background(), &testutils.TestUser{}, getWhereExpr("id", clause.OpEqual, "4"))
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestBuildSQLiteWhereClause(t *testing.T) {
	tests := []struct {
		name         string
		expr         *clause.Expression
		expectedSQL  string
		expectedArgs []any
	}{
		{
			name:         "nil expression returns empty",
			expr:         nil,
			expectedSQL:  "",
			expectedArgs: nil,
		},
		{
			name: "single condition - eq",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpEqual, Value: "john"},
				},
			},
			expectedSQL:  "(name = $1)",
			expectedArgs: []any{"john"},
		},
		{
			name: "single condition - ne",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpNotEqual, Value: 30},
				},
			},
			expectedSQL:  "(age != $1)",
			expectedArgs: []any{30},
		},
		{
			name: "single condition - gt",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterThan, Value: 18},
				},
			},
			expectedSQL:  "(age > $1)",
			expectedArgs: []any{18},
		},
		{
			name: "single condition - gte",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
				},
			},
			expectedSQL:  "(age >= $1)",
			expectedArgs: []any{18},
		},
		{
			name: "single condition - lt",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpLessThan, Value: 65},
				},
			},
			expectedSQL:  "(age < $1)",
			expectedArgs: []any{65},
		},
		{
			name: "single condition - lte",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpLessEq, Value: 65},
				},
			},
			expectedSQL:  "(age <= $1)",
			expectedArgs: []any{65},
		},
		{
			name: "single condition - in with slice",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpIn, Value: []any{"active", "pending", "inactive"}},
				},
			},
			expectedSQL:  "(status IN ($1, $2, $3))",
			expectedArgs: []any{"active", "pending", "inactive"},
		},
		{
			name: "single condition - in with ints",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "id", Operator: clause.OpIn, Value: []any{1, 2, 3, 4, 5}},
				},
			},
			expectedSQL:  "(id IN ($1, $2, $3, $4, $5))",
			expectedArgs: []any{1, 2, 3, 4, 5},
		},
		{
			name: "single condition - in with non list value",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "id", Operator: clause.OpIn, Value: 10},
				},
			},
			expectedSQL:  "(id IN ($1))",
			expectedArgs: []any{10},
		},
		{
			name: "single condition - not in with non list value",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "id", Operator: clause.OpNotIn, Value: 10},
				},
			},
			expectedSQL:  "(id NOT IN ($1))",
			expectedArgs: []any{10},
		},
		{
			name: "single condition - not in",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpNotIn, Value: []any{"deleted", "archived"}},
				},
			},
			expectedSQL:  "(status NOT IN ($1, $2))",
			expectedArgs: []any{"deleted", "archived"},
		},
		{
			name: "single condition - starts_with",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpStartsWith, Value: "john"},
				},
			},
			expectedSQL:  "(name LIKE $1)",
			expectedArgs: []any{"john%"},
		},
		{
			name: "single condition - ends_with",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "email", Operator: clause.OpEndsWith, Value: "@gmail.com"},
				},
			},
			expectedSQL:  "(email LIKE $1)",
			expectedArgs: []any{"%@gmail.com"},
		},
		{
			name: "single condition - contains",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "description", Operator: clause.OpContains, Value: "test"},
				},
			},
			expectedSQL:  "(description LIKE $1)",
			expectedArgs: []any{"%test%"},
		},
		{
			name: "single condition - is_null",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "deleted_at", Operator: clause.OpIsNull, Value: nil},
				},
			},
			expectedSQL:  "(deleted_at IS NULL)",
			expectedArgs: nil,
		},
		{
			name: "single condition - not_null",
			expr: &clause.Expression{
				Conditions: []clause.Condition{
					{Field: "email", Operator: clause.OpNotNull, Value: nil},
				},
			},
			expectedSQL:  "(email IS NOT NULL)",
			expectedArgs: nil,
		},
		{
			name: "two conditions with AND logic",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
					{Field: "status", Operator: clause.OpEqual, Value: "active"},
				},
			},
			expectedSQL:  "((age >= $1) AND (status = $2))",
			expectedArgs: []any{18, "active"},
		},
		{
			name: "two conditions with OR logic",
			expr: &clause.Expression{
				Logic: clause.OpOr,
				Conditions: []clause.Condition{
					{Field: "status", Operator: clause.OpEqual, Value: "pending"},
					{Field: "status", Operator: clause.OpEqual, Value: "active"},
				},
			},
			expectedSQL:  "((status = $1) OR (status = $2))",
			expectedArgs: []any{"pending", "active"},
		},
		{
			name: "single child expression",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Children: []*clause.Expression{
					{
						Conditions: []clause.Condition{
							{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
						},
					},
				},
			},
			expectedSQL:  "(age >= $1)",
			expectedArgs: []any{18},
		},
		{
			name: "nested expressions with AND and OR",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "active", Operator: clause.OpEqual, Value: true},
				},
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Conditions: []clause.Condition{
							{Field: "role", Operator: clause.OpEqual, Value: "admin"},
							{Field: "role", Operator: clause.OpEqual, Value: "moderator"},
						},
					},
				},
			},
			expectedSQL:  "(((role = $1) OR (role = $2)) AND (active = $3))",
			expectedArgs: []any{"admin", "moderator", true},
		},
		{
			name: "deeply nested expressions",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Children: []*clause.Expression{
							{
								Conditions: []clause.Condition{
									{Field: "priority", Operator: clause.OpGreaterThan, Value: 5},
								},
							},
							{
								Conditions: []clause.Condition{
									{Field: "urgent", Operator: clause.OpEqual, Value: true},
								},
							},
						},
					},
					{
						Conditions: []clause.Condition{
							{Field: "status", Operator: clause.OpNotEqual, Value: "archived"},
						},
					},
				},
			},
			expectedSQL:  "(((priority > $1) OR (urgent = $2)) AND (status != $3))",
			expectedArgs: []any{5, true, "archived"},
		},
		{
			name: "complex expression with IN and LIKE",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
					{Field: "tags", Operator: clause.OpIn, Value: []any{"premium", "vip"}},
					{Field: "name", Operator: clause.OpContains, Value: "john"},
				},
			},
			expectedSQL:  "((age >= $1) AND (tags IN ($2, $3)) AND (name LIKE $4))",
			expectedArgs: []any{18, "premium", "vip", "%john%"},
		},
		{
			name: "multiple children with same level",
			expr: &clause.Expression{
				Logic: clause.OpOr,
				Children: []*clause.Expression{
					{
						Conditions: []clause.Condition{
							{Field: "a", Operator: clause.OpEqual, Value: 1},
						},
					},
					{
						Conditions: []clause.Condition{
							{Field: "b", Operator: clause.OpEqual, Value: 2},
						},
					},
					{
						Conditions: []clause.Condition{
							{Field: "c", Operator: clause.OpEqual, Value: 3},
						},
					},
				},
			},
			expectedSQL:  "((a = $1) OR (b = $2) OR (c = $3))",
			expectedArgs: []any{1, 2, 3},
		},
		{
			name: "mixed children and conditions with parameter numbering",
			expr: &clause.Expression{
				Logic: clause.OpAnd,
				Conditions: []clause.Condition{
					{Field: "active", Operator: clause.OpEqual, Value: true},
					{Field: "score", Operator: clause.OpGreaterThan, Value: 50},
				},
				Children: []*clause.Expression{
					{
						Logic: clause.OpOr,
						Conditions: []clause.Condition{
							{Field: "role", Operator: clause.OpEqual, Value: "admin"},
							{Field: "role", Operator: clause.OpEqual, Value: "moderator"},
						},
					},
				},
			},
			expectedSQL:  "(((role = $1) OR (role = $2)) AND (active = $3) AND (score > $4))",
			expectedArgs: []any{"admin", "moderator", true, 50},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql, args := adapters.BuildSQLWhereClause(tt.expr)
			assert.Equal(t, tt.expectedSQL, sql)
			assert.Equal(t, tt.expectedArgs, args)
		})
	}
}

func TestBuildSQLiteWhereClauseEdgeCases(t *testing.T) {
	t.Run("empty expression with no conditions and no children", func(t *testing.T) {
		expr := &clause.Expression{
			Logic:      clause.OpAnd,
			Conditions: []clause.Condition{},
			Children:   []*clause.Expression{},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		assert.Equal(t, "", sql)
		assert.Empty(t, args)
	})

	t.Run("expression with empty IN slice", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "ids", Operator: clause.OpIn, Value: []any{}},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		// This will produce invalid SQL, but we test current behavior
		assert.Equal(t, "(ids IN ())", sql)
		assert.Empty(t, args)
	})

	t.Run("special characters in LIKE patterns", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "name", Operator: clause.OpContains, Value: "%_test%"},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		assert.Equal(t, "(name LIKE $1)", sql)
		assert.Equal(t, []any{"%%_test%%"}, args) // Note: SQLite will treat % and _ as special chars
	})

	t.Run("nil values in conditions", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "field1", Operator: clause.OpEqual, Value: nil},
				{Field: "field2", Operator: clause.OpNotEqual, Value: nil},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		assert.Equal(t, "((field1 = $1) AND (field2 != $2))", sql)
		assert.Equal(t, []any{nil, nil}, args)
	})

	t.Run("boolean values", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "is_active", Operator: clause.OpEqual, Value: true},
				{Field: "is_deleted", Operator: clause.OpEqual, Value: false},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		assert.Equal(t, "((is_active = $1) AND (is_deleted = $2))", sql)
		assert.Equal(t, []any{true, false}, args)
	})

	t.Run("floating point numbers", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "price", Operator: clause.OpGreaterThan, Value: 99.99},
				{Field: "rating", Operator: clause.OpLessEq, Value: 4.5},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		assert.Equal(t, "((price > $1) AND (rating <= $2))", sql)
		assert.Equal(t, []any{99.99, 4.5}, args)
	})
}

func TestBuildSQLiteWhereClauseWithRealisticScenarios(t *testing.T) {
	t.Run("user search filter", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "deleted_at", Operator: clause.OpIsNull, Value: nil},
				{Field: "status", Operator: clause.OpIn, Value: []any{"active", "pending"}},
			},
			Children: []*clause.Expression{
				{
					Logic: clause.OpOr,
					Conditions: []clause.Condition{
						{Field: "full_name", Operator: clause.OpContains, Value: "john"},
						{Field: "email", Operator: clause.OpContains, Value: "john"},
						{Field: "username", Operator: clause.OpContains, Value: "john"},
					},
				},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		expectedSQL := "(((full_name LIKE $1) OR (email LIKE $2) OR (username LIKE $3)) AND (deleted_at IS NULL) AND (status IN ($4, $5)))"
		expectedArgs := []any{"%john%", "%john%", "%john%", "active", "pending"}

		assert.Equal(t, expectedSQL, sql)
		assert.Equal(t, expectedArgs, args)
	})

	t.Run("product filter with price range and categories", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "price", Operator: clause.OpGreaterEq, Value: 10.00},
				{Field: "price", Operator: clause.OpLessEq, Value: 100.00},
				{Field: "in_stock", Operator: clause.OpEqual, Value: true},
			},
			Children: []*clause.Expression{
				{
					Logic: clause.OpOr,
					Conditions: []clause.Condition{
						{Field: "category", Operator: clause.OpEqual, Value: "electronics"},
						{Field: "category", Operator: clause.OpEqual, Value: "computers"},
						{Field: "tags", Operator: clause.OpContains, Value: "sale"},
					},
				},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		expectedSQL := "(((category = $1) OR (category = $2) OR (tags LIKE $3)) AND (price >= $4) AND (price <= $5) AND (in_stock = $6))"
		expectedArgs := []any{"electronics", "computers", "%sale%", 10.00, 100.00, true}

		assert.Equal(t, expectedSQL, sql)
		assert.Equal(t, expectedArgs, args)
	})

	t.Run("date range filter", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpAnd,
			Conditions: []clause.Condition{
				{Field: "created_at", Operator: clause.OpGreaterEq, Value: "2024-01-01"},
				{Field: "created_at", Operator: clause.OpLessEq, Value: "2024-12-31"},
				{Field: "status", Operator: clause.OpNotEqual, Value: "cancelled"},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		expectedSQL := "((created_at >= $1) AND (created_at <= $2) AND (status != $3))"
		expectedArgs := []any{"2024-01-01", "2024-12-31", "cancelled"}

		assert.Equal(t, expectedSQL, sql)
		assert.Equal(t, expectedArgs, args)
	})
}

func TestBuildSQLiteWhereClauseUnsupportedOperator(t *testing.T) {
	t.Run("unsupported operator returns empty string and args", func(t *testing.T) {
		expr := &clause.Expression{
			Conditions: []clause.Condition{
				{Field: "test", Operator: "unsupported", Value: "value"},
			},
		}
		sql, args := adapters.BuildSQLWhereClause(expr)
		// The current implementation returns empty string and args for unsupported ops
		assert.Equal(t, "", sql)
		assert.Equal(t, []any{"value"}, args) // default case in buildConditionSQL returns args
	})
}

func TestBuildSQLiteWhereClauseParameterNumberingSequence(t *testing.T) {
	t.Run("verify parameter numbering increases correctly across nested expressions", func(t *testing.T) {
		expr := &clause.Expression{
			Logic: clause.OpAnd,
			Children: []*clause.Expression{
				{
					Conditions: []clause.Condition{
						{Field: "a", Operator: clause.OpEqual, Value: 1},
						{Field: "b", Operator: clause.OpEqual, Value: 2},
					},
				},
				{
					Conditions: []clause.Condition{
						{Field: "c", Operator: clause.OpEqual, Value: 3},
					},
					Children: []*clause.Expression{
						{
							Conditions: []clause.Condition{
								{Field: "d", Operator: clause.OpEqual, Value: 4},
								{Field: "e", Operator: clause.OpEqual, Value: 5},
							},
						},
					},
				},
			},
		}

		sql, args := adapters.BuildSQLWhereClause(expr)
		// Parameters should be sequential: $1, $2, $3, $4, $5
		expectedSQL := "(((a = $1) AND (b = $2)) AND (((d = $3) AND (e = $4)) AND (c = $5)))"
		expectedArgs := []any{1, 2, 4, 5, 3}

		assert.Equal(t, expectedSQL, sql)
		assert.Equal(t, expectedArgs, args)
	})
}

// Benchmark tests
func BenchmarkBuildSQLiteWhereClause(b *testing.B) {
	expr := &clause.Expression{
		Logic: clause.OpAnd,
		Conditions: []clause.Condition{
			{Field: "age", Operator: clause.OpGreaterEq, Value: 18},
			{Field: "status", Operator: clause.OpIn, Value: []any{"active", "pending", "verified"}},
		},
		Children: []*clause.Expression{
			{
				Logic: clause.OpOr,
				Conditions: []clause.Condition{
					{Field: "name", Operator: clause.OpContains, Value: "john"},
					{Field: "email", Operator: clause.OpContains, Value: "john"},
				},
			},
		},
	}

	for b.Loop() {
		adapters.BuildSQLWhereClause(expr)
	}
}
