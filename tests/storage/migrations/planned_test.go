package migrations

import (
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/types/schema"
)

// TestPlannedTablesGetTheirIndexes runs the pipeline's own plan for two new
// tables through the driver: introspect, plan, generate, apply. It is a
// method of DriverTestSuite, so it runs for every driver.
//
// The other tests of the suite build their operations by hand. This one
// fails when the planner and a driver disagree on who creates what, as they
// did for the indexes of a new table: the planner left them on the table,
// and no driver creates them from there.
func (s *DriverTestSuite) TestPlannedTablesGetTheirIndexes() {
	introspector, ok := s.driver.(core.SchemaIntrospector)
	if !ok {
		s.T().Skip("the driver does not introspect")
	}

	users, posts := usersTable(), postsTable()
	users.Indexes = []schema.Index{{Name: "uq_users_name", Columns: []string{"name"}, Unique: true}}
	// An index and a foreign key on the same column, as core's sessions
	// table has them.
	posts.Indexes = []schema.Index{{Name: "idx_posts_user_id", Columns: []string{"user_id"}}}
	posts.ForeignKeys = []schema.ForeignKey{postsUserFK(schema.FKCascade)}

	registry := schema.NewRegistry()
	for _, table := range []schema.Table{users, posts} {
		s.Require().NoError(registry.Declare(tableModel{name: table.Name}, table))
	}
	s.Require().NoError(registry.Freeze())

	plan := func() []core.SchemaOperation {
		report, err := core.RunIntrospection(s.ctx, registry, introspector, false)
		s.Require().NoError(err)
		planned, issues, err := core.BuildPlan(report, registry)
		s.Require().NoError(err)
		s.Require().Empty(issues)
		ops := make([]core.SchemaOperation, len(planned.Operations))
		for i, p := range planned.Operations {
			ops[i] = p.Operation
		}
		return ops
	}

	m, err := (&core.DefaultMigrationGenerator{}).Generate(&core.ResolvedOperationSet{Operations: plan()}, "")
	s.Require().NoError(err)
	s.Require().NoError(s.driver.ApplyMigration(s.ctx, request(*m, nil)))

	unique, found := s.index("users", "uq_users_name")
	s.Require().True(found, "the unique index of a new table")
	s.True(unique.Unique)
	s.insert("users", map[string]any{"id": 1, "email": "ada@example.com", "name": "Ada"})
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 2, "email": "bob@example.com", "name": "Ada"}), "the index is enforced")

	_, found = s.index("posts", "idx_posts_user_id")
	s.True(found, "the index of a new table")
	_, found = s.foreignKey("posts", "fk_posts_user")
	s.True(found, "the foreign key of a new table")

	// The database matches the declaration after one migration.
	s.Empty(plan(), "a second plan")
}
