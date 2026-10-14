package core

import (
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/types/schema"
)

func TestMigrationName(t *testing.T) {
	create := func(table string) SchemaOperation {
		return SchemaOperation{ID: createTableID(table), Kind: OpCreateTable, Table: table, NewTable: &schema.Table{Name: table}}
	}
	addColumn := func(table, column string) SchemaOperation {
		return SchemaOperation{ID: addColumnID(table, column), Kind: OpAddColumn, Table: table, Column: &schema.Column{Name: column}}
	}
	index := func(table, name string) SchemaOperation { return addIndexOp(addIndexID(table, name), table, name) }

	for want, resolved := range map[string]*ResolvedOperationSet{
		"add_column_users_plan": {Operations: []SchemaOperation{addColumn("users", "plan")}},
		"rename_column_users_mail_to_email": {Operations: []SchemaOperation{
			{Kind: OpRenameColumn, Table: "users", ColumnName: "mail", NewColumnName: "email"},
		}},
		"drop_index_users_idx_old": {Operations: []SchemaOperation{{Kind: OpDropIndex, Table: "users", IndexName: "idx_old"}}},
		"alter_notes":              {Operations: []SchemaOperation{addColumn("notes", "pinned"), index("notes", "idx_notes_pinned")}},
		// A new table's index and foreign key belong to creating it.
		"create_users": {Operations: []SchemaOperation{create("users"), index("users", "idx_users_name")}},
		// Sorted, whatever order the planner's map gave them.
		"create_sessions_tokens_users": {Operations: []SchemaOperation{create("users"), create("tokens"), create("sessions")}},
		"create_accounts_and_3_more": {Operations: []SchemaOperation{
			create("users"), create("tokens"), create("sessions"), create("accounts"),
		}},
		"update_notes_users": {Operations: []SchemaOperation{create("notes"), addColumn("users", "plan")}},
		"update_a_and_3_more": {Operations: []SchemaOperation{
			addColumn("a", "x"), addColumn("b", "x"), addColumn("c", "x"), addColumn("d", "x"),
		}},
		"backfill_plans": {Custom: []CustomMigration{{Name: "reindex"}, {Name: "backfill_plans"}}},
		// Generated operations name the migration when both are present.
		"add_column_users_plan ": {
			Operations: []SchemaOperation{addColumn("users", "plan")},
			Custom:     []CustomMigration{{Name: "backfill_plans"}},
		},
		// Names from an application are reduced to what a file name takes.
		"add_column_app_users_first_name": {Operations: []SchemaOperation{addColumn("App.Users", "First Name")}},
		"0007":                            {},
	} {
		if got := migrationName(resolved, "0007"); got != strings.TrimSpace(want) {
			t.Errorf("migrationName = %q, want %q", got, strings.TrimSpace(want))
		}
	}

	long := migrationName(&ResolvedOperationSet{Operations: []SchemaOperation{addColumn("users", strings.Repeat("very_long_", 20))}}, "0007")
	if len(long) > maxMigrationNameLength || strings.HasSuffix(long, "_") {
		t.Errorf("a long name came out as %q (%d characters)", long, len(long))
	}
}

// The name is part of what a preview promises: the confirmed run has to
// write the file the preview named.
func TestGenerateNamesTheMigrationFromItsOperations(t *testing.T) {
	plan := planFor(t, declaredRegistry(t, planAuthors, planBooks))
	for range 5 { // the plan's order varies from run to run; the name must not
		m, err := (&DefaultMigrationGenerator{}).Generate(&ResolvedOperationSet{Operations: opsFromPlanned(plan.Operations)}, "0003")
		if err != nil {
			t.Fatal(err)
		}
		if m.ID != "0004" || m.Name != "create_authors_books" {
			t.Fatalf("ID = %q, Name = %q; want 0004 and create_authors_books", m.ID, m.Name)
		}
		plan = planFor(t, declaredRegistry(t, planAuthors, planBooks))
	}
}
