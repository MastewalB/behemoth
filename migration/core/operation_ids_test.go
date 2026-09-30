package core

import "testing"

// TestOperationIDFormats pins every ID format. These strings are persisted in
// migration files and resolution drafts: a change here must be deliberate,
// never a side effect of refactoring. Each expectation is the exact string the
// planner/generator/baseline produced before IDs were centralized.
func TestOperationIDFormats(t *testing.T) {
	renameID := renameColumnID("users", "mail", "email")

	for want, got := range map[string]string{
		"create_table_users":                     createTableID("users"),
		"add_column_users_email":                 addColumnID("users", "email"),
		"drop_column_users_email":                dropColumnID("users", "email"),
		"alter_column_users_email":               alterColumnID("users", "email"),
		"rename_column_users_mail_to_email":      renameID,
		"rename_column_users_mail_to_email_drop": renameFallbackDropID(renameID),
		"rename_column_users_mail_to_email_add":  renameFallbackAddID(renameID),
		"rename_group_users_group_1":             renameGroupIssueID("users", "group_1"),
		"add_index_users_idx_email":              addIndexID("users", "idx_email"),
		"drop_index_users_idx_email":             dropIndexID("users", "idx_email"),
		"add_fk_posts_fk_posts_user":             addForeignKeyID("posts", "fk_posts_user"),
		"drop_fk_posts_fk_posts_user":            dropForeignKeyID("posts", "fk_posts_user"),
		"down_add_column_users_email":            downID(addColumnID("users", "email")),
		"baseline_table_users":                   baselineTableID("users"),
		"baseline_index_users_idx_email":         baselineIndexID("users", "idx_email"),
		"baseline_fk_posts_fk_posts_user":        baselineForeignKeyID("posts", "fk_posts_user"),
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
