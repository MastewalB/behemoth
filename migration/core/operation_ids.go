package core

import "strings"

// Operation and issue IDs.
//
// Every SchemaOperation / PlanIssue ID the planner, generator and baseline
// build comes from this file. The strings are persisted — frozen into
// migration files, and used by FilePresenter as the stable keys that carry a
// developer's resolution decisions from one run to the next (Identity
// Stability) — so changing a format here orphans existing decisions and makes
// regenerated migrations differ from reviewed ones. Treat each format as a
// compatibility contract.
//
// Formats are "<prefix>_<table>[_<name>...]". The prefixes are not always the
// OperationKind value (foreign keys use "add_fk" / "drop_fk").

func operationID(prefix string, parts ...string) string {
	return prefix + "_" + strings.Join(parts, "_")
}

func createTableID(table string) string { return operationID("create_table", table) }

func addColumnID(table, column string) string   { return operationID("add_column", table, column) }
func dropColumnID(table, column string) string  { return operationID("drop_column", table, column) }
func alterColumnID(table, column string) string { return operationID("alter_column", table, column) }

// renameColumnID identifies a confirmed rename, and also the PlanIssue that
// proposes it.
func renameColumnID(table, from, to string) string {
	return operationID("rename_column", table, from, "to", to)
}

// renameFallbackDropID / renameFallbackAddID are the two operations of a
// rename issue's "drop old, add new independently" option.
func renameFallbackDropID(renameID string) string { return renameID + "_drop" }
func renameFallbackAddID(renameID string) string  { return renameID + "_add" }

// renameGroupIssueID identifies the PlanIssue for an ambiguous rename group.
func renameGroupIssueID(table, groupID string) string {
	return operationID("rename_group", table, groupID)
}

func addIndexID(table, index string) string  { return operationID("add_index", table, index) }
func dropIndexID(table, index string) string { return operationID("drop_index", table, index) }

func addForeignKeyID(table, fk string) string  { return operationID("add_fk", table, fk) }
func dropForeignKeyID(table, fk string) string { return operationID("drop_fk", table, fk) }

// downID identifies the inverse of operation id in a migration's Down.
func downID(id string) string { return "down_" + id }

func baselineTableID(table string) string { return operationID("baseline_table", table) }
func baselineIndexID(table, index string) string {
	return operationID("baseline_index", table, index)
}
func baselineForeignKeyID(table, fk string) string {
	return operationID("baseline_fk", table, fk)
}
