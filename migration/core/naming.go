package core

import (
	"fmt"
	"sort"
	"strings"
)

// maxMigrationNameLength bounds a derived name, so that a file name built
// from it stays well under what file systems accept.
const maxMigrationNameLength = 60

// migrationName derives a migration's name from what it does. The name is
// the readable half of the file name, <ID>_<Name>: 0002_add_column_users_plan.
// The ID stays the number alone, and nothing but the file name reads the
// name.
//
// It is derived from the resolved operations and nothing else, so a preview
// and the confirmed run that follows it agree on the name.
//
//	one operation                    its kind and target   add_column_users_plan
//	several operations on one table  the table             alter_notes
//	only new tables                  the tables            create_users_sessions
//	a mix across tables              the tables            update_users_notes
//	only custom migrations           the first one's name  backfill_plans
//
// More than three tables are named as the first and a count:
// create_accounts_and_6_more. fallback is returned when nothing can be
// derived.
//
// Deferred: a name chosen by the developer. It would override this one.
func migrationName(resolved *ResolvedOperationSet, fallback string) string {
	name := deriveMigrationName(resolved)
	if name = cleanMigrationName(name); name == "" {
		return fallback
	}
	return name
}

func deriveMigrationName(resolved *ResolvedOperationSet) string {
	ops := resolved.Operations
	if len(ops) == 0 {
		// Sorted, like Migration.Custom: declaration order is the
		// application's to change.
		if names := customNames(resolved); len(names) > 0 {
			return names[0]
		}
		return ""
	}

	// The planner walks a map, so the operations arrive in no fixed order.
	touched, created := map[string]bool{}, map[string]bool{}
	for _, op := range ops {
		touched[op.Table] = true
		if op.Kind == OpCreateTable {
			created[op.Table] = true
		}
	}
	tables := make([]string, 0, len(touched))
	for table := range touched {
		tables = append(tables, table)
	}
	sort.Strings(tables)

	switch {
	case len(created) == len(touched):
		// A new table's indexes and foreign keys are operations of their
		// own, and still part of creating it.
		return "create_" + tableList(tables)
	case len(ops) == 1:
		return operationName(ops[0])
	case len(tables) == 1:
		return "alter_" + tables[0]
	default:
		return "update_" + tableList(tables)
	}
}

// tableList names up to three tables, and more as the first and a count.
func tableList(tables []string) string {
	if len(tables) <= 3 {
		return strings.Join(tables, "_")
	}
	return fmt.Sprintf("%s_and_%d_more", tables[0], len(tables)-1)
}

// operationName is one operation as a name: its kind, its table and what in
// the table it concerns.
func operationName(op SchemaOperation) string {
	parts := []string{string(op.Kind), op.Table}
	switch op.Kind {
	case OpAddColumn, OpAlterColumn:
		if op.Column != nil {
			parts = append(parts, op.Column.Name)
		}
	case OpDropColumn:
		parts = append(parts, op.ColumnName)
	case OpRenameColumn:
		parts = append(parts, op.ColumnName, "to", op.NewColumnName)
	case OpAddIndex:
		if op.Index != nil {
			parts = append(parts, op.Index.Name)
		}
	case OpDropIndex:
		parts = append(parts, op.IndexName)
	case OpAddForeignKey:
		if op.ForeignKey != nil {
			parts = append(parts, op.ForeignKey.Name)
		}
	case OpDropForeignKey:
		parts = append(parts, op.ForeignKeyName)
	}
	return strings.Join(parts, "_")
}

// cleanMigrationName reduces name to lower-case letters, digits and single
// underscores, and cuts it to maxMigrationNameLength. Table and column names
// come from applications, and the result is part of a file name.
func cleanMigrationName(name string) string {
	var b strings.Builder
	underscore := true // drops leading underscores, and doubles
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			underscore = false
		case !underscore:
			b.WriteByte('_')
			underscore = true
		}
	}
	clean := b.String()
	if len(clean) > maxMigrationNameLength {
		clean = clean[:maxMigrationNameLength]
	}
	return strings.TrimRight(clean, "_")
}
