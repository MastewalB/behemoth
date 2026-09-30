package adapters

import (
	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
)

// Name resolution shared by the SQL adapters.
//
// Models speak canonical names: SchemaName(), the keys of ToMap(), clause
// fields, PrimaryKeyName(). Only the SQL text an adapter sends to the database
// uses physical names; rows are still handed to FromMap under canonical keys,
// so models never see a physical name.

func resolverOrIdentity(r behemoth.SchemaResolver) behemoth.SchemaResolver {
	if r == nil {
		return behemoth.IdentityResolver{}
	}
	return r
}

// physicalTable returns m's physical table name.
func physicalTable(r behemoth.SchemaResolver, m behemoth.Model) string {
	return r.Resolve(m.SchemaName())
}

// physicalColumn returns the physical name of one of m's canonical columns.
func physicalColumn(r behemoth.SchemaResolver, m behemoth.Model, column string) string {
	return r.ResolveColumn(m.SchemaName(), column)
}

// physicalColumns resolves canonical column names, preserving order, so the
// result can be zipped back against the canonical slice.
func physicalColumns(r behemoth.SchemaResolver, m behemoth.Model, columns []string) []string {
	out := make([]string, len(columns))
	for i, c := range columns {
		out[i] = physicalColumn(r, m, c)
	}
	return out
}

// physicalExpression returns a copy of expr with every condition field — in
// nested children too — resolved to its physical column. expr is not modified.
func physicalExpression(r behemoth.SchemaResolver, m behemoth.Model, expr *clause.Expression) *clause.Expression {
	if expr == nil {
		return nil
	}
	out := &clause.Expression{Logic: expr.Logic}
	if expr.Conditions != nil {
		out.Conditions = make([]clause.Condition, len(expr.Conditions))
		for i, cond := range expr.Conditions {
			cond.Field = physicalColumn(r, m, cond.Field)
			out.Conditions[i] = cond
		}
	}
	if expr.Children != nil {
		out.Children = make([]*clause.Expression, len(expr.Children))
		for i, child := range expr.Children {
			out.Children[i] = physicalExpression(r, m, child)
		}
	}
	return out
}
