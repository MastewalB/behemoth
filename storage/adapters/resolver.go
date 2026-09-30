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

// physicalDocument returns a copy of doc (canonical keys, e.g. from ToMap or
// an update map) keyed by physical field names — for document stores, where
// the stored keys are the names.
func physicalDocument(r behemoth.SchemaResolver, m behemoth.Model, doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[physicalColumn(r, m, k)] = v
	}
	return out
}

// canonicalFields maps m's physical field names back to canonical ones.
//
// The resolver only maps canonical -> physical, so the canonical side comes
// from the model itself: the keys of an empty model's ToMap(), the same
// source the SQL adapters derive their column lists from. Only renamed fields
// are included.
func canonicalFields(r behemoth.SchemaResolver, m behemoth.Model) map[string]string {
	out := map[string]string{}
	ser, ok := m.New().(behemoth.Serializable)
	if !ok {
		return out
	}
	fields, err := ser.ToMap()
	if err != nil {
		return out
	}
	for canonical := range fields {
		if physical := physicalColumn(r, m, canonical); physical != canonical {
			out[physical] = canonical
		}
	}
	return out
}

// canonicalDocument rewrites a stored document's physical keys to canonical
// ones before it is handed to FromMap. Keys the model doesn't declare (e.g.
// Mongo's _id) pass through unchanged. raw is not modified.
func canonicalDocument(canonical map[string]string, raw map[string]any) map[string]any {
	if len(canonical) == 0 {
		return raw
	}
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		if c, ok := canonical[k]; ok {
			k = c
		}
		out[k] = v
	}
	return out
}
