package adapters

import (
	"sort"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
)

// Name resolution shared by every adapter — exported so adapters living in
// their own modules (e.g. storage/adapters/postgres) resolve names identically.
//
// Models speak canonical names: SchemaName(), the keys of ToMap(), clause
// fields, PrimaryKeyName(). Only the SQL text an adapter sends to the database
// uses physical names; rows are still handed to FromMap under canonical keys,
// so models never see a physical name.

// ResolverOrIdentity returns r, or an identity resolver when r is nil.
func ResolverOrIdentity(r behemoth.SchemaResolver) behemoth.SchemaResolver {
	if r == nil {
		return behemoth.IdentityResolver{}
	}
	return r
}

// PhysicalTable returns m's physical table name.
func PhysicalTable(r behemoth.SchemaResolver, m behemoth.Model) string {
	return r.Resolve(m.SchemaName())
}

// PhysicalColumn returns the physical name of one of m's canonical columns.
func PhysicalColumn(r behemoth.SchemaResolver, m behemoth.Model, column string) string {
	return r.ResolveColumn(m.SchemaName(), column)
}

// PhysicalColumns resolves canonical column names, preserving order, so the
// result can be zipped back against the canonical slice.
func PhysicalColumns(r behemoth.SchemaResolver, m behemoth.Model, columns []string) []string {
	out := make([]string, len(columns))
	for i, c := range columns {
		out[i] = PhysicalColumn(r, m, c)
	}
	return out
}

// PhysicalExpression returns a copy of expr with every condition field — in
// nested children too — resolved to its physical column. expr is not modified.
func PhysicalExpression(r behemoth.SchemaResolver, m behemoth.Model, expr *clause.Expression) *clause.Expression {
	if expr == nil {
		return nil
	}
	out := &clause.Expression{Logic: expr.Logic}
	if expr.Conditions != nil {
		out.Conditions = make([]clause.Condition, len(expr.Conditions))
		for i, cond := range expr.Conditions {
			cond.Field = PhysicalColumn(r, m, cond.Field)
			out.Conditions[i] = cond
		}
	}
	if expr.Children != nil {
		out.Children = make([]*clause.Expression, len(expr.Children))
		for i, child := range expr.Children {
			out.Children[i] = PhysicalExpression(r, m, child)
		}
	}
	return out
}

// PhysicalDocument returns a copy of doc (canonical keys, e.g. from ToMap or
// an update map) keyed by physical field names — for document stores, where
// the stored keys are the names.
func PhysicalDocument(r behemoth.SchemaResolver, m behemoth.Model, doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[PhysicalColumn(r, m, k)] = v
	}
	return out
}

// CanonicalFields maps m's physical field names back to canonical ones.
//
// The resolver only maps canonical -> physical, so the canonical side comes
// from the columns ReadColumns lists: the table's declared columns,
// contributions included, or m's own ToMap keys. Only renamed fields are
// included.
func CanonicalFields(r behemoth.SchemaResolver, m behemoth.Model) map[string]string {
	out := map[string]string{}
	for _, canonical := range ReadColumns(r, m, nil) {
		if physical := PhysicalColumn(r, m, canonical); physical != canonical {
			out[physical] = canonical
		}
	}
	return out
}

// CanonicalDocument rewrites a stored document's physical keys to canonical
// ones before it is handed to FromMap. Keys the model doesn't declare (e.g.
// Mongo's _id) pass through unchanged. raw is not modified.
func CanonicalDocument(canonical map[string]string, raw map[string]any) map[string]any {
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

// ReadColumns lists the canonical columns to read for m's table: the
// resolver's declared columns when it knows the table — including columns
// other declarers contributed, which m's own fields don't cover — or m's own
// ToMap keys otherwise, sorted so the query text is stable. With selected
// (QueryOptions.Select), only those of them, in that order.
func ReadColumns(r behemoth.SchemaResolver, m behemoth.Model, selected []string) []string {
	columns := r.Columns(m.SchemaName())
	if len(columns) == 0 {
		if ser, ok := m.New().(behemoth.Serializable); ok {
			if row, err := ser.ToMap(); err == nil {
				for k := range row {
					columns = append(columns, k)
				}
				sort.Strings(columns)
			}
		}
	}
	if len(selected) == 0 {
		return columns
	}
	known := make(map[string]bool, len(columns))
	for _, c := range columns {
		known[c] = true
	}
	var out []string
	for _, c := range selected {
		if known[c] {
			out = append(out, c)
		}
	}
	return out
}

// ScanTargets allocates n scan destinations: values, and pointers to them to
// pass to Scan.
func ScanTargets(n int) (values []any, ptrs []any) {
	values = make([]any, n)
	ptrs = make([]any, n)
	for i := range values {
		ptrs[i] = &values[i]
	}
	return values, ptrs
}
