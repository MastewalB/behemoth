package types

import (
	"fmt"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types/schema"
)

// PublicView builds what a client is sent of a row: the columns its table
// declares Public (schema.Column), and no others. A route that returns a
// user answers with PublicView.Of(user) and never with the model itself,
// which as JSON carries every column a plugin contributed.
//
// It is to responses what hook payloads are to handlers, with one
// difference: a payload has every column, because a handler runs on the
// server, and a view has the public ones, because it leaves it.
//
// AuthContext.Public is the view of the declared schema. It is an interface
// so that an application can wrap it, to decide per request what a viewer
// may see, for example; that is not built.
type PublicView interface {
	// Of returns m's public columns, keyed by column name and flat: a
	// contributed column sits next to the table's own. Values are in the Go
	// type their column declares, so the JSON is the same on every database.
	// A model whose table was never declared is an error, not an empty or a
	// full view.
	Of(m behemoth.Model) (behemoth.M, error)
}

// schemaPublicView is the PublicView of a set of declared tables.
type schemaPublicView struct {
	// tables maps a canonical table name to its public columns by name. A
	// declared table with no public column has an empty entry.
	tables map[string]map[string]schema.Column
}

// NewPublicView returns the view of tables: the merged tables of a frozen
// schema.Registry (Registry.All), contributions included. Boot builds
// AuthContext.Public with it.
func NewPublicView(tables []schema.Table) PublicView {
	v := &schemaPublicView{tables: make(map[string]map[string]schema.Column, len(tables))}
	for _, t := range tables {
		public := map[string]schema.Column{}
		for _, c := range t.Columns {
			if c.Public {
				public[c.Name] = c
			}
		}
		v.tables[t.Name] = public
	}
	return v
}

// Of implements [PublicView].
func (v *schemaPublicView) Of(m behemoth.Model) (behemoth.M, error) {
	const op = "PublicView.Of"
	if m == nil {
		return nil, behemotherr.NewConfigurationError(op, "no model to build a view of", nil)
	}
	public, declared := v.tables[m.SchemaName()]
	if !declared {
		return nil, behemotherr.NewConfigurationError(op,
			fmt.Sprintf("table %q is not declared, so none of its columns is known to be public", m.SchemaName()), nil)
	}
	s, ok := m.(behemoth.Serializable)
	if !ok {
		return nil, behemotherr.NewConfigurationError(op, fmt.Sprintf("%T has no ToMap to build a view from", m), nil)
	}
	row, err := s.ToMap()
	if err != nil {
		return nil, err
	}
	view := make(behemoth.M, len(public))
	for name, col := range public {
		if raw, ok := row[name]; ok {
			view[name] = schema.Normalize(col, raw)
		}
	}
	return view, nil
}

var _ PublicView = (*schemaPublicView)(nil)
