package models

import "github.com/MastewalB/behemoth"

// Extension carries the values of columns other declarers contributed to a
// model's table (schema.Registry ExtendColumn) — a plugin adding
// two_factor_enabled to users, an application adding plan. Embedding it makes
// a model behemoth.Extensible. Typed access to one column goes through
// schema.Field.
//
// Encoded as JSON, a model has every one of these columns under "extra",
// whatever its declarer meant a client to see. That encoding is for
// behemoth's own storage (the session cache keeps sessions this way). A
// route answers with types.PublicView instead, which leaves out the columns
// that are not declared Public.
type Extension struct {
	Extra behemoth.M `json:"extra,omitempty"`
}

// Extras implements [behemoth.Extensible].
func (e *Extension) Extras() behemoth.M { return e.Extra }

// SetExtra implements [behemoth.Extensible].
func (e *Extension) SetExtra(column string, value any) {
	if e.Extra == nil {
		e.Extra = behemoth.M{}
	}
	e.Extra[column] = value
}

// mergeExtras adds the extras to row, the model's own columns winning (the
// registry rejects a contribution that reuses one, so they can't collide).
func (e *Extension) mergeExtras(row map[string]any) map[string]any {
	for k, v := range e.Extra {
		if _, own := row[k]; !own {
			row[k] = v
		}
	}
	return row
}

// collectExtras replaces the extras with every column of data that isn't one
// of the model's own.
func (e *Extension) collectExtras(data map[string]any, own map[string]bool) {
	e.Extra = nil
	for k, v := range data {
		if !own[k] {
			e.SetExtra(k, v)
		}
	}
}

func columnSet(columns ...string) map[string]bool {
	set := make(map[string]bool, len(columns))
	for _, c := range columns {
		set[c] = true
	}
	return set
}
