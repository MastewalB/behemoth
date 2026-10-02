package core

import (
	"reflect"
	"strings"

	"github.com/MastewalB/behemoth/types/schema"
)

// A column's default has two forms: Column.Default, a literal value, and
// Overrides[driver].Default, a raw expression in that driver's language that
// wins over the literal. Introspectors report a live default the same way —
// a literal they could parse as Default, anything else under their own
// driver's override — and a driver's NormalizeColumn maps a declaration onto
// exactly that shape, keeping only its own override.

// hasDefault reports whether col declares or carries any default.
func hasDefault(col schema.Column) bool {
	if col.Default != nil {
		return true
	}
	for _, ov := range col.Overrides {
		if ov.Default != "" {
			return true
		}
	}
	return false
}

// defaultsEqual compares two columns' defaults: literals by value (numbers
// numerically), expressions per driver with sameExpression.
func defaultsEqual(a, b schema.Column) bool {
	if !literalsEqual(a.Default, b.Default) {
		return false
	}
	for driver := range a.Overrides {
		if !sameExpression(a.Overrides[driver].Default, b.Overrides[driver].Default) {
			return false
		}
	}
	for driver := range b.Overrides {
		if !sameExpression(a.Overrides[driver].Default, b.Overrides[driver].Default) {
			return false
		}
	}
	return true
}

// literalsEqual compares literal defaults. Numbers compare by value whatever
// their Go type: a declaration says 7 (int), an introspector reads int64(7),
// and a migration file round-tripped through JSON holds float64(7).
func literalsEqual(a, b any) bool {
	if fa, ok := asFloat(a); ok {
		fb, ok := asFloat(b)
		return ok && fa == fb
	}
	return reflect.DeepEqual(a, b)
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// sameExpression compares raw default expressions the way databases rewrite
// them when storing: case-insensitively, ignoring whitespace and parentheses
// enclosing the whole expression — Postgres stores NOW() as now() and (1+1)
// as (1 + 1). Quoted strings and quoted identifiers are compared exactly.
func sameExpression(a, b string) bool {
	return canonicalExpression(a) == canonicalExpression(b)
}

func canonicalExpression(expr string) string {
	var out strings.Builder
	var quote byte // the open quote character, or 0 outside quotes
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			out.WriteByte(c)
			if c == quote {
				quote = 0 // a doubled quote reopens on the next byte, keeping it verbatim
			}
		case c == '\'' || c == '"':
			quote = c
			out.WriteByte(c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			// dropped
		default:
			out.WriteString(strings.ToLower(string(c)))
		}
	}
	return stripEnclosingParens(out.String())
}

// stripEnclosingParens removes parentheses that enclose the whole expression,
// repeatedly: "((now()))" -> "now()", while "(a)+(b)" is left alone.
func stripEnclosingParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		encloses := true
		for i := 0; i < len(s)-1; i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				encloses = false // the first paren closes before the end
				break
			}
		}
		if !encloses {
			break
		}
		s = s[1 : len(s)-1]
	}
	return s
}
