package behemothotel

import (
	"fmt"
	"slices"

	"github.com/MastewalB/behemoth"
	"go.opentelemetry.io/otel/attribute"
)

// attributes converts behemoth's attribute map to OpenTelemetry's typed
// key-values, in key order. Strings, booleans, integers and floats keep
// their type; anything else is formatted as a string.
func attributes(attrs behemoth.M) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]attribute.KeyValue, len(keys))
	for i, k := range keys {
		switch v := attrs[k].(type) {
		case string:
			out[i] = attribute.String(k, v)
		case bool:
			out[i] = attribute.Bool(k, v)
		case int:
			out[i] = attribute.Int(k, v)
		case int64:
			out[i] = attribute.Int64(k, v)
		case float64:
			out[i] = attribute.Float64(k, v)
		case fmt.Stringer:
			out[i] = attribute.String(k, v.String())
		default:
			out[i] = attribute.String(k, fmt.Sprint(v))
		}
	}
	return out
}
