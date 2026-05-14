package adapters

import "reflect"

// ToSlice is a helper function that safely converts any value to a slice of any.
// If the value is already a slice, it returns it as is. If it's a single value, it wraps it in a slice.
func ToSlice(value any) []any {
	rv := reflect.ValueOf(value)

	if rv.Kind() == reflect.Slice {
		slice := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			slice[i] = rv.Index(i).Interface()
		}
		return slice
	}
	return []any{value}
}
