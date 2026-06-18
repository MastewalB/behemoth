package adapters

import (
	"reflect"
	"runtime"
)

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

func WrapWithCaller(err error, entity string, wrapperFn func(string, string, error) error) error {

	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	caller := runtime.FuncForPC(pc[0])
	op := "unknown"
	if caller != nil {
		op = caller.Name()
	}

	return wrapperFn(op, entity, err)
}
