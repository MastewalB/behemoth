package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/MastewalB/behemoth"
)

// Field is a typed key for one column contributed to a table — the way a
// plugin or an application declares, reads and writes a column of a table it
// doesn't own (two_factor_enabled on users, plan on users, ...) without raw
// column-name strings or untyped values.
//
//	var TwoFactorEnabled = schema.Field[bool]{Table: "users", Name: "two_factor_enabled"}
//
//	ic.Schemas.ExtendColumn(TwoFactorEnabled.Contribution(schema.Column{Type: schema.ColTypeBoolean, Default: false}))
//	on, _, err := TwoFactorEnabled.Get(user)
//	changes, err := TwoFactorEnabled.Update(true) // for Store.UpdateUser
//
// The value lives in the model's extras (behemoth.Extensible). Get converts
// what drivers actually return — SQLite's 0/1 for a boolean, []byte for
// text, int64 for any integer, float64 after a JSON round trip — and Decode
// and Encode replace those conversions for a type they don't cover (an enum,
// a database-specific type).
type Field[T any] struct {
	Table string // canonical table name
	Name  string // canonical column name

	// Decode converts the raw stored value into T. nil: built-in conversions.
	Decode func(raw any) (T, error)
	// Encode converts T into the value to store. nil: stored as-is.
	Encode func(v T) (any, error)
}

// Contribution declares the column: col with its Name set to the field's,
// for Registry.ExtendColumn.
func (f Field[T]) Contribution(col Column) ColumnContribution {
	col.Name = f.Name
	return ColumnContribution{Table: f.Table, Column: col}
}

// Get reads the field from m. ok is false when m carries no value for it (or
// a NULL); err reports a value that can't be converted to T, or m being a
// model of another table.
func (f Field[T]) Get(m behemoth.Extensible) (v T, ok bool, err error) {
	if err := f.check(m); err != nil {
		return v, false, err
	}
	raw, present := m.Extras()[f.Name]
	if !present || raw == nil {
		return v, false, nil
	}
	if f.Decode != nil {
		v, err = f.Decode(raw)
	} else {
		v, err = convert[T](raw)
	}
	if err != nil {
		return v, false, fmt.Errorf("schema.Field %s.%s: %w", f.Table, f.Name, err)
	}
	return v, true, nil
}

// Set writes v into m — e.g. on a model about to be created.
func (f Field[T]) Set(m behemoth.Extensible, v T) error {
	if err := f.check(m); err != nil {
		return err
	}
	stored, err := f.encode(v)
	if err != nil {
		return err
	}
	m.SetExtra(f.Name, stored)
	return nil
}

// Update returns the update map setting the field to v, for the store's
// update operations; merge several with maps.Copy.
func (f Field[T]) Update(v T) (behemoth.M, error) {
	stored, err := f.encode(v)
	if err != nil {
		return nil, err
	}
	return behemoth.M{f.Name: stored}, nil
}

func (f Field[T]) encode(v T) (any, error) {
	if f.Encode == nil {
		return v, nil
	}
	stored, err := f.Encode(v)
	if err != nil {
		return nil, fmt.Errorf("schema.Field %s.%s: %w", f.Table, f.Name, err)
	}
	return stored, nil
}

func (f Field[T]) check(m behemoth.Extensible) error {
	if m.SchemaName() != f.Table {
		return fmt.Errorf("schema.Field %s.%s used on a %s model", f.Table, f.Name, m.SchemaName())
	}
	return nil
}

// Normalize returns raw, a value a driver returned for col, as the Go type
// col declares: a bool for a boolean SQLite returned as 0 or 1, a string for
// text a driver returned as []byte, a time.Time for a timestamp stored as
// text, the document itself for a JSON column. A value it can't convert is
// returned as it is, and nil stays nil.
//
// It is for encoding a row for a client (types.PublicView), where the value
// has to look the same on every database. Typed access to one column goes
// through Field.
func Normalize(col Column, raw any) any {
	if raw == nil {
		return nil
	}
	switch col.Type {
	case ColTypeBoolean:
		if v, err := convert[bool](raw); err == nil {
			return v
		}
	case ColTypeString, ColTypeText, ColTypeUuid:
		if v, err := convert[string](raw); err == nil {
			return v
		}
	case ColTypeInteger, ColTypeBigInt:
		if v, err := convert[int64](raw); err == nil {
			return v
		}
	case ColTypeReal:
		if v, err := convert[float64](raw); err == nil {
			return v
		}
	case ColTypeDateTime, ColTypeTimestamp:
		if v, err := convert[time.Time](raw); err == nil {
			return v
		}
	case ColTypeJson:
		switch v := raw.(type) {
		case []byte:
			if json.Valid(v) {
				return json.RawMessage(v)
			}
		case string:
			if json.Valid([]byte(v)) {
				return json.RawMessage(v)
			}
		}
	case ColTypeBlob, ColTypeBytes:
		return raw // bytes are the value
	}
	if b, ok := raw.([]byte); ok {
		return string(b) // text a driver returned as bytes, such as a numeric
	}
	return raw
}

var timeType = reflect.TypeOf(time.Time{})

// convert maps a raw stored value onto T: the value itself if it already is
// a T, otherwise a lossless conversion by T's kind (named types included —
// a `type Plan string` converts like a string).
func convert[T any](raw any) (T, error) {
	var v T
	if t, ok := raw.(T); ok {
		return t, nil
	}
	target := reflect.ValueOf(&v).Elem()
	if b, ok := raw.([]byte); ok {
		raw = string(b) // drivers return text as []byte; parse it like a string
	}
	src := reflect.ValueOf(raw)

	fail := func() (T, error) {
		var zero T
		return zero, fmt.Errorf("can't convert %T to %T; give the Field a Decode", raw, v)
	}

	if target.Type() == timeType {
		if s, ok := raw.(string); ok {
			for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
				if t, err := time.Parse(layout, s); err == nil {
					target.Set(reflect.ValueOf(t))
					return v, nil
				}
			}
		}
		return fail()
	}

	switch target.Kind() {
	case reflect.String:
		if src.Kind() == reflect.String {
			target.SetString(src.String())
			return v, nil
		}
	case reflect.Bool:
		switch {
		case src.CanInt():
			if n := src.Int(); n == 0 || n == 1 {
				target.SetBool(n == 1)
				return v, nil
			}
		case src.Kind() == reflect.String:
			if b, err := strconv.ParseBool(src.String()); err == nil {
				target.SetBool(b)
				return v, nil
			}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch {
		case src.CanInt():
			if n := src.Int(); !target.OverflowInt(n) {
				target.SetInt(n)
				return v, nil
			}
		case src.CanFloat():
			if f := src.Float(); f == float64(int64(f)) && !target.OverflowInt(int64(f)) {
				target.SetInt(int64(f))
				return v, nil
			}
		case src.Kind() == reflect.String:
			if n, err := strconv.ParseInt(src.String(), 10, 64); err == nil && !target.OverflowInt(n) {
				target.SetInt(n)
				return v, nil
			}
		}
	case reflect.Float32, reflect.Float64:
		switch {
		case src.CanFloat():
			target.SetFloat(src.Float())
			return v, nil
		case src.CanInt():
			target.SetFloat(float64(src.Int()))
			return v, nil
		case src.Kind() == reflect.String:
			if f, err := strconv.ParseFloat(src.String(), 64); err == nil {
				target.SetFloat(f)
				return v, nil
			}
		}
	}
	return fail()
}
