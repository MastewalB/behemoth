package mysql

import (
	"testing"
	"time"
)

func TestConvertValue(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	cases := []struct {
		name     string
		typeName string
		in       any
		want     any
	}{
		{"null", "VARCHAR", nil, nil},
		{"varchar", "VARCHAR", []byte("ada"), "ada"},
		{"text", "TEXT", []byte("long"), "long"},
		{"json", "JSON", []byte(`{"a":1}`), `{"a":1}`},
		{"decimal", "DECIMAL", []byte("1.50"), "1.50"},
		{"blob stays bytes", "BLOB", []byte{1, 2}, []byte{1, 2}},
		{"bool, binary protocol", "TINYINT", int64(1), true},
		{"bool, text protocol", "TINYINT", []byte("0"), false},
		{"unsigned tinyint is a number", "UNSIGNED TINYINT", int64(7), int64(7)},
		{"bigint, binary protocol", "BIGINT", int64(21), int64(21)},
		{"bigint, text protocol", "BIGINT", []byte("21"), int64(21)},
		{"unsigned bigint", "UNSIGNED BIGINT", uint64(21), int64(21)},
		{"double, text protocol", "DOUBLE", []byte("0.5"), 0.5},
		{"datetime", "DATETIME", []byte("2026-10-01 12:00:00.123456"), at},
		{"datetime without fraction", "DATETIME", []byte("2026-10-01 12:00:00"), at.Truncate(time.Second)},
		{"date", "DATE", []byte("2026-10-01"), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"zero date", "DATETIME", []byte("0000-00-00 00:00:00"), time.Time{}},
		{"datetime with parseTime", "DATETIME", at, at},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := convertValue(c.typeName, c.in)
			if err != nil {
				t.Fatal(err)
			}
			if gb, ok := got.([]byte); ok {
				if wb, ok := c.want.([]byte); !ok || string(gb) != string(wb) {
					t.Fatalf("got %v, want %v", got, c.want)
				}
				return
			}
			if gt, ok := got.(time.Time); ok {
				if wt, ok := c.want.(time.Time); !ok || !gt.Equal(wt) {
					t.Fatalf("got %v, want %v", got, c.want)
				}
				return
			}
			if got != c.want {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}

	if _, err := convertValue("DATETIME", []byte("not a time")); err == nil {
		t.Fatal("a malformed time is an error")
	}
}
