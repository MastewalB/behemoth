package mysql

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// scanRow reads the current row of rows into Go values the models' FromMap
// understands: string, int64, float64, bool, time.Time, []byte or nil.
//
// The MySQL driver does not return those types by itself. A statement with
// arguments is answered in the binary protocol, where strings and times
// arrive as []byte. A statement without arguments is answered in the text
// protocol, where every value does, numbers included. Postgres and SQLite
// need no such step because their drivers convert by column type.
func scanRow(rows *sql.Rows, types []*sql.ColumnType) ([]any, error) {
	values := make([]any, len(types))
	ptrs := make([]any, len(types))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	for i, v := range values {
		converted, err := convertValue(types[i].DatabaseTypeName(), v)
		if err != nil {
			return nil, fmt.Errorf("column %s: %w", types[i].Name(), err)
		}
		values[i] = converted
	}
	return values, nil
}

// convertValue converts one scanned value by its column's type name, as the
// driver reports it ("VARCHAR", "DATETIME", "UNSIGNED BIGINT", ...).
//
// A TINYINT column is read as a bool, because that is how the migration
// driver stores a bool column (TINYINT(1)) and the display width is not
// available here. UNSIGNED TINYINT and the wider integer types stay int64.
func convertValue(typeName string, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	if typeName == "TINYINT" {
		n, err := toInt64(v)
		if err != nil {
			return nil, err
		}
		return n != 0, nil
	}

	switch strings.TrimPrefix(typeName, "UNSIGNED ") {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT", "YEAR":
		return toInt64(v)
	case "FLOAT", "DOUBLE":
		if b, ok := v.([]byte); ok {
			return strconv.ParseFloat(string(b), 64)
		}
		return v, nil
	case "DATETIME", "TIMESTAMP", "DATE":
		// Already a time.Time when the DSN has parseTime=true.
		if b, ok := v.([]byte); ok {
			return parseTime(string(b))
		}
		return v, nil
	case "BLOB", "TINYBLOB", "MEDIUMBLOB", "LONGBLOB", "BINARY", "VARBINARY", "BIT", "GEOMETRY":
		return v, nil
	}
	// CHAR, VARCHAR, the TEXT sizes, JSON, DECIMAL, ENUM, SET, TIME.
	if b, ok := v.([]byte); ok {
		return string(b), nil
	}
	return v, nil
}

// toInt64 converts an integer column's value: int64 or uint64 in the binary
// protocol, digits in the text protocol.
func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case uint64:
		return int64(n), nil
	case []byte:
		return strconv.ParseInt(string(n), 10, 64)
	}
	return 0, fmt.Errorf("unexpected %T for an integer column", v)
}

// parseTime parses MySQL's text form of a DATETIME, TIMESTAMP or DATE as UTC,
// the zone the driver writes a time.Time in unless the DSN sets loc. MySQL's
// zero date ("0000-00-00 ...") becomes the zero time.Time.
func parseTime(s string) (time.Time, error) {
	if strings.HasPrefix(s, "0000-00-00") {
		return time.Time{}, nil
	}
	layout := "2006-01-02 15:04:05.999999"
	if len(s) == len("2006-01-02") {
		layout = "2006-01-02"
	}
	return time.Parse(layout, s)
}
