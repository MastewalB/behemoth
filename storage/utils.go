package storage

import (
	"database/sql"
	"fmt"
	"reflect"
	"strings"

	"github.com/MastewalB/behemoth"
)
type ScannableRow interface {
    Scan(dest ...any) error
}
// Helper function to get column names from the table
func getSQLiteColumnNames(db *sql.DB, table string) ([]string, error) {
	query := fmt.Sprintf(`PRAGMA table_info(%s)`, table)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func getPGColumnNames(db *sql.DB, table string) ([]string, error) {
	query := `
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1
        ORDER BY ordinal_position
    `
	rows, err := db.Query(query, table)
	if err != nil {
		return nil, fmt.Errorf("query column names: %w", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan column name: %w", err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return columns, nil
}

func mapRowToStruct[T any](row ScannableRow, entity T, columns []string) (T, error) {

	// Check if T is a struct or a pointer to a struct
	entityType := reflect.TypeOf(entity)
	if entityType == nil {
		return entity, fmt.Errorf("entity is nil or invalid")
	}

	// Handle pointer types
	isPointer := entityType.Kind() == reflect.Ptr
	structType := entityType
	if isPointer {
		structType = entityType.Elem()
		if structType.Kind() != reflect.Struct {
			return entity, fmt.Errorf("entity must be a struct or pointer to a struct, got %v", entityType.Kind())
		}
		// Initialize the pointer if it’s nil
		if reflect.ValueOf(entity).IsNil() {
			entity = reflect.New(structType).Interface().(T)
		}
	} else if structType.Kind() != reflect.Struct {
		return entity, fmt.Errorf("entity must be a struct, got %v", entityType.Kind())
	}

	// Use reflection to get the fields of T
	entityValue := reflect.ValueOf(&entity).Elem()
	// If T is a pointer, dereference entityValue to get the struct
	if isPointer {
		entityValue = entityValue.Elem()
	}

	dest := make([]any, len(columns))
	fields := make(map[string]reflect.Value)
	for i := range structType.NumField() {
		field := structType.Field(i)
		colName := field.Tag.Get("db")
		if colName == "" {
			colName = strings.ToLower(field.Name)
		}
		fields[colName] = entityValue.Field(i)
	}
	// Match columns to struct fields
	for i, col := range columns {
		if field, ok := fields[col]; ok && field.CanSet() {
			dest[i] = field.Addr().Interface()
			// fmt.Println("Mapping column", col, "to field", col)
		} else {
			var dummy any
			dest[i] = &dummy
			fmt.Println("No matching field for column", col)
		}
	}

	// Scan the row into the destination slice
	err := row.Scan(dest...)
	if err != nil {
		fmt.Println("Scan error:", err)
		return entity, err
	}

	// fmt.Println("Entity:", entity, "Error:", err)
	return entity, nil
}

// serializeSession converts a Session to JSON for storage.
func serializeSession(session behemoth.Session) ([]byte, error) {
	return session.MarshalJSON()
}

// deserializeSession reconstructs a Session from JSON data.
func deserializeSession(sessionID string, data []byte, factory behemoth.SessionFactory) (behemoth.Session, error) {
	session := factory(sessionID)
	if err := session.UnmarshalJSON(data); err != nil {
		return nil, err
	}

	return session, nil
}
