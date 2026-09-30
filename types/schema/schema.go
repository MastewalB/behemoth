// Package schema holds the definitions every part of behemoth shares when it
// talks about database tables: the shapes plugins and applications declare,
// and the Registry they declare them into.
//
// It sits below the types package so PluginInitContext can carry a Registry.
// It must never import github.com/MastewalB/behemoth/types — that would
// reintroduce the cycle this package exists to break. Migration planning,
// operations and running stay in migration/core.
package schema

type ColumnType string

const (
	ColTypeString    ColumnType = "string"
	ColTypeInteger   ColumnType = "int"
	ColTypeReal      ColumnType = "real"
	ColTypeNumeric   ColumnType = "numeric"
	ColTypeBigInt    ColumnType = "bigint"
	ColTypeText      ColumnType = "text"
	ColTypeUuid      ColumnType = "uuid"
	ColTypeBlob      ColumnType = "blob"
	ColTypeJson      ColumnType = "json"
	ColTypeDateTime  ColumnType = "datetime"
	ColTypeTimestamp ColumnType = "timestamp"
	ColTypeBoolean   ColumnType = "bool"
	ColTypeBytes     ColumnType = "bytes"
)

type Table struct {
	Name         string
	PhysicalName string
	Columns      []Column
	Indexes      []Index
	ForeignKeys  []ForeignKey
	Owner        string // plugin name: injected by the owner-scoped registry each declarer receives
}

type Column struct {
	Name         string
	PhysicalName string
	Type         ColumnType
	Length       int
	Nullable     bool
	Unique       bool
	PrimaryKey   bool

	Default any
	Check   string
	AutoInc bool

	// optional per-db overrides
	Overrides map[string]ColumnOverride
}

type Index struct {
	Name    string
	Columns []string
	Unique  bool
}

type ForeignKeyAction string

const (
	FKCascade  ForeignKeyAction = "cascade"
	FKRestrict ForeignKeyAction = "restrict"
	FKSetNull  ForeignKeyAction = "set_null"
)

type ForeignKey struct {
	Name       string
	Columns    []string
	RefTable   string
	RefColumns []string
	OnDelete   ForeignKeyAction
}

// ColumnOverride is used to override the default column property interpretations for a specific database.
//
// For eg. If a column has UUID type, the SQLite interpretation can be overriden to have type Text instead of the default BLOB,
//
//	ColumnOverride{
//		Type: Text,
//	}
type ColumnOverride struct {
	Type    ColumnType
	Default string
	Check   string
	AutoInc *bool
}

type ColumnContribution struct {
	Table  string
	Column Column
	Owner  string // injected
}

type IndexContribution struct {
	Table string
	Index Index
	Owner string
}

type ForeignKeyContribution struct {
	Table      string
	ForeignKey ForeignKey
	Owner      string
}
