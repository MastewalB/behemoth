package core

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/types"
)

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

type TableSchema struct {
	Name         string
	PhysicalName string
	Columns      []Column
	Indexes      []Index
	ForeignKeys  []ForeignKey
	Owner        string // plugin name: injected by scopedSchemaRegistry
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

type OperationKind string

const (
	OpCreateTable    OperationKind = "create_table"
	OpDropTable      OperationKind = "drop_table"
	OpAddColumn      OperationKind = "add_column"
	OpDropColumn     OperationKind = "drop_column"
	OpRenameColumn   OperationKind = "rename_column"
	OpAlterColumn    OperationKind = "alter_column" // type/nullable/default change on an existing column
	OpAddIndex       OperationKind = "add_index"
	OpDropIndex      OperationKind = "drop_index"
	OpAddForeignKey  OperationKind = "add_foreign_key"
	OpDropForeignKey OperationKind = "drop_foreign_key"
)

type SchemaOperation struct {
	ID    string // unique within one Migration. e.g. "create_table_users"
	Kind  OperationKind
	Table string // table this operation targets; Also the primary signal auto-dependency-inference reads

	// Only the field(s) relevant to Kind are populated. documented per Kind
	NewTable       *TableSchema // OpCreateTable
	Column         *Column      // OpAddColumn, OpAlterColumn
	ColumnName     string       // OpDropColumn, OpRenameColumn (old name)
	NewColumnName  string       // OpRenameColumn
	PrevColumn     *Column      // OpAlterColumn: the old column definition being replaced, needed to invert the change for Down
	Index          *Index       // OpAddIndex
	IndexName      string       // OpDropIndex
	ForeignKey     *ForeignKey  // OpAddForeignKey
	ForeignKeyName string       // OpDropForeignKey

	// DependsOn: explicit operation IDs. an escape hatch layered on top of
	// automatic same-table inference
	DependsOn []string

	// Confirmed: must be true for any Drop*/Rename* kind before
	// MigrationGenerator will freeze it into a Migration
	// destructive/ambiguous operations require explicit developer confirmation
	// ignored for purely additive kinds.
	Confirmed bool
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

type ColumnDivergenceKind string

const (
	ColMatch       ColumnDivergenceKind = "match"
	ColMissingLive ColumnDivergenceKind = "missing_live" // declared, not found live
	ColExtraLive   ColumnDivergenceKind = "extra_live"   // found live, not declared
	ColDiffers     ColumnDivergenceKind = "differs"
)

type ColumnFinding struct {
	Name          string
	Kind          ColumnDivergenceKind
	Declared      *Column
	Live          *Column
	TypeAmbiguity *ColumnAmbiguity // set only when Kind != ColMissingLive and the reverse type mapping was a guess
}

type RenameCandidate struct {
	From      Column // live-only column
	To        Column // declared-only column
	Ambiguous bool
	GroupID   string // shared by every column involved in one ambiguous group; "" when Ambiguous is false
}

type IndexDivergenceKind string

const (
	IdxMatch   IndexDivergenceKind = "match"
	IdxMissing IndexDivergenceKind = "missing_live"
	IdxExtra   IndexDivergenceKind = "extra_live"
	IdxDiffers IndexDivergenceKind = "differs"
)

type IndexFinding struct {
	Name     string
	Kind     IndexDivergenceKind
	Declared *Index
	Live     *Index
}

type ForeignKeyDivergenceKind string

const (
	FKMatch   ForeignKeyDivergenceKind = "match"
	FKMissing ForeignKeyDivergenceKind = "missing_live"
	FKExtra   ForeignKeyDivergenceKind = "extra_live"
	FKDiffers ForeignKeyDivergenceKind = "differs"
)

type ForeignKeyFinding struct {
	Name     string
	Kind     ForeignKeyDivergenceKind
	Declared *ForeignKey
	Live     *ForeignKey
}

type TableIntrospection struct {
	Table              string
	ExistsLive         bool
	IncompatibleObject bool // manifesto: "Table found live as incompatible object" branch
	Columns            []ColumnFinding
	Renames            []RenameCandidate
	Indexes            []IndexFinding
	ForeignKeys        []ForeignKeyFinding
}

// IntrospectionReport returns the introspection output for each table declared
// The canonical(declared) name is used as key in the report.
// extra live tables are not included in the report.
type IntrospectionReport struct {
	Tables map[string]TableIntrospection
}

// BaselineFieldOption is BaselineIssue's counterpart to ResolutionOption —
// resolving to a canonical field definition instead of a SchemaOperation,
// since there is nothing to "operate" on yet; the table doesn't exist in
// any canonical form until this decision produces one.
type BaselineFieldOption struct {
	Label  string
	Column *Column // for a column-ambiguity issue
	// Table is left for a future table-level issue kind (see Step 3, table
	// existing-as-incompatible-object case) — not populated by anything in
	// this round, since that case is already a hard failure in BuildPlan's
	// sibling logic, not a resolvable option.
}

// BaselineIssue mirrors PlanIssue's shape deliberately (ID/Description/
// Options/Default) so ResolveBaselineIssues below is structurally almost
// identical to ResolveIssues — same review discipline, same stable-ID
// persistence story, different resolved payload type.
type BaselineIssue struct {
	ID          string
	Table       string
	Description string
	Options     []BaselineFieldOption
	Default     int
}

type BaselineCandidate struct {
	Table   string
	Current TableSchema // from SchemaRegistry(current) — what the app DECLARES this table should look like
}

// ResolvedBaseline is what Step 3 hands to Step 4 — every introspected
// table's FINAL canonical shape, with every ambiguity already resolved.
// This is the baseline-flow analogue of ResolvedOperationSet: a type that,
// by construction, cannot carry an unresolved decision.
type ResolvedBaseline struct {
	Tables map[string]TableSchema
}

type MigrationGenerator interface {
	// Generate resolves plan's dependency graph (PlannedOperations + Custom,
	// combined) via KahnSort, validates every Confirmed requirement is
	// satisfied, and freezes the result into one new Migration.
	Generate(resolvedPlan *ResolvedOperationSet, previousMigrationID string) (*Migration, error)
}

// MigrationRunner
type MigrationRunner interface {
	// Pending computes onDisk - ledger, ordered by DependsOn (KahnSort)
	Pending(ctx context.Context, onDisk []Migration) ([]Migration, error)

	// Apply runs each pending Migration's Up operations through the driver,
	// and writes the ledger row and updates SchemaSnapshot in the same transaction.
	// A failure mid-migration rolls back both the DDL (where the underlying
	// DB supports transactional DDL) and the ledger/snapshot writes together.
	Apply(ctx context.Context, migrations []Migration) error

	LoadSnapshot(ctx context.Context) (SchemaSnapshot, error)
}

type GenerateDeps struct {
	Introspector SchemaIntrospector // required for PathGenerateOnly; unused for PathManaged
	Runner       MigrationRunner    // required for PathManaged; unused for PathGenerateOnly
	Presenter    ResolutionPresenter
	Generator    MigrationGenerator
	Renderer     MigrationRenderer // optional; nil = no script file next to each migration's .json
}

type MigrationDeps struct {
	Introspector SchemaIntrospector
	Runner       MigrationRunner
	GenerateDeps GenerateDeps        // reused as-is from the Path I/II round. Presenter/Generator live here
	Presenter    ResolutionPresenter // duplicated reference for baseline's own resolve call — same underlying FilePresenter instance as GenerateDeps.Presenter, not a second one
	Telemetry    *types.Telemetry    // optional; used for non-fatal warnings (e.g. a script file that couldn't be written after Apply)
}

type MigrationConfig struct {
	FolderPath string // where generated migration files are written/read from
	TableName  string // For PathManaged only base name for the ledger table; snapshot table is derived from it
	Path       MigrationPath
}

// snapshotTableName derives the second table PathManaged needs from the
// single configured TableName, rather than requiring a second config value
// the user never asked for.
func (c MigrationConfig) snapshotTableName() string { return c.TableName + "_snapshot" }

// SchemaResolver is defined next to behemoth.Model so storage adapters can
// resolve physical names without depending on the migration package.
type SchemaResolver = behemoth.SchemaResolver

// ConditionValueTransformer provides a way to customize clause conditions.
// If models have fields that have different operator semantics at database level, they can change the clause
// to match their correct type semantics.
// Optional: discovered via type assertion, same pattern as Serializable.
type ConditionValueTransformer interface {
	// TransformCondition can rewrite both the value and the operator/field
	// shape of a condition. This matters for cases like
	// OpContains against a column that is physically a BIGINT: the
	// transform must reject or rewrite the operator itself.
	TransformCondition(cond clause.Condition) (clause.Condition, error)
}

// MigrationPlanner / MigrationPlan - the diff stage

type PlannedOperation struct {
	Operation SchemaOperation
	Source    string // "generated" (from the differ) or "manual"
}

// CustomMigration is a hand-authored migration ordered in the dependency graph as generated operations
//
// complex multi-step change or a data backfill can be applied via CustomMigrations
type CustomMigration struct {
	Name      string
	Up        []SchemaOperation
	Down      []SchemaOperation
	DependsOn []string // may reference generated operation IDs or other custom migrations by Name
}

// MigrationGenerator / Migration - the freeze stage

// Migration is the immutable, named, frozen artifact.
// once generated and written to disk, its Up/Down are fixed.
// This is the only source read by MigrationRunner to decide what DDL to execute
type Migration struct {
	ID        string // sortable, filename-derived. e.g. "0002_add_email_verified"
	Name      string
	Up        []SchemaOperation // already topologically ordered by MigrationGenerator, via KahnSort over Table/DependsOn edges
	Down      []SchemaOperation // reverse operations; may be shorter than Up or absent entirely for irreversible changes (e.g. a Confirmed OpDropColumn has no safe automatic Down)
	DependsOn []string          // other Migration IDs. ordinarily just the immediately preceding one, but the field allows non-linear history later
	CreatedAt time.Time

	IsBaseline bool // true = record-only; MigrationRunner must not execute Up as DDL
}

type ColumnAmbiguity struct {
	Column string
	// "no length specified on varchar; assumed 255"
	// "cannot determine NOT NULL from driver metadata"
	// "vendor-specific type 'jsonb' mapped to canonical TypeJSON"
	Reason string
}

// incompatible-object detection declaration
type ObjectKind string

const (
	ObjectTable ObjectKind = "table"
	ObjectView  ObjectKind = "view"
	ObjectOther ObjectKind = "other"
)

type IntrospectedTable struct {
	Schema      TableSchema // best-effort reverse mapping, never auto-trusted
	Ambiguities []ColumnAmbiguity
	Kind        ObjectKind
	Exists      bool // false if the table wasn't found live
}

type SchemaIntrospector interface {
	// TableExists is a cheap existence check, used for the partition step
	TableExists(ctx context.Context, name string) (bool, error)

	// Introspect performs the full reverse-mapping, one table at a time
	Introspect(ctx context.Context, name string) (IntrospectedTable, error)
}

type MigrationPath string

const (
	// PathManaged: behemoth owns generation AND application — its own
	// ledger + snapshot tables, per the original Path I design.
	PathManaged MigrationPath = "managed"

	// PathGenerateOnly: behemoth only produces a Migration file/stdout
	// output; the developer's own tool (goose, golang-migrate, Atlas, ...)
	// owns application. No ledger/snapshot table is ever created or
	// consulted in this mode.
	PathGenerateOnly MigrationPath = "generate_only"
)

// ResolvedOperationSet is what Resolution hands to Generation. Every
// operation in it is final — Generation has no concept of "tier" and no
// mechanism for asking anyone anything. This type existing at all is what
// makes the Resolution/Generation boundary a real compile-time boundary
// rather than a documentation-only convention a future contributor could
// accidentally violate by wiring Planning's raw output straight into Generate.
type ResolvedOperationSet struct {
	Operations []SchemaOperation // no Tier, no Confirmed field needed here — those concepts don't exist past Resolution
	Custom     []CustomMigration
}

type ResolutionPresenter interface {
	// Present writes/updates whatever medium holds unresolved issues,
	// alongside issues already resolved in a prior run (so a partial
	// resolution session is never silently discarded).
	Present(ctx context.Context, issues []PlanIssue, priorDecisions map[string]int) error
	// Collect reads back developer decisions, keyed by PlanIssue.ID.
	Collect(ctx context.Context) (decisions map[string]int, err error)
}
