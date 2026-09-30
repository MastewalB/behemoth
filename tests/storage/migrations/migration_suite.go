package migrations

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/stretchr/testify/suite"
)

const (
	ledgerTable   = "behemoth_test_ledger"
	snapshotTable = "behemoth_test_ledger_snapshot"
)

// DriverFactory builds the driver under test. The suite passes its own
// resolver for the physical-name tests and nil everywhere else.
type DriverFactory func(resolver core.SchemaResolver) core.SchemaDriver

// DriverTestManager is the database-specific half of the suite: it inspects
// and seeds the database directly, without going through the driver under test.
type DriverTestManager interface {
	TableExists(ctx context.Context, table string) (bool, error)
	Columns(ctx context.Context, table string) ([]ColumnInfo, error)
	// Indexes returns every index on table, including ones backing constraints.
	Indexes(ctx context.Context, table string) ([]IndexInfo, error)
	ForeignKeys(ctx context.Context, table string) ([]ForeignKeyInfo, error)

	Insert(ctx context.Context, table string, row map[string]any) error
	Delete(ctx context.Context, table, column string, value any) error
	// Rows returns every row of table ordered by orderBy (a column name).
	Rows(ctx context.Context, table, orderBy string) ([]map[string]any, error)
	RowCount(ctx context.Context, table string) (int64, error)

	// LedgerIDs returns the recorded migration IDs in ascending order, or none
	// if the ledger table doesn't exist yet.
	LedgerIDs(ctx context.Context, ledgerTable string) ([]string, error)
	// Snapshot returns the persisted snapshot; found is false if the snapshot
	// table or its row doesn't exist.
	Snapshot(ctx context.Context, snapshotTable string) (snap core.SchemaSnapshot, found bool, err error)

	DropAllTables(ctx context.Context) error
	CleanupDatabase(ctx context.Context)
}

type ColumnInfo struct {
	Name       string
	Nullable   bool
	PrimaryKey bool
	HasDefault bool
}

type IndexInfo struct {
	Name    string
	Unique  bool
	Columns []string
}

type ForeignKeyInfo struct {
	Name       string
	Columns    []string
	RefTable   string
	RefColumns []string
	OnDelete   core.ForeignKeyAction
}

// DriverTestSuite is the database-agnostic contract every core.SchemaDriver
// must satisfy. Each test drives the driver only through ApplyMigration /
// RecordBaseline, exactly as core's MigrationRunner does, and verifies the
// outcome both structurally (via the manager) and behaviorally (constraints
// actually enforced, data actually preserved).
type DriverTestSuite struct {
	suite.Suite
	ctx       context.Context
	newDriver DriverFactory
	driver    core.SchemaDriver
	tm        DriverTestManager
	seq       int
}

// RunDriverTests runs the suite against a driver.
func RunDriverTests(t *testing.T, newDriver DriverFactory, tm DriverTestManager) {
	suite.Run(t, &DriverTestSuite{ctx: context.Background(), newDriver: newDriver, tm: tm})
}

func (s *DriverTestSuite) SetupTest() {
	s.Require().NoError(s.tm.DropAllTables(s.ctx), "failed to clean tables before test")
	s.driver = s.newDriver(nil)
	s.seq = 0
}

func (s *DriverTestSuite) TearDownSuite() {
	s.NoError(s.tm.DropAllTables(s.ctx))
	s.tm.CleanupDatabase(s.ctx)
}

// ---- Fixtures & helpers ----

func usersTable() core.TableSchema {
	return core.TableSchema{
		Name: "users",
		Columns: []core.Column{
			{Name: "id", Type: core.ColTypeInteger, PrimaryKey: true},
			{Name: "email", Type: core.ColTypeString, Length: 255, Unique: true},
			{Name: "name", Type: core.ColTypeText, Nullable: true},
			{Name: "status", Type: core.ColTypeString, Length: 32, Default: "active"},
		},
	}
}

func postsTable() core.TableSchema {
	return core.TableSchema{
		Name: "posts",
		Columns: []core.Column{
			{Name: "id", Type: core.ColTypeInteger, PrimaryKey: true},
			{Name: "user_id", Type: core.ColTypeInteger, Nullable: true},
			{Name: "title", Type: core.ColTypeText},
		},
	}
}

func postsUserFK(onDelete core.ForeignKeyAction) core.ForeignKey {
	return core.ForeignKey{Name: "fk_posts_user", Columns: []string{"user_id"}, RefTable: "users", RefColumns: []string{"id"}, OnDelete: onDelete}
}

func createTableOp(t core.TableSchema) core.SchemaOperation {
	return core.SchemaOperation{ID: "create_table_" + t.Name, Kind: core.OpCreateTable, Table: t.Name, NewTable: &t}
}

func dropTableOp(table string) core.SchemaOperation {
	return core.SchemaOperation{ID: "drop_table_" + table, Kind: core.OpDropTable, Table: table, Confirmed: true}
}

func addColumnOp(table string, col core.Column) core.SchemaOperation {
	return core.SchemaOperation{ID: "add_column_" + table + "_" + col.Name, Kind: core.OpAddColumn, Table: table, Column: &col}
}

func dropColumnOp(table, column string) core.SchemaOperation {
	return core.SchemaOperation{ID: "drop_column_" + table + "_" + column, Kind: core.OpDropColumn, Table: table, ColumnName: column, Confirmed: true}
}

func renameColumnOp(table, from, to string) core.SchemaOperation {
	return core.SchemaOperation{ID: "rename_column_" + table + "_" + from, Kind: core.OpRenameColumn, Table: table, ColumnName: from, NewColumnName: to, Confirmed: true}
}

func alterColumnOp(table string, col core.Column) core.SchemaOperation {
	return core.SchemaOperation{ID: "alter_column_" + table + "_" + col.Name, Kind: core.OpAlterColumn, Table: table, Column: &col}
}

func addIndexOp(table string, idx core.Index) core.SchemaOperation {
	return core.SchemaOperation{ID: "add_index_" + idx.Name, Kind: core.OpAddIndex, Table: table, Index: &idx}
}

func dropIndexOp(table, name string) core.SchemaOperation {
	return core.SchemaOperation{ID: "drop_index_" + name, Kind: core.OpDropIndex, Table: table, IndexName: name, Confirmed: true}
}

func addForeignKeyOp(table string, fk core.ForeignKey) core.SchemaOperation {
	return core.SchemaOperation{ID: "add_fk_" + fk.Name, Kind: core.OpAddForeignKey, Table: table, ForeignKey: &fk}
}

func dropForeignKeyOp(table, name string) core.SchemaOperation {
	return core.SchemaOperation{ID: "drop_fk_" + name, Kind: core.OpDropForeignKey, Table: table, ForeignKeyName: name, Confirmed: true}
}

func (s *DriverTestSuite) nextMigration(ops ...core.SchemaOperation) core.Migration {
	s.seq++
	return core.Migration{ID: fmt.Sprintf("%04d_test", s.seq), Name: "test", Up: ops, CreatedAt: time.Now()}
}

func request(m core.Migration, tables map[string]core.TableSchema) core.MigrationRequest {
	if tables == nil {
		tables = map[string]core.TableSchema{}
	}
	return core.MigrationRequest{
		Migration:      m,
		LedgerEntry:    core.MigrationLedgerEntry{ID: m.ID, AppliedAt: time.Now()},
		SnapshotUpdate: core.SchemaSnapshot{Version: m.ID, Tables: tables},
		LedgerTable:    ledgerTable,
		SnapshotTable:  snapshotTable,
	}
}

// apply runs ops as one migration through ApplyMigration.
func (s *DriverTestSuite) apply(ops ...core.SchemaOperation) error {
	return s.driver.ApplyMigration(s.ctx, request(s.nextMigration(ops...), nil))
}

func (s *DriverTestSuite) mustApply(ops ...core.SchemaOperation) {
	s.Require().NoError(s.apply(ops...))
}

func (s *DriverTestSuite) insert(table string, row map[string]any) {
	s.Require().NoError(s.tm.Insert(s.ctx, table, row), "seeding %s", table)
}

func (s *DriverTestSuite) tableExists(table string) bool {
	exists, err := s.tm.TableExists(s.ctx, table)
	s.Require().NoError(err)
	return exists
}

func (s *DriverTestSuite) columns(table string) map[string]ColumnInfo {
	cols, err := s.tm.Columns(s.ctx, table)
	s.Require().NoError(err)
	out := make(map[string]ColumnInfo, len(cols))
	for _, c := range cols {
		out[c.Name] = c
	}
	return out
}

func (s *DriverTestSuite) index(table, name string) (IndexInfo, bool) {
	idxs, err := s.tm.Indexes(s.ctx, table)
	s.Require().NoError(err)
	for _, i := range idxs {
		if i.Name == name {
			return i, true
		}
	}
	return IndexInfo{}, false
}

func (s *DriverTestSuite) foreignKey(table, name string) (ForeignKeyInfo, bool) {
	fks, err := s.tm.ForeignKeys(s.ctx, table)
	s.Require().NoError(err)
	for _, fk := range fks {
		if fk.Name == name {
			return fk, true
		}
	}
	return ForeignKeyInfo{}, false
}

func (s *DriverTestSuite) rows(table, orderBy string) []map[string]any {
	rows, err := s.tm.Rows(s.ctx, table, orderBy)
	s.Require().NoError(err)
	return rows
}

func (s *DriverTestSuite) rowCount(table string) int64 {
	n, err := s.tm.RowCount(s.ctx, table)
	s.Require().NoError(err)
	return n
}

func (s *DriverTestSuite) ledgerIDs() []string {
	ids, err := s.tm.LedgerIDs(s.ctx, ledgerTable)
	s.Require().NoError(err)
	return ids
}

// seedUsers creates users with two rows: one with a name, one without.
func (s *DriverTestSuite) seedUsers() {
	s.mustApply(createTableOp(usersTable()))
	s.insert("users", map[string]any{"id": 1, "email": "ada@example.com", "name": "Ada"})
	s.insert("users", map[string]any{"id": 2, "email": "bob@example.com"})
}

// seedUsersAndPosts creates users and posts linked by fk_posts_user.
func (s *DriverTestSuite) seedUsersAndPosts(onDelete core.ForeignKeyAction) {
	s.seedUsers()
	s.mustApply(createTableOp(postsTable()), addForeignKeyOp("posts", postsUserFK(onDelete)))
	s.insert("posts", map[string]any{"id": 10, "user_id": 1, "title": "first"})
	s.insert("posts", map[string]any{"id": 11, "user_id": 2, "title": "second"})
}

// asString / asInt64 normalize values across database/sql drivers, which
// variously return string or []byte, and int64 or float64.
func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int32:
		return int64(x)
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case []byte:
		var n int64
		fmt.Sscan(string(x), &n)
		return n
	case string:
		var n int64
		fmt.Sscan(x, &n)
		return n
	default:
		return 0
	}
}

// ---- OpCreateTable ----

func (s *DriverTestSuite) TestCreateTable() {
	s.mustApply(createTableOp(usersTable()))

	s.True(s.tableExists("users"))
	s.Equal(int64(0), s.rowCount("users"), "new table should be empty")

	cols := s.columns("users")
	s.Len(cols, 4)
	s.True(cols["id"].PrimaryKey)
	s.False(cols["email"].Nullable)
	s.True(cols["name"].Nullable)
	s.True(cols["status"].HasDefault)
	s.False(cols["email"].PrimaryKey)
}

func (s *DriverTestSuite) TestCreateTableEnforcesConstraints() {
	s.seedUsers()

	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": "ada@example.com"}), "UNIQUE email must be enforced")
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": nil}), "NOT NULL email must be enforced")
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 1, "email": "other@example.com"}), "PRIMARY KEY must be enforced")

	rows := s.rows("users", "id")
	s.Require().Len(rows, 2)
	s.Equal("active", asString(rows[0]["status"]), "DEFAULT must apply when the column is omitted")
}

func (s *DriverTestSuite) TestCreateTableCompositePrimaryKey() {
	s.mustApply(createTableOp(core.TableSchema{
		Name: "memberships",
		Columns: []core.Column{
			{Name: "user_id", Type: core.ColTypeInteger, PrimaryKey: true},
			{Name: "group_id", Type: core.ColTypeInteger, PrimaryKey: true},
			{Name: "role", Type: core.ColTypeString, Length: 16, Nullable: true},
		},
	}))

	cols := s.columns("memberships")
	s.True(cols["user_id"].PrimaryKey)
	s.True(cols["group_id"].PrimaryKey)
	s.False(cols["role"].PrimaryKey)

	s.insert("memberships", map[string]any{"user_id": 1, "group_id": 1})
	s.insert("memberships", map[string]any{"user_id": 1, "group_id": 2})
	s.Error(s.tm.Insert(s.ctx, "memberships", map[string]any{"user_id": 1, "group_id": 1}), "composite key must be enforced")
}

func (s *DriverTestSuite) TestCreateTableAutoIncrement() {
	s.mustApply(createTableOp(core.TableSchema{
		Name: "events",
		Columns: []core.Column{
			{Name: "id", Type: core.ColTypeBigInt, PrimaryKey: true, AutoInc: true},
			{Name: "kind", Type: core.ColTypeString, Length: 32},
		},
	}))

	s.insert("events", map[string]any{"kind": "a"})
	s.insert("events", map[string]any{"kind": "b"})

	rows := s.rows("events", "id")
	s.Require().Len(rows, 2)
	s.Equal(int64(1), asInt64(rows[0]["id"]))
	s.Equal(int64(2), asInt64(rows[1]["id"]))
}

func (s *DriverTestSuite) TestCreateTableAlreadyExistsFails() {
	s.mustApply(createTableOp(usersTable()))
	s.Error(s.apply(createTableOp(usersTable())))
}

// ---- OpDropTable ----

func (s *DriverTestSuite) TestDropTable() {
	s.seedUsers()
	s.mustApply(dropTableOp("users"))
	s.False(s.tableExists("users"))
}

func (s *DriverTestSuite) TestDropMissingTableFails() {
	s.Error(s.apply(dropTableOp("does_not_exist")))
}

// ---- OpAddColumn ----

func (s *DriverTestSuite) TestAddNullableColumn() {
	s.seedUsers()
	s.mustApply(addColumnOp("users", core.Column{Name: "bio", Type: core.ColTypeText, Nullable: true}))

	cols := s.columns("users")
	s.Require().Contains(cols, "bio")
	s.True(cols["bio"].Nullable)
	for _, r := range s.rows("users", "id") {
		s.Nil(r["bio"], "existing rows get NULL")
	}
}

func (s *DriverTestSuite) TestAddNotNullColumnWithDefault() {
	s.seedUsers()
	s.mustApply(addColumnOp("users", core.Column{Name: "score", Type: core.ColTypeInteger, Default: 7}))

	s.False(s.columns("users")["score"].Nullable)
	for _, r := range s.rows("users", "id") {
		s.Equal(int64(7), asInt64(r["score"]), "existing rows get the default")
	}
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": "c@example.com", "score": nil}))
}

func (s *DriverTestSuite) TestAddUniqueColumn() {
	s.seedUsers()
	s.mustApply(addColumnOp("users", core.Column{Name: "handle", Type: core.ColTypeString, Length: 64, Nullable: true, Unique: true}))

	s.Contains(s.columns("users"), "handle")
	s.Equal(int64(2), s.rowCount("users"), "existing rows are preserved")
	s.insert("users", map[string]any{"id": 3, "email": "c@example.com", "handle": "cee"})
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 4, "email": "d@example.com", "handle": "cee"}), "UNIQUE must be enforced")
}

func (s *DriverTestSuite) TestAddNotNullColumnWithoutDefaultOnPopulatedTableFails() {
	s.seedUsers()
	s.Error(s.apply(addColumnOp("users", core.Column{Name: "required", Type: core.ColTypeText})))
	s.NotContains(s.columns("users"), "required", "failed migration must leave no trace")
	s.Equal(int64(2), s.rowCount("users"))
}

// ---- OpDropColumn ----

func (s *DriverTestSuite) TestDropColumn() {
	s.seedUsers()
	s.mustApply(dropColumnOp("users", "name"))

	cols := s.columns("users")
	s.NotContains(cols, "name")
	s.Len(cols, 3)

	rows := s.rows("users", "id")
	s.Require().Len(rows, 2)
	s.Equal("ada@example.com", asString(rows[0]["email"]), "remaining data is preserved")
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": "ada@example.com"}), "other constraints survive")
}

func (s *DriverTestSuite) TestDropIndexedColumnDropsItsIndexes() {
	s.seedUsers()
	s.mustApply(
		addIndexOp("users", core.Index{Name: "idx_users_name", Columns: []string{"name"}}),
		addIndexOp("users", core.Index{Name: "idx_users_status", Columns: []string{"status"}}),
	)
	s.mustApply(dropColumnOp("users", "name"))

	_, found := s.index("users", "idx_users_name")
	s.False(found, "index on the dropped column goes with it")
	_, found = s.index("users", "idx_users_status")
	s.True(found, "unrelated indexes survive")
}

func (s *DriverTestSuite) TestDropMissingColumnFails() {
	s.seedUsers()
	s.Error(s.apply(dropColumnOp("users", "does_not_exist")))
}

// ---- OpRenameColumn ----

func (s *DriverTestSuite) TestRenameColumn() {
	s.seedUsers()
	s.mustApply(addIndexOp("users", core.Index{Name: "idx_users_name", Columns: []string{"name"}}))
	s.mustApply(renameColumnOp("users", "name", "full_name"))

	cols := s.columns("users")
	s.NotContains(cols, "name")
	s.Contains(cols, "full_name")

	rows := s.rows("users", "id")
	s.Equal("Ada", asString(rows[0]["full_name"]), "data follows the rename")

	idx, found := s.index("users", "idx_users_name")
	s.Require().True(found, "index survives the rename")
	s.Equal([]string{"full_name"}, idx.Columns)
}

// ---- OpAlterColumn ----

func (s *DriverTestSuite) TestAlterColumnNullability() {
	s.seedUsers()
	s.mustApply(alterColumnOp("users", core.Column{Name: "status", Type: core.ColTypeString, Length: 32, Nullable: true, Default: "active"}))
	s.True(s.columns("users")["status"].Nullable)
	s.insert("users", map[string]any{"id": 3, "email": "c@example.com", "status": nil})

	s.Require().NoError(s.tm.Delete(s.ctx, "users", "id", 3))
	s.mustApply(alterColumnOp("users", core.Column{Name: "status", Type: core.ColTypeString, Length: 32, Default: "active"}))
	s.False(s.columns("users")["status"].Nullable)
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 4, "email": "d@example.com", "status": nil}))
}

func (s *DriverTestSuite) TestAlterColumnToNotNullWithNullsFails() {
	s.seedUsers() // user 2 has a NULL name
	s.Error(s.apply(alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText})))

	s.True(s.columns("users")["name"].Nullable, "failed alter must be rolled back")
	s.Equal(int64(2), s.rowCount("users"))
}

func (s *DriverTestSuite) TestAlterColumnDefault() {
	s.seedUsers()
	s.mustApply(alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText, Nullable: true, Default: "anonymous"}))

	s.insert("users", map[string]any{"id": 3, "email": "c@example.com"})
	rows := s.rows("users", "id")
	s.Require().Len(rows, 3)
	s.Equal("Ada", asString(rows[0]["name"]), "existing values are preserved")
	s.Equal("anonymous", asString(rows[2]["name"]), "new default applies")

	s.mustApply(alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText, Nullable: true}))
	s.False(s.columns("users")["name"].HasDefault, "default is dropped")
}

func (s *DriverTestSuite) TestAlterColumnType() {
	s.seedUsers()
	s.mustApply(alterColumnOp("users", core.Column{Name: "status", Type: core.ColTypeText, Default: "active"}))

	rows := s.rows("users", "id")
	s.Require().Len(rows, 2)
	s.Equal("active", asString(rows[0]["status"]), "data survives a compatible type change")
}

func (s *DriverTestSuite) TestAlterColumnPreservesIndexesAndConstraints() {
	s.seedUsers()
	s.mustApply(addIndexOp("users", core.Index{Name: "idx_users_status", Columns: []string{"status"}}))
	s.mustApply(alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText, Nullable: true, Default: "x"}))

	_, found := s.index("users", "idx_users_status")
	s.True(found, "explicit index survives")
	s.True(s.columns("users")["id"].PrimaryKey, "primary key survives")
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": "ada@example.com"}), "UNIQUE on another column survives")
}

func (s *DriverTestSuite) TestAlterColumnPreservesForeignKeys() {
	s.seedUsersAndPosts(core.FKCascade)

	// Alter the child table, then the parent table.
	s.mustApply(alterColumnOp("posts", core.Column{Name: "title", Type: core.ColTypeText, Default: "untitled"}))
	s.mustApply(alterColumnOp("users", core.Column{Name: "status", Type: core.ColTypeString, Length: 64, Default: "active"}))

	_, found := s.foreignKey("posts", "fk_posts_user")
	s.Require().True(found, "foreign key survives both alters")
	s.Error(s.tm.Insert(s.ctx, "posts", map[string]any{"id": 12, "user_id": 99, "title": "orphan"}), "FK still enforced")

	s.Require().NoError(s.tm.Delete(s.ctx, "users", "id", 1))
	s.Equal(int64(1), s.rowCount("posts"), "ON DELETE CASCADE still fires")
}

func (s *DriverTestSuite) TestAlterMissingColumnFails() {
	s.seedUsers()
	s.Error(s.apply(alterColumnOp("users", core.Column{Name: "does_not_exist", Type: core.ColTypeText, Nullable: true})))
}

// ---- OpAddIndex / OpDropIndex ----

func (s *DriverTestSuite) TestAddIndex() {
	s.seedUsers()
	s.mustApply(addIndexOp("users", core.Index{Name: "idx_users_name_status", Columns: []string{"name", "status"}}))

	idx, found := s.index("users", "idx_users_name_status")
	s.Require().True(found)
	s.False(idx.Unique)
	s.Equal([]string{"name", "status"}, idx.Columns)
}

func (s *DriverTestSuite) TestAddUniqueIndex() {
	s.seedUsers()
	s.mustApply(addIndexOp("users", core.Index{Name: "uq_users_name", Columns: []string{"name"}, Unique: true}))

	idx, found := s.index("users", "uq_users_name")
	s.Require().True(found)
	s.True(idx.Unique)
	s.Error(s.tm.Insert(s.ctx, "users", map[string]any{"id": 3, "email": "c@example.com", "name": "Ada"}))
}

func (s *DriverTestSuite) TestAddUniqueIndexOnDuplicateDataFails() {
	s.seedUsers()
	s.Error(s.apply(addIndexOp("users", core.Index{Name: "uq_users_status", Columns: []string{"status"}, Unique: true})))
	_, found := s.index("users", "uq_users_status")
	s.False(found)
}

func (s *DriverTestSuite) TestDropIndex() {
	s.seedUsers()
	s.mustApply(addIndexOp("users", core.Index{Name: "idx_users_name", Columns: []string{"name"}}))
	s.mustApply(dropIndexOp("users", "idx_users_name"))

	_, found := s.index("users", "idx_users_name")
	s.False(found)
}

func (s *DriverTestSuite) TestDropMissingIndexFails() {
	s.seedUsers()
	s.Error(s.apply(dropIndexOp("users", "does_not_exist")))
}

// ---- OpAddForeignKey / OpDropForeignKey ----

func (s *DriverTestSuite) TestAddForeignKey() {
	s.seedUsersAndPosts(core.FKRestrict)

	fk, found := s.foreignKey("posts", "fk_posts_user")
	s.Require().True(found)
	s.Equal([]string{"user_id"}, fk.Columns)
	s.Equal("users", fk.RefTable)
	s.Equal([]string{"id"}, fk.RefColumns)
	s.Equal(core.FKRestrict, fk.OnDelete)

	s.Equal(int64(2), s.rowCount("posts"), "existing rows are preserved")
	s.Error(s.tm.Insert(s.ctx, "posts", map[string]any{"id": 12, "user_id": 99, "title": "orphan"}))
	s.Error(s.tm.Delete(s.ctx, "users", "id", 1), "ON DELETE RESTRICT blocks deleting a referenced parent")
}

func (s *DriverTestSuite) TestAddForeignKeyCascade() {
	s.seedUsersAndPosts(core.FKCascade)
	s.Require().NoError(s.tm.Delete(s.ctx, "users", "id", 1))

	rows := s.rows("posts", "id")
	s.Require().Len(rows, 1)
	s.Equal(int64(11), asInt64(rows[0]["id"]))
}

func (s *DriverTestSuite) TestAddForeignKeySetNull() {
	s.seedUsersAndPosts(core.FKSetNull)
	s.Require().NoError(s.tm.Delete(s.ctx, "users", "id", 1))

	rows := s.rows("posts", "id")
	s.Require().Len(rows, 2)
	s.Nil(rows[0]["user_id"])
}

func (s *DriverTestSuite) TestAddForeignKeyWithOrphanRowsFails() {
	s.seedUsers()
	s.mustApply(createTableOp(postsTable()))
	s.insert("posts", map[string]any{"id": 10, "user_id": 99, "title": "orphan"})

	s.Error(s.apply(addForeignKeyOp("posts", postsUserFK(core.FKCascade))))
	_, found := s.foreignKey("posts", "fk_posts_user")
	s.False(found, "failed migration must be rolled back")
	s.Equal(int64(1), s.rowCount("posts"))
}

func (s *DriverTestSuite) TestDropForeignKey() {
	s.seedUsersAndPosts(core.FKCascade)
	s.mustApply(dropForeignKeyOp("posts", "fk_posts_user"))

	_, found := s.foreignKey("posts", "fk_posts_user")
	s.False(found)
	s.Equal(int64(2), s.rowCount("posts"), "existing rows are preserved")
	s.insert("posts", map[string]any{"id": 12, "user_id": 99, "title": "orphan now allowed"})
}

func (s *DriverTestSuite) TestDropMissingForeignKeyFails() {
	s.seedUsers()
	s.mustApply(createTableOp(postsTable()))
	s.Error(s.apply(dropForeignKeyOp("posts", "does_not_exist")))
}

// ---- Migration semantics ----

func (s *DriverTestSuite) TestApplyRecordsLedgerAndSnapshot() {
	users := usersTable()
	first := s.nextMigration(createTableOp(users))
	s.Require().NoError(s.driver.ApplyMigration(s.ctx, request(first, map[string]core.TableSchema{"users": users})))

	s.Equal([]string{first.ID}, s.ledgerIDs())
	snap, found, err := s.tm.Snapshot(s.ctx, snapshotTable)
	s.Require().NoError(err)
	s.Require().True(found)
	s.Equal(first.ID, snap.Version)
	s.Require().Contains(snap.Tables, "users")
	s.Len(snap.Tables["users"].Columns, len(users.Columns))

	posts := postsTable()
	second := s.nextMigration(createTableOp(posts))
	s.Require().NoError(s.driver.ApplyMigration(s.ctx, request(second, map[string]core.TableSchema{"users": users, "posts": posts})))

	s.Equal([]string{first.ID, second.ID}, s.ledgerIDs())
	snap, found, err = s.tm.Snapshot(s.ctx, snapshotTable)
	s.Require().NoError(err)
	s.Require().True(found)
	s.Equal(second.ID, snap.Version, "snapshot is replaced, not appended")
	s.Len(snap.Tables, 2)
}

func (s *DriverTestSuite) TestApplyIsAtomic() {
	if s.driver.AtomicityLevel() != core.AtomicityFull {
		s.T().Skipf("driver atomicity is %q", s.driver.AtomicityLevel())
	}

	err := s.apply(
		createTableOp(usersTable()),
		addColumnOp("does_not_exist", core.Column{Name: "x", Type: core.ColTypeText, Nullable: true}),
	)
	s.Error(err)
	s.False(s.tableExists("users"), "DDL before the failing operation is rolled back")
	s.Empty(s.ledgerIDs(), "no ledger entry for a failed migration")
	_, found, err := s.tm.Snapshot(s.ctx, snapshotTable)
	s.Require().NoError(err)
	s.False(found, "no snapshot for a failed migration")
}

func (s *DriverTestSuite) TestReapplyingMigrationFails() {
	m := s.nextMigration(createTableOp(usersTable()))
	s.Require().NoError(s.driver.ApplyMigration(s.ctx, request(m, nil)))

	// Same ID, different DDL: the duplicate ledger row must abort the whole unit.
	m.Up = []core.SchemaOperation{createTableOp(postsTable())}
	s.Error(s.driver.ApplyMigration(s.ctx, request(m, nil)))
	if s.driver.AtomicityLevel() == core.AtomicityFull {
		s.False(s.tableExists("posts"), "DDL is rolled back with the rejected ledger write")
	}
	s.Equal([]string{m.ID}, s.ledgerIDs())
}

func (s *DriverTestSuite) TestRecordBaselineExecutesNoDDL() {
	users := usersTable()
	m := s.nextMigration(createTableOp(users))
	m.IsBaseline = true
	s.Require().NoError(s.driver.RecordBaseline(s.ctx, request(m, map[string]core.TableSchema{"users": users})))

	s.False(s.tableExists("users"), "baseline must not execute Up")
	s.Equal([]string{m.ID}, s.ledgerIDs())
	snap, found, err := s.tm.Snapshot(s.ctx, snapshotTable)
	s.Require().NoError(err)
	s.Require().True(found)
	s.Equal(m.ID, snap.Version)
	s.Contains(snap.Tables, "users")
}

func (s *DriverTestSuite) TestOperationMissingPayloadFails() {
	s.seedUsers()
	for _, op := range []core.SchemaOperation{
		{ID: "no_table", Kind: core.OpCreateTable, Table: "t"},
		{ID: "no_column", Kind: core.OpAddColumn, Table: "users"},
		{ID: "no_alter_column", Kind: core.OpAlterColumn, Table: "users"},
		{ID: "no_index", Kind: core.OpAddIndex, Table: "users"},
		{ID: "no_fk", Kind: core.OpAddForeignKey, Table: "users"},
	} {
		s.Error(s.apply(op), "kind %s with no payload", op.Kind)
	}
	s.Equal(1, len(s.ledgerIDs()), "only the seeding migration is recorded")
}

func (s *DriverTestSuite) TestUnknownOperationKindFails() {
	s.Error(s.apply(core.SchemaOperation{ID: "bogus", Kind: core.OperationKind("bogus"), Table: "users"}))
	s.Empty(s.ledgerIDs())
}

// TestUpThenDownRoundTrip applies a migration and then its inverse (built the
// way MigrationGenerator's invertOperation does), and expects the original shape back.
func (s *DriverTestSuite) TestUpThenDownRoundTrip() {
	s.seedUsersAndPosts(core.FKCascade)
	before := s.columns("users")

	bio := core.Column{Name: "bio", Type: core.ColTypeText, Nullable: true}
	idx := core.Index{Name: "idx_users_bio", Columns: []string{"bio"}}
	s.mustApply(
		addColumnOp("users", bio),
		addIndexOp("users", idx),
		renameColumnOp("users", "name", "display_name"),
		dropForeignKeyOp("posts", "fk_posts_user"),
	)
	s.mustApply(
		addForeignKeyOp("posts", postsUserFK(core.FKCascade)),
		renameColumnOp("users", "display_name", "name"),
		dropIndexOp("users", idx.Name),
		dropColumnOp("users", bio.Name),
	)

	s.Equal(before, s.columns("users"))
	_, found := s.foreignKey("posts", "fk_posts_user")
	s.True(found)
	s.Equal("Ada", asString(s.rows("users", "id")[0]["name"]))
}

// ---- core.MigrationRenderer (optional) ----

func (s *DriverTestSuite) renderer() core.MigrationRenderer {
	r, ok := s.driver.(core.MigrationRenderer)
	if !ok {
		s.T().Skip("driver does not implement core.MigrationRenderer")
	}
	return r
}

// TestRenderMigrationHasNoSideEffects: rendering happens before Apply, so it
// must leave schema, data and ledger exactly as they were.
func (s *DriverTestSuite) TestRenderMigrationHasNoSideEffects() {
	r := s.renderer()
	s.seedUsersAndPosts(core.FKCascade)
	beforeUsers, beforePosts, beforeLedger := s.columns("users"), s.columns("posts"), s.ledgerIDs()

	m := s.nextMigration(
		createTableOp(core.TableSchema{Name: "tags", Columns: []core.Column{{Name: "id", Type: core.ColTypeInteger, PrimaryKey: true}}}),
		addColumnOp("users", core.Column{Name: "bio", Type: core.ColTypeText, Nullable: true}),
		alterColumnOp("users", core.Column{Name: "name", Type: core.ColTypeText, Nullable: true, Default: "x"}),
		dropForeignKeyOp("posts", "fk_posts_user"),
	)
	script, err := r.RenderMigration(s.ctx, m)
	s.Require().NoError(err)
	s.NotEmpty(strings.TrimSpace(script))
	s.True(strings.HasPrefix(r.FileExtension(), "."), "extension includes the dot")

	s.False(s.tableExists("tags"))
	s.Equal(beforeUsers, s.columns("users"))
	s.Equal(beforePosts, s.columns("posts"))
	_, found := s.foreignKey("posts", "fk_posts_user")
	s.True(found)
	s.Equal(int64(2), s.rowCount("users"))
	s.Equal(beforeLedger, s.ledgerIDs())

	s.Require().NoError(s.driver.ApplyMigration(s.ctx, request(m, nil)), "the rendered migration still applies")
}

func (s *DriverTestSuite) TestRenderMigrationFailsLikeApply() {
	r := s.renderer()
	_, err := r.RenderMigration(s.ctx, s.nextMigration(core.SchemaOperation{ID: "no_table", Kind: core.OpCreateTable, Table: "t"}))
	s.Error(err)
}

// ---- Physical names ----

// mapResolver maps canonical names to physical ones; unmapped names pass through.
type mapResolver struct {
	tables  map[string]string
	columns map[string]string // "table.column" -> physical column
}

func (r mapResolver) Resolve(canonical string) string {
	if p, ok := r.tables[canonical]; ok {
		return p
	}
	return canonical
}

func (r mapResolver) ResolveColumn(table, column string) string {
	if p, ok := r.columns[table+"."+column]; ok {
		return p
	}
	return column
}

func (s *DriverTestSuite) TestResolverMapsPhysicalNames() {
	s.driver = s.newDriver(mapResolver{
		tables:  map[string]string{"users": "app_users", "posts": "app_posts"},
		columns: map[string]string{"users.email": "email_address", "posts.user_id": "author_id"},
	})

	s.mustApply(createTableOp(usersTable()), createTableOp(postsTable()))
	s.mustApply(
		addIndexOp("users", core.Index{Name: "idx_users_email", Columns: []string{"email"}}),
		addForeignKeyOp("posts", postsUserFK(core.FKCascade)),
		alterColumnOp("users", core.Column{Name: "email", Type: core.ColTypeString, Length: 320, Unique: true}),
	)

	s.False(s.tableExists("users"))
	s.True(s.tableExists("app_users"))
	s.Contains(s.columns("app_users"), "email_address")
	idx, found := s.index("app_users", "idx_users_email")
	s.Require().True(found)
	s.Equal([]string{"email_address"}, idx.Columns)

	fk, found := s.foreignKey("app_posts", "fk_posts_user")
	s.Require().True(found)
	s.Equal([]string{"author_id"}, fk.Columns)
	s.True(strings.EqualFold("app_users", fk.RefTable))
}
