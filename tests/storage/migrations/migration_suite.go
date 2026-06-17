package migrations

import (
	"context"
	"testing"

	"github.com/MastewalB/behemoth/migration/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type DriverTestSuite struct {
	suite.Suite
	ctx               context.Context
	driver            core.Driver
	driverTestManager DriverTestManager
	schema            *core.TableSchema
	table             string
	testData          map[string]any
}

func NewDriverTestSuite(driver core.Driver, testManager DriverTestManager) *DriverTestSuite {
	return &DriverTestSuite{
		ctx:               context.Background(),
		driver:            driver,
		driverTestManager: testManager,
		table:             "test_users",
	}
}

// SetupSuite runs once before all tests
func (s *DriverTestSuite) SetupSuite() {
	// Define schema once for all tests
	s.schema = &core.TableSchema{
		Name: s.table,
		Columns: []core.Column{
			{Name: "id", Type: "string", Primary: true, Nullable: false},
			{Name: "email", Type: "string", Unique: true, Nullable: false},
			{Name: "username", Type: "string", Unique: true, Nullable: false},
			{Name: "age", Type: "int", Nullable: true},
			{Name: "active", Type: "bool", Nullable: false},
			{Name: "created_at", Type: "datetime", Nullable: true},
		},
		Indexes: []core.Index{
			{Name: "idx_email", Columns: []string{"email"}, Unique: true},
			{Name: "idx_username", Columns: []string{"username"}, Unique: true},
			{Name: "idx_age", Columns: []string{"age"}, Unique: false},
		},
	}

	s.testData = map[string]any{
		"id":       "user-1",
		"email":    "test@example.com",
		"username": "testuser",
		"age":      25,
		"active":   true,
	}
}

// TearDownSuite runs after all tests
func (s *DriverTestSuite) TearDownSuite() {
	if s.driver != nil {
		s.driverTestManager.DropAllTables(s.ctx)
		s.driver.Close()
	}
}

// SetupTest runs before each test
func (s *DriverTestSuite) SetupTest() {
	// Ensure clean state before each test
	err := s.driverTestManager.DropAllTables(s.ctx)
	assert.NoError(s.T(), err, "Failed to clean tables before test")
}

// TearDownTest runs after each test
func (s *DriverTestSuite) TearDownTest() {
	// Clean up after each test
	err := s.driverTestManager.DropAllTables(s.ctx)
	assert.NoError(s.T(), err, "Failed to clean tables after test")
}

func (s *DriverTestSuite) TestCreateTable() {
	t := s.T()

	err := s.driver.CreateTable(s.ctx, s.table, s.schema)
	assert.NoError(t, err, "failed to create table")

	exists, err := s.driverTestManager.TableExists(s.ctx, s.table)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Verify row count is 0
	count, err := s.driverTestManager.TableRowCount(s.ctx, s.table)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count, "New table should be empty")

}

// TestDropTable tests table dropping
func (s *DriverTestSuite) TestDropTable() {
	t := s.T()

	// Create table
	err := s.driver.CreateTable(s.ctx, s.table, s.schema)
	assert.NoError(t, err)

	// Verify table exists
	exists, err := s.driverTestManager.TableExists(s.ctx, s.table)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Drop table
	err = s.driver.DropTable(s.ctx, s.table)
	assert.NoError(t, err)

	// Verify table doesn't exist
	exists, err = s.driverTestManager.TableExists(s.ctx, s.table)
	assert.NoError(t, err)
	assert.False(t, exists, "Table should not exist after drop")
}

// TestDropTableNonExistent tests dropping non-existent table
func (s *DriverTestSuite) TestDropTableNonExistent() {
	t := s.T()

	// Drop non-existent table should not error
	err := s.driver.DropTable(s.ctx, "non_existent_table")
	assert.NoError(t, err, "Dropping non-existent table should be safe")
}

// TestPing tests database connectivity
func (s *DriverTestSuite) TestPing() {
	t := s.T()

	err := s.driver.Ping(s.ctx)
	assert.NoError(t, err, "Should ping successfully")
}

// TestName tests driver name retrieval
func (s *DriverTestSuite) TestName() {
	t := s.T()

	name := s.driver.Name()
	assert.NotEmpty(t, name, "Driver should have a name")
}

// TestClose tests closing connection
// func (s *DriverTestSuite) TestClose() {
// 	t := s.T()

// 	err := s.driver.Close()
// 	assert.NoError(t, err, "Should close successfully")

// 	// Should be safe to close again
// 	err = s.driver.Close()
// 	assert.NoError(t, err, "Closing twice should be safe")
// }

// RunDriverTests runs all tests against a driver
func RunDriverTests(t *testing.T, driver core.Driver, testManager DriverTestManager) {
	suite.Run(t, NewDriverTestSuite(driver, testManager))
}

// DriverTestManager provides utility methods that will be used in the tests.
type DriverTestManager interface {
	TableExists(ctx context.Context, tableName string) (bool, error)
	ColumnExists(ctx context.Context, tableName, columnName string) (bool, error)
	IndexExists(ctx context.Context, tableName, indexName string) (bool, error)
	TableRowCount(ctx context.Context, tableName string) (int64, error)
	MigrationTableExists(ctx context.Context) (bool, error)
	GetMigrationVersion(ctx context.Context) (int, error)
	DropAllTables(ctx context.Context) error
	InsertTestData(ctx context.Context, tableName string, data map[string]any) error
	QueryTable(ctx context.Context, tableName string, query string) ([]map[string]any, error)
}
