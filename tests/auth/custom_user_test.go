package auth

// import (
// 	"context"
// 	"database/sql"
// 	"testing"

// 	"github.com/MastewalB/behemoth"
// 	"github.com/MastewalB/behemoth/auth"
// 	"github.com/MastewalB/behemoth/clause"
// 	"github.com/MastewalB/behemoth/utils"
// 	_ "github.com/mattn/go-sqlite3"
// 	"github.com/stretchr/testify/assert"
// )

// type CustomUser struct {
// 	ID           string `db:"id"`
// 	Name         string `db:"name"`
// 	PasswordHash string `db:"password_hash"`
// 	CreatedAt    string `db:"created_at"`
// 	UpdatedAt    string `db:"updated_at"`
// }

// func (u *CustomUser) GetID() string           { return u.ID }
// func (u *CustomUser) GetPasswordHash() string { return u.PasswordHash }
// func (u *CustomUser) New() behemoth.Model {
// 	return &CustomUser{}
// }

// func (u *CustomUser) PrimaryKeyName() string {
// 	return "id"
// }

// func (u *CustomUser) PrimaryKeyField() any {
// 	return u.ID
// }

// func (u *CustomUser) SchemaName() string {
// 	return "users"
// }

// func (u *CustomUser) ToMap() (map[string]any, error) {
// 	return map[string]any{
// 		"id":            u.ID,
// 		"name":          u.Name,
// 		"password_hash": u.PasswordHash,
// 		"created_at":    u.CreatedAt,
// 		"updated_at":    u.UpdatedAt,
// 	}, nil

// }

// func (u *CustomUser) FromMap(data map[string]any) error {
// 	u.ID = data["id"].(string)
// 	u.Name = data["name"].(string)
// 	u.PasswordHash = data["password_hash"].(string)
// 	u.CreatedAt = data["created_at"].(string)
// 	u.UpdatedAt = data["updated_at"].(string)
// 	return nil
// }

// func customUserFactory(data map[string]any) behemoth.User {
// 	return &CustomUser{
// 		ID:           data["id"].(string),
// 		Name:         data["name"].(string),
// 		PasswordHash: data["password_hash"].(string),
// 		CreatedAt:    data["created_at"].(string),
// 		UpdatedAt:    data["updated_at"].(string),
// 	}
// }

// var schema = `
// CREATE TABLE users (
// 	id TEXT PRIMARY KEY,
// 	name TEXT,
// 	password_hash TEXT NOT NULL,
// 	created_at TEXT,
// 	updated_at TEXT
// );
// `

// func setUpCustomUserTable(t *testing.T) *sql.DB {
// 	db, err := sql.Open("sqlite3", ":memory:")
// 	if err != nil {
// 		t.Fatalf("failed to open sqlite database: %v", err)
// 	}

// 	_, err = db.Exec(schema)
// 	if err != nil {
// 		t.Fatalf("failed to create users table: %v", err)
// 	}

// 	return db
// }

// func newTestUser() *CustomUser {
// 	uuidStr := utils.GenerateUUID()

// 	return &CustomUser{
// 		ID:           uuidStr,
// 		Name:         "CustomUser" + uuidStr,
// 		PasswordHash: "hashedpassword",
// 		CreatedAt:    "2023-01-01T00:00:00Z",
// 		UpdatedAt:    "2023-01-01T00:00:00Z",
// 	}
// }

// func insertCustomUser(t *testing.T, db *sql.DB, u *CustomUser) {
// 	_, err := db.Exec(`INSERT INTO users
// 		(id, name, password_hash, created_at, updated_at)
// 		VALUES (?, ?, ?, ?, ?)`,
// 		u.ID, u.Name, u.PasswordHash, u.CreatedAt, u.UpdatedAt)
// 	if err != nil {
// 		t.Fatalf("failed to insert user: %v", err)
// 	}
// }

// func getBehemothInstance(db *sql.DB) (*auth.Behemoth[*CustomUser], error) {
// 	config := &behemoth.Config[*CustomUser]{
// 		DatabaseConfig: behemoth.DatabaseConfig{
// 			Name:           behemoth.SQLite,
// 			DB:             db,
// 			UseDefaultUser: false,
// 			UserModel:      &CustomUser{},
// 			UserFactory:    customUserFactory,
// 		},
// 		Password: &behemoth.PasswordConfig{HashCost: 10},
// 		// OAuthProviders: []behemoth.Provider{},
// 		JWT:         &behemoth.JWTConfig{Secret: "default_secret", Expiry: 24 * 60 * 60},
// 		UseSessions: false,
// 	}

// 	return auth.New(config)
// }

// func TestCreateCustomUser(t *testing.T) {
// 	ctx := context.Background()
// 	db := setUpCustomUserTable(t)
// 	defer db.Close()

// 	user := newTestUser()
// 	insertCustomUser(t, db, user)

// 	var retrievedUser CustomUser

// 	err := db.QueryRow(`SELECT id, name, password_hash, created_at, updated_at FROM users WHERE id = ?`, user.ID).Scan(
// 		&retrievedUser.ID,
// 		&retrievedUser.Name,
// 		&retrievedUser.PasswordHash,
// 		&retrievedUser.CreatedAt,
// 		&retrievedUser.UpdatedAt,
// 	)

// 	assert.NoError(t, err)
// 	assert.Equal(t, user.ID, retrievedUser.ID)
// 	assert.Equal(t, user.Name, retrievedUser.Name)
// 	assert.Equal(t, user.PasswordHash, retrievedUser.PasswordHash)
// 	assert.Equal(t, user.CreatedAt, retrievedUser.CreatedAt)
// 	assert.Equal(t, user.UpdatedAt, retrievedUser.UpdatedAt)

// 	bmth, err := getBehemothInstance(db)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	whereClause := clause.Expression{
// 		Logic: clause.OpAnd,
// 		Conditions: []clause.Condition{
// 			{Field: "id", Operator: clause.OpEqual, Value: user.ID},
// 		},
// 	}

// 	found, err := bmth.DB.FindOne(ctx, &CustomUser{}, whereClause)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, found)

// 	usr, ok := found.(*CustomUser)
// 	assert.True(t, ok)
// 	assert.Equal(t, user.ID, usr.GetID())
// }

// func TestAuthenticateCustomUser(t *testing.T) {

// 	db := setUpCustomUserTable(t)
// 	defer db.Close()

// 	password := "securepassword"
// 	hashedPassword, err := utils.GeneratePasswordHash(password)
// 	assert.NoError(t, err)

// 	user := newTestUser()
// 	user.PasswordHash = hashedPassword
// 	insertCustomUser(t, db, user)

// 	bmth, err := getBehemothInstance(db)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	credentials := auth.PasswordCredentials{
// 		PrimaryKey: user.ID,
// 		Password:   password,
// 	}

// 	authenticatedUser, err := bmth.Password.Login(credentials)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, authenticatedUser)
// 	assert.Equal(t, user.ID, authenticatedUser.GetID())
// 	assert.Equal(t, user.Name, authenticatedUser.(*CustomUser).Name)

// }
// func TestLoginCustomUserIncorrectCredential(t *testing.T) {
// 	db := setUpCustomUserTable(t)
// 	defer db.Close()

// 	password := "securepassword"
// 	hashedPassword, err := utils.GeneratePasswordHash(password)
// 	assert.NoError(t, err)

// 	user := newTestUser()
// 	user.PasswordHash = hashedPassword
// 	insertCustomUser(t, db, user)

// 	bmth, err := getBehemothInstance(db)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	credentials := auth.PasswordCredentials{
// 		PrimaryKey: user.ID,
// 		Password:   "wrongpassword",
// 	}

// 	authenticatedUser, err := bmth.Password.Login(credentials)
// 	assert.Error(t, err)
// 	assert.Nil(t, authenticatedUser)
// }

// func TestRegisterCustomUser(t *testing.T) {
// 	db := setUpCustomUserTable(t)
// 	defer db.Close()

// 	bmth, err := getBehemothInstance(db)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, bmth)

// 	registrationData := map[string]any{
// 		"id":       "custom_user_1",
// 		"name":     "Custom User One",
// 		"password": "newsecurepassword",
// 	}

// 	created, err := bmth.Password.Register(registrationData)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, created)

// 	registeredUser, ok := created.(*CustomUser)
// 	assert.True(t, ok)

// 	assert.Equal(t, registrationData["name"], registeredUser.Name)
// 	assert.NotEmpty(t, registeredUser.PasswordHash)

// }
