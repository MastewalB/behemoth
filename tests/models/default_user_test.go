package models

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/models"
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"
)

var schema = `
CREATE TABLE users (
	id TEXT PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	username TEXT UNIQUE NOT NULL,
	firstname TEXT,
	lastname TEXT,
	password_hash TEXT NOT NULL,
	email_verified TEXT,
	image_url TEXT,
	created_at TEXT,
	updated_at TEXT
);
`

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	db.Exec(schema)
	return db
}

func newTestUser(id string) *models.User {
	return &models.User{
		ID:            id,
		Email:         fmt.Sprintf("user%s@example.com", id),
		Username:      fmt.Sprintf("user%s", id),
		Firstname:     "John",
		Lastname:      "Doe",
		PasswordHash:  "hashedpassword",
		EmailVerified: "false",
		ImageUrl:      "http://example.com/avatar.png",
		CreatedAt:     time.Now().Format(time.RFC3339),
		UpdatedAt:     time.Now().Format(time.RFC3339),
	}
}

func insertUser(t *testing.T, db *sql.DB, u *models.User) {
	_, err := db.Exec(`INSERT INTO users 
		(id, email, username, firstname, lastname, password_hash, email_verified, image_url, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		u.ID,
		u.Email,
		u.Username,
		u.Firstname,
		u.Lastname,
		u.PasswordHash,
		u.EmailVerified,
		u.ImageUrl,
		u.CreatedAt,
		u.UpdatedAt,
	)

	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	db := setupTestDB(t)

	user := newTestUser("1")
	insertUser(t, db, user)

	var u models.User
	err := db.QueryRow("SELECT * FROM users WHERE id = ?", user.ID).
		Scan(
			&u.ID,
			&u.Email,
			&u.Username,
			&u.Firstname,
			&u.Lastname,
			&u.PasswordHash,
			&u.EmailVerified,
			&u.ImageUrl,
			&u.CreatedAt,
			&u.UpdatedAt,
		)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, u.Email)
	assert.Equal(t, user.Username, u.Username)
	assert.Equal(t, user.PasswordHash, u.PasswordHash)
}

func TestReadUser(t *testing.T) {
	db := setupTestDB(t)

	user := newTestUser("2")
	insertUser(t, db, user)

	var u models.User
	err := db.QueryRow("SELECT * FROM users WHERE id = ?", user.ID).
		Scan(
			&u.ID,
			&u.Email,
			&u.Username,
			&u.Firstname,
			&u.Lastname,
			&u.PasswordHash,
			&u.EmailVerified,
			&u.ImageUrl,
			&u.CreatedAt,
			&u.UpdatedAt,
		)

	assert.NoError(t, err)
	assert.Equal(t, user.ID, u.ID)
	assert.Equal(t, "John Doe", u.GetName())
}

func TestUpdateUser(t *testing.T) {
	db := setupTestDB(t)

	user := newTestUser("3")
	insertUser(t, db, user)

	// Update username and email_verified
	newUsername := "newuser3"
	newVerified := "true"
	_, err := db.Exec("UPDATE users SET username=?, email_verified=?, updated_at=? WHERE id=?",
		newUsername, newVerified, time.Now().Format(time.RFC3339), user.ID)
	assert.NoError(t, err)

	var u models.User
	err = db.QueryRow("SELECT * FROM users WHERE id = ?", user.ID).
		Scan(
			&u.ID,
			&u.Email,
			&u.Username,
			&u.Firstname,
			&u.Lastname,
			&u.PasswordHash,
			&u.EmailVerified,
			&u.ImageUrl,
			&u.CreatedAt,
			&u.UpdatedAt,
		)

	assert.NoError(t, err)
	assert.Equal(t, newUsername, u.Username)
	assert.Equal(t, "true", u.EmailVerified)
}

func TestDeleteUser(t *testing.T) {
	db := setupTestDB(t)

	user := newTestUser("4")
	insertUser(t, db, user)

	_, err := db.Exec("DELETE FROM users WHERE id = ?", user.ID)
	assert.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT
			EXISTS(SELECT 1 FROM users WHERE id = ?)`, user.ID).Scan(&count)

	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestDuplicateEmailFails(t *testing.T) {
	db := setupTestDB(t)

	user1 := newTestUser("5")
	user2 := newTestUser("6")
	user2.Email = user1.Email // duplicate email

	insertUser(t, db, user1)
	_, err := db.Exec(`INSERT INTO users 
		(id, email, username, firstname, lastname, password_hash, email_verified, image_url, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, user2.ID,
		user2.Email,
		user2.Username,
		user2.Firstname,
		user2.Lastname,
		user2.PasswordHash,
		user2.EmailVerified,
		user2.ImageUrl,
		user2.CreatedAt,
		user2.UpdatedAt,
	)

	assert.Error(t, err, "expected duplicate email constraint violation")
}

func TestDuplicateUsernameFails(t *testing.T) {
	db := setupTestDB(t)

	user1 := newTestUser("7")
	user2 := newTestUser("8")
	user2.Username = user1.Username // duplicate username

	insertUser(t, db, user1)

	_, err := db.Exec(`INSERT INTO users 
		(id, email, username, firstname, lastname, password_hash, email_verified, image_url, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, user2.ID,
		user2.Email,
		user2.Username,
		user2.Firstname,
		user2.Lastname,
		user2.PasswordHash,
		user2.EmailVerified,
		user2.ImageUrl,
		user2.CreatedAt,
		user2.UpdatedAt,
	)
	assert.Error(t, err, "expected duplicate username constraint violation")
}
