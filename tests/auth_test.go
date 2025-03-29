package tests

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/config"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/storage"
	"github.com/MastewalB/behemoth/utils"
	"github.com/stretchr/testify/assert"
	// _ "github.com/mattn/go-sqlite3"
)

func TestDefaultUserFlow(t *testing.T) {
	sqliteCfg := &storage.DBConfig{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}
	// Setup SQLite in-memory
	sqliteDB, err := storage.NewSQLiteProvider(":memory:", sqliteCfg)
	assert.NoError(t, err, "Failed to initialize SQLite provider")

	cfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: true},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	b := auth.New(cfg)

	// Register handler
	registerHandler := func(w http.ResponseWriter, _ *http.Request) {
		creds := auth.PasswordCredentials{Email: "test@example.com", Password: "password123"}
		user, err := b.Password.Register(creds)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte(user.GetID()))
	}

	// Login handler
	loginHandler := func(w http.ResponseWriter, _ *http.Request) {
		creds := auth.PasswordCredentials{Email: "test@example.com", Password: "password123"}
		user, err := b.Password.Authenticate(creds)
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := b.JWT.GenerateToken(user)
		w.Write([]byte(token))
	}

	// Test Register
	req, _ := http.NewRequest("POST", "/register", nil)
	rr := httptest.NewRecorder()
	registerHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "Register should succeed")
	assert.NotEmpty(t, rr.Body.String(), "Register should return a non-empty ID")

	// Test Login
	req, _ = http.NewRequest("POST", "/login", nil)
	rr = httptest.NewRecorder()
	loginHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "Login should succeed")
	assert.NotEmpty(t, rr.Body.String(), "Login should return a non-empty token")
}

func TestCustomUserLogin(t *testing.T) {
	// Setup SQLite with custom provider
	sqliteDB, _ := storage.NewSQLiteProvider(":memory:", nil)
	customCfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: false},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	b := auth.New(customCfg)

	// Prepopulate (mimic custom provider logic)
	hash, _ := utils.GeneratePasswordHash("password123")
	err := sqliteDB.SaveUser(&models.DefaultUser{
		Email:        "custom@example.com",
		PasswordHash: hash,
	})
	assert.NoError(t, err, "Failed to prepopulate user")

	// Login handler
	loginHandler := func(w http.ResponseWriter, _ *http.Request) {
		creds := auth.PasswordCredentials{Email: "custom@example.com", Password: "password123"}
		user, err := b.Password.Authenticate(creds)
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		token, _ := b.JWT.GenerateToken(user)
		w.Write([]byte(token))
	}

	// Test Login
	req, _ := http.NewRequest("POST", "/login", nil)
	rr := httptest.NewRecorder()
	loginHandler(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Custom login failed: got %v, want %v", status, http.StatusOK)
	}
}

// TestFailedRegistration tests registration with invalid credentials
func TestFailedRegistration(t *testing.T) {
	sqliteDB, err := storage.NewSQLiteProvider(":memory:", nil)
	assert.NoError(t, err, "Failed to initialize SQLite provider")

	cfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: true},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	b := auth.New(cfg)

	// Register handler with invalid credentials
	registerHandler := func(w http.ResponseWriter, r *http.Request) {
		creds := "not-a-struct" // Invalid type
		_, err := b.Password.Register(creds)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte("should not reach here"))
	}

	req, _ := http.NewRequest("POST", "/register", nil)
	rr := httptest.NewRecorder()
	registerHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code, "Register should fail with invalid credentials")
	assert.Contains(t, rr.Body.String(), "invalid credentials", "Error message should indicate invalid credentials")
}

// TestFailedLogin tests login with wrong password
func TestFailedLogin(t *testing.T) {
	sqliteDB, err := storage.NewSQLiteProvider(":memory:", nil)
	assert.NoError(t, err, "Failed to initialize SQLite provider")

	cfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: true},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	b := auth.New(cfg)

	// Register a user
	creds := auth.PasswordCredentials{Email: "failtest@example.com", Password: "password123"}
	_, err = b.Password.Register(creds)
	assert.NoError(t, err, "Failed to register user")

	// Login handler with wrong password
	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		creds := auth.PasswordCredentials{Email: "failtest@example.com", Password: "wrongpassword"}
		_, err := b.Password.Authenticate(creds)
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("should not reach here"))
	}

	req, _ := http.NewRequest("POST", "/login", nil)
	rr := httptest.NewRecorder()
	loginHandler(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Login should fail with wrong password")
	assert.Contains(t, rr.Body.String(), "login failed", "Error message should indicate login failure")
}

// TestTransactionRollback tests transaction rollback on failure
func TestTransactionRollback(t *testing.T) {
	sqliteDB, err := storage.NewSQLiteProvider(":memory:", nil)
	assert.NoError(t, err, "Failed to initialize SQLite provider")

	cfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: true},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	auth.New(cfg)

	// Simulate a failing transaction
	err = sqliteDB.WithTransaction(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)", "1", "tx@example.com", "hash")
		if err != nil {
			return err
		}
		// Force a failure (e.g., duplicate email violates UNIQUE constraint)
		_, err = tx.Exec("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)", "2", "tx@example.com", "hash2")
		return err
	})
	assert.Error(t, err, "Transaction should fail due to duplicate email")

	// Verify rollback: user should not exist
	user, err := sqliteDB.FindUserByEmail("tx@example.com")
	assert.Error(t, err, "User should not exist after rollback")
	assert.Nil(t, user, "User should be nil after rollback")
}

// TestConnectionPooling tests behavior under connection limits
func TestConnectionPooling(t *testing.T) {
	sqliteCfg := &storage.DBConfig{
		MaxOpenConns:    1, // Restrict to 1 connection
		MaxIdleConns:    1,
		ConnMaxLifetime: 1 * time.Minute,
	}
	sqliteDB, err := storage.NewSQLiteProvider(":memory:", sqliteCfg)
	assert.NoError(t, err, "Failed to initialize SQLite provider")

	cfg := &config.Config{
		Password: config.PasswordConfig{DB: sqliteDB, UseDefaultUser: true, DBConfig: sqliteCfg},
		JWT:      config.JWTConfig{Secret: "mysecret", Expiry: 24 * time.Hour},
	}
	b := auth.New(cfg)

	// Register handler
	registerHandler := func(email string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			creds := auth.PasswordCredentials{Email: email, Password: "password123"}
			_, err := b.Password.Register(creds)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Write([]byte("ok"))
		}
	}

	// Run two concurrent requests to test pooling
	done := make(chan bool, 2)
	emails := []string{"pooltest1@example.com", "pooltest2@example.com"}
	successCount := 0

	for i := 0; i < 2; i++ {
		go func(email string) {
			req, _ := http.NewRequest("POST", "/register", nil)
			rr := httptest.NewRecorder()
			registerHandler(email)(rr, req)
			if rr.Code == http.StatusOK {
				successCount++
			}
			done <- true
		}(emails[i])
	}

	// Wait for both to complete
	for i := 0; i < 2; i++ {
		<-done
	}

	// Verify both users exist (pooling should allow sequential writes)
	for _, email := range emails {
		user, err := sqliteDB.FindUserByEmail(email)
		assert.NoError(t, err, "User %s should exist after registration", email)
		assert.NotNil(t, user, "User %s should not be nil", email)
	}
	// With MaxOpenConns=1, SQLite’s single-writer nature should still allow both
	// due to connection reuse, but successCount tracks actual completions
	assert.Equal(t, 2, successCount, "Both registrations should succeed with connection reuse")
}
