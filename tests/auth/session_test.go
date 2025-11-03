package auth

import (
	"context"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
)

var session_schema = `
CREATE TABLE sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	ip_address TEXT,
	user_agent TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);
`

func TestSessionManager_CreateSession(t *testing.T) {
	// Setup a mock database or use an in-memory database for testing
	db := testutils.SetupTestDB(t, nil)
	defer db.Close()

	// Create a SessionManager
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		24*time.Hour,
		"test_session_id",
	)

	// Create a context for the session
	sctx := behemoth.SessionContext{
		UserID:    "test_user_id",
		IpAddress: "test_ip",
		UserAgent: "test_user_agent",
	}

	// Create a new session
	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.NotEmpty(t, session.GetID())

}

func TestSessionManager_GetSession(t *testing.T) {
	// Setup a mock database or use an in-memory database for testing
	db := testutils.SetupTestDB(t, nil)
	defer db.Close()

	// Create a SessionManager
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		24*time.Hour,
		"test_session_id",
	)

	// Create a context for the session
	sctx := behemoth.SessionContext{
		UserID:    "test_user_id",
		IpAddress: "test_ip",
		UserAgent: "test_user_agent",
	}

	// Create a new session
	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.NotEmpty(t, session.GetID())

	// Retrieve the session by ID
	retrievedSession, err := sessionManager.GetSession(context.Background(), session.GetID())
	assert.NoError(t, err)
	assert.NotNil(t, retrievedSession)
	assert.Equal(t, session.GetID(), retrievedSession.GetID())
}

func TestSessionManager_GetSession_Expired(t *testing.T) {
	// Setup a mock database or use an in-memory database for testing
	db := testutils.SetupTestDB(t, nil)
	defer db.Close()

	// Create a SessionManager with a short expiry time
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		1*time.Millisecond,
		"test_session_id",
	)

	// Create a context for the session
	sctx := behemoth.SessionContext{
		UserID:    "test_user_id",
		IpAddress: "test_ip",
		UserAgent: "test_user_agent",
	}

	// Create a new session
	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.NotEmpty(t, session.GetID())

	// Wait for the session to expire
	time.Sleep(1 * time.Millisecond)

	// Attempt to retrieve the expired session
	retrievedSession, err := sessionManager.GetSession(context.Background(), session.GetID())
	assert.Error(t, err)
	assert.Equal(t, "session expired", err.Error())
	assert.Nil(t, retrievedSession)
}

func TestSessionManager_UpdateSession(t *testing.T) {
	db := testutils.SetupTestDB(t, &session_schema)
	defer db.Close()

	expiry := 24 * time.Hour
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		expiry,
		"test_session_id",
	)

	sctx := behemoth.SessionContext{
		UserID:    "test_user_id",
		IpAddress: "test_ip",
		UserAgent: "test_user_agent",
	}

	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	// Update the session's expiry time

	updatedSession, err := sessionManager.UpdateSession(context.Background(), session)
	assert.NoError(t, err)
	assert.NotNil(t, updatedSession)

	agentUpdatedSession, ok := updatedSession.(*models.Session)
	agentUpdatedSession.UserAgent = "updated_user_agent"
	assert.True(t, ok)

	// Save the updated session
	updatedSession, err = sessionManager.UpdateSession(context.Background(), agentUpdatedSession)
	assert.NoError(t, err)
	assert.NotNil(t, updatedSession)

	// Verify the expiry time was updated
	retrievedSession, err := sessionManager.GetSession(context.Background(), session.GetID())
	assert.NoError(t, err)
	assert.NotNil(t, retrievedSession)
	assert.WithinDuration(t, time.Now().Add(expiry), retrievedSession.(*models.Session).ExpiresAt, time.Second)
	assert.Equal(t, "updated_user_agent", retrievedSession.(*models.Session).UserAgent)
}

func TestSessionManager_DeleteSession(t *testing.T) {
	db := testutils.SetupTestDB(t, nil)
	defer db.Close()

	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		24*time.Hour,
		"test_session_id",
	)

	sctx := behemoth.SessionContext{
		UserID:    "test_user_id",
		IpAddress: "test_ip",
		UserAgent: "test_user_agent",
	}

	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	// Delete the session
	err = sessionManager.DeleteSession(context.Background(), session)
	assert.NoError(t, err)

	// Attempt to retrieve the deleted session
	retrievedSession, err := sessionManager.GetSession(context.Background(), session.GetID())
	assert.Error(t, err)
	assert.Nil(t, retrievedSession)
}
