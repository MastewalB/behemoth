package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/tests/testutils"
	"github.com/stretchr/testify/assert"
)

var session_schema = `
CREATE TABLE sessions (
	id TEXT PRIMARY KEY,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL
);
`

func TestSessionManager_CreateSession(t *testing.T) {
	// Setup a mock database or use an in-memory database for testing
	db := testutils.SetupTestDB(t, session_schema)
	defer db.Close()

	// Create a SessionManager
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		24*time.Hour,
		"test_session_id",
		nil, // Use default session factory
	)

	// Create a context for the session
	sctx := behemoth.SessionContext{
		Request: &http.Request{},
	}

	// Create a new session
	session, err := sessionManager.CreateSession(context.Background(), sctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.NotEmpty(t, session.GetID())

}

func TestSessionManager_GetSession(t *testing.T) {
	// Setup a mock database or use an in-memory database for testing
	db := testutils.SetupTestDB(t, session_schema)
	defer db.Close()

	// Create a SessionManager
	sessionManager := auth.NewSessionManager(
		testutils.SetupSQLiteAdapter(t, db),
		24*time.Hour,
		"test_session_id",
		nil, // Use default session factory
	)

	// Create a context for the session
	sctx := behemoth.SessionContext{
		Request: &http.Request{},
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
