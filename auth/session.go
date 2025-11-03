package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// sessionContextKey is a key type to be used to store session in request context
type sessionContextKey string

const sessionKey sessionContextKey = "session"

// SessionManager handles session creation, retrieval, and deletion.
type SessionManager struct {
	store      models.SessionStore // Database for session storage
	expiry     time.Duration       // Session duration (e.g., 24h)
	cookieName string              // Name of the session cookie (e.g., "session_id")
	lock       sync.Mutex          // Ensures thread-safety
}

// NewSessionManager creates a new SessionManager with the given database and configuration.
func NewSessionManager(
	db behemoth.Database,
	expiry time.Duration,
	cookieName string,
) *SessionManager {

	store := models.SessionStore{
		DB: db,
	}

	if err := store.CreateSessionTable(context.Background()); err != nil {
		panic("failed to create sessions table: " + err.Error())
	}

	return &SessionManager{
		store:      store,
		expiry:     expiry,
		cookieName: cookieName,
	}
}

// CreateSession creates a new session with a unique ID and stores it in the backend.
func (sm *SessionManager) CreateSession(ctx context.Context, sctx behemoth.SessionContext) (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session := models.NewDefaultSession(sctx)

	expiresAt := time.Now().Add(sm.expiry)
	session.SetExpiresAt(expiresAt)

	if err := sm.store.SaveSession(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession retrieves a session by ID, returning an error if not found or expired.
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sessionModel := &models.Session{}
	session, err := sm.store.GetSession(ctx, sessionModel, sessionID)
	if err != nil {
		return nil, err
	}

	// Validate expiration
	if session.IsExpired() {
		_ = sm.store.DeleteSession(ctx, sessionModel)
		return nil, errors.New("session expired")
	}

	return session, nil
}

func (sm *SessionManager) UpdateSession(ctx context.Context, session behemoth.Session) (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	expiresAt := time.Now().Add(sm.expiry)
	session.SetExpiresAt(expiresAt)
	if err := sm.store.UpdateSession(ctx, session); err != nil {
		return nil, err
	}

	return session, nil

}

// DeleteSession removes a session by ID from the backend.
func (sm *SessionManager) DeleteSession(ctx context.Context, session behemoth.Session) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.store.DeleteSession(ctx, session)
}

func (sm *SessionManager) Expiry() time.Duration {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.expiry
}

// Middleware checks for a session in incoming requests and adds it to the context.
func (sm *SessionManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sm == nil {
			panic("SessionManager is nil. Set UseSessions to true in Behemoth config to use SessionManager Middleware.")
		}

		cookie, err := r.Cookie(sm.cookieName)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		session, err := sm.GetSession(ctx, cookie.Value)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Attach the sesion to the context
		ctx = context.WithValue(r.Context(), sessionKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSessionFromContext extracts a session from a given context if it was set by the SessionManager Middleware
func GetSessionFromContext(ctx context.Context) (behemoth.Session, bool) {
	session, ok := ctx.Value(sessionKey).(behemoth.Session)
	return session, ok
}
