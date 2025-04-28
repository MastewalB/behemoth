package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/utils"
)

// sessionContextKey is a key type to be used to store session in request context
type sessionContextKey string

const sessionKey sessionContextKey = "session"

// SessionManager handles session creation, retrieval, and deletion.
type SessionManager struct {
	store          behemoth.SessionStore   // Database for session storage
	expiry         time.Duration           // Session duration (e.g., 24h)
	cookieName     string                  // Name of the session cookie (e.g., "session_id")
	sessionFactory behemoth.SessionFactory // Factory to create new sessions
	lock           sync.Mutex              // Ensures thread-safety
}

// NewSessionManager creates a new SessionManager with the given database and configuration.
func NewSessionManager(
	store behemoth.SessionStore,
	expiry time.Duration,
	cookieName string,
	factory behemoth.SessionFactory,
) *SessionManager {

	if factory == nil {
		factory = func(id string) behemoth.Session {
			return behemoth.NewDefaultSession(id, expiry)
		}
	}

	return &SessionManager{
		store:          store,
		expiry:         expiry,
		cookieName:     cookieName,
		sessionFactory: factory,
	}
}

// CreateSession creates a new session with a unique ID and stores it in the backend.
func (sm *SessionManager) CreateSession() (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	id := utils.GenerateState()
	session := sm.sessionFactory(id)

	expiresAt := time.Now().Add(sm.expiry)

	if err := sm.store.SaveSession(session, expiresAt); err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession retrieves a session by ID, returning an error if not found or expired.
func (sm *SessionManager) GetSession(sessionID string) (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, err := sm.store.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (sm *SessionManager) UpdateSession(session behemoth.Session) (behemoth.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if err := sm.store.SaveSession(session, time.Now().Add(sm.expiry)); err != nil {
		return nil, err
	}

	return session, nil

}

// DeleteSession removes a session by ID from the backend.
func (sm *SessionManager) DeleteSession(sessionID string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.store.DeleteSession(sessionID)
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

		session, err := sm.GetSession(cookie.Value)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Attach the sesion to the context
		ctx := context.WithValue(r.Context(), sessionKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSessionFromContext extracts a session from a given context if it was set by the SessionManager Middleware
func GetSessionFromContext(ctx context.Context) (behemoth.Session, bool) {
	session, ok := ctx.Value(sessionKey).(behemoth.Session)
	return session, ok
}
