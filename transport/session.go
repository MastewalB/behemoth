package transport

import (
	"context"
	"errors"
	"sync"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/types"
)

type SessionManager struct {
	lock        sync.Mutex
	authContext types.AuthContext
}

func (sm *SessionManager) Create(ctx context.Context, userID string) (string, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, err := sm.authContext.InternalAdapter.CreateSession(ctx, behemoth.M{})
	if err != nil {
		return "", err
	}

	return session.ID, nil

}

func (sm *SessionManager) Verify(ctx context.Context, tokenStr string) (any, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, err := sm.authContext.InternalAdapter.FindSession(ctx, tokenStr)
	if err != nil {
		return nil, err
	}

	if session.IsExpired() {
		_ = sm.authContext.InternalAdapter.DeleteSession(ctx, session.ID)
		return nil, errors.New("session expired")
	}

	return session, nil
}

func (sm *SessionManager) Revoke(ctx context.Context, tokenStr string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.authContext.InternalAdapter.DeleteSession(ctx, tokenStr)
}
