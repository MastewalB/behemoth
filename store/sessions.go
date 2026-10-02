package store

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/models"
)

// CreateSession inserts sess, assigning its ID and created/updated
// timestamps. Everything else — hashes, state, expiry — is the session
// manager's to set. sess holds the stored session afterwards.
func (s *Store) CreateSession(ctx context.Context, sess *models.Session) error {
	now := s.now()
	sess.ID = s.newID()
	sess.CreatedAt, sess.UpdatedAt = now, now
	return s.create(ctx, sess)
}

func (s *Store) FindSessionByID(ctx context.Context, id string) (*models.Session, error) {
	return s.findSession(ctx, eq(models.SessionID, id))
}

func (s *Store) FindSessionByLookupHash(ctx context.Context, lookupHash string) (*models.Session, error) {
	return s.findSession(ctx, eq(models.SessionLookupHash, lookupHash))
}

// UpdateSession applies changes (canonical column names) to the session with
// id, stamps updated_at, and returns the stored session.
func (s *Store) UpdateSession(ctx context.Context, id string, changes behemoth.M) (*models.Session, error) {
	updated, err := s.update(ctx, &models.Session{}, id, changes, models.SessionUpdatedAt, nil)
	if err != nil {
		return nil, err
	}
	return updated.(*models.Session), nil
}

// CountLiveSessions counts userID's sessions that aren't revoked — pending
// ones included: an abandoned half-completed login still occupies a slot.
func (s *Store) CountLiveSessions(ctx context.Context, userID string) (int64, error) {
	return s.db.Count(ctx, &models.Session{}, liveSessionsOf(userID, ""))
}

// ListLiveSessions lists userID's sessions that aren't revoked, oldest
// first, except exceptID ("" for none). limit <= 0 means no limit.
func (s *Store) ListLiveSessions(ctx context.Context, userID, exceptID string, limit int) ([]*models.Session, error) {
	return s.findSessions(ctx, liveSessionsOf(userID, exceptID),
		&behemoth.QueryOptions{OrderBy: behemoth.Order{Field: models.SessionCreatedAt, Direction: behemoth.Asc}, Limit: limit})
}

// ListSessionsForUser lists all of userID's sessions, revoked included,
// newest first.
func (s *Store) ListSessionsForUser(ctx context.Context, userID string) ([]*models.Session, error) {
	return s.findSessions(ctx, eq(models.SessionUserID, userID),
		&behemoth.QueryOptions{OrderBy: behemoth.Order{Field: models.SessionCreatedAt, Direction: behemoth.Desc}})
}

func liveSessionsOf(userID, exceptID string) clause.Expression {
	conds := []clause.Condition{
		{Field: models.SessionUserID, Operator: clause.OpEqual, Value: userID},
		{Field: models.SessionStateColumn, Operator: clause.OpNotEqual, Value: string(models.SessionRevoked)},
	}
	if exceptID != "" {
		conds = append(conds, clause.Condition{Field: models.SessionID, Operator: clause.OpNotEqual, Value: exceptID})
	}
	return clause.Expression{Conditions: conds, Logic: clause.OpAnd}
}

func (s *Store) findSession(ctx context.Context, where clause.Expression) (*models.Session, error) {
	found, err := s.db.FindOne(ctx, &models.Session{}, where)
	if err != nil {
		return nil, err
	}
	return found.(*models.Session), nil
}

func (s *Store) findSessions(ctx context.Context, where clause.Expression, opts *behemoth.QueryOptions) ([]*models.Session, error) {
	found, err := s.db.FindMany(ctx, &models.Session{}, where, opts)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Session, len(found))
	for i, f := range found {
		sess, ok := f.(*models.Session)
		if !ok {
			return nil, fmt.Errorf("store: unexpected %T in sessions", f)
		}
		out[i] = sess
	}
	return out, nil
}
