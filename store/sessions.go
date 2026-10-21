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
	return s.create(ctx, sess, nil)
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

// UpdateSessionIn is UpdateSession for a session that is in state when the
// change is written. The state is checked in the write itself (UpdateOne
// re-checks its expression), so of several calls that move one session out
// of a state at once, one does. A session in another state gets a NotFound
// error, as a missing one does.
func (s *Store) UpdateSessionIn(ctx context.Context, id string, state models.SessionState, changes behemoth.M) (*models.Session, error) {
	updated, err := s.update(ctx, &models.Session{}, id, changes, models.SessionUpdatedAt, nil,
		clause.Condition{Field: models.SessionStateColumn, Operator: clause.OpEqual, Value: string(state)})
	if err != nil {
		return nil, err
	}
	return updated.(*models.Session), nil
}

// CountActiveSessions counts userID's sessions that are active and have not
// expired: the sessions SessionConfig.MaxConcurrent limits. A session that
// waits for a second factor is not counted, and neither is one past its
// expiry that nothing revoked.
//
// The expiry is compared with the store's clock (Now) in the database. On
// SQLite, which stores a time as text with its zone, a session whose expiry
// was written in a zone other than UTC can be counted wrongly; the session
// manager writes expiries from Now.
func (s *Store) CountActiveSessions(ctx context.Context, userID string) (int64, error) {
	return s.db.Count(ctx, &models.Session{}, s.activeSessionsOf(userID))
}

// ListActiveSessions lists the sessions CountActiveSessions counts, oldest
// first. limit <= 0 means no limit.
func (s *Store) ListActiveSessions(ctx context.Context, userID string, limit int) ([]*models.Session, error) {
	return s.findSessions(ctx, s.activeSessionsOf(userID),
		&behemoth.QueryOptions{OrderBy: behemoth.Order{Field: models.SessionCreatedAt, Direction: behemoth.Asc}, Limit: limit})
}

// ListLiveSessions lists userID's sessions that aren't revoked, pending and
// expired ones included, oldest first, except exceptID ("" for none).
// limit <= 0 means no limit.
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

func (s *Store) activeSessionsOf(userID string) clause.Expression {
	return clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
		{Field: models.SessionUserID, Operator: clause.OpEqual, Value: userID},
		{Field: models.SessionStateColumn, Operator: clause.OpEqual, Value: string(models.SessionActive)},
		{Field: models.SessionExpiresAt, Operator: clause.OpGreaterThan, Value: s.now()},
	}}
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
