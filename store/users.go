package store

import (
	"context"
	"strings"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/models"
)

// NormalizeEmail is the one form emails are stored and looked up in.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateUser inserts u, assigning its ID and timestamps and normalizing its
// email. BeforeCreate hooks see the normalized email and may rewrite the
// row; an email they set is normalized again before the insert. u holds the
// stored user afterwards.
func (s *Store) CreateUser(ctx context.Context, u *models.User) error {
	now := s.now()
	u.ID = s.newID()
	u.Email = NormalizeEmail(u.Email)
	u.CreatedAt, u.UpdatedAt = now, now
	return s.create(ctx, u, normalizeUserRow)
}

// normalizeUserRow puts a user row's email, if it has one, in the stored
// form. It runs on the row a create or an update is about to write, after
// the before hooks, so no path stores an email FindUserByEmail can't find.
func normalizeUserRow(row behemoth.M) {
	if email, ok := row[models.UserEmail].(string); ok {
		row[models.UserEmail] = NormalizeEmail(email)
	}
}

func (s *Store) FindUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.findUser(ctx, eq(models.UserID, id))
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.findUser(ctx, eq(models.UserEmail, NormalizeEmail(email)))
}

// UpdateUser applies updates (canonical column names, e.g. models.UserEmail)
// to the user with id — after BeforeUpdate hooks, which may rewrite them —
// stamps updated_at, and returns the stored user. The caller's map is never
// modified.
func (s *Store) UpdateUser(ctx context.Context, id string, updates behemoth.M) (*models.User, error) {
	updated, err := s.update(ctx, &models.User{}, id, updates, models.UserUpdatedAt, normalizeUserRow)
	if err != nil {
		return nil, err
	}
	return updated.(*models.User), nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.db.DeleteOne(ctx, &models.User{}, eq(models.UserID, id))
}

func (s *Store) findUser(ctx context.Context, where clause.Expression) (*models.User, error) {
	found, err := s.db.FindOne(ctx, &models.User{}, where)
	if err != nil {
		return nil, err
	}
	return found.(*models.User), nil
}

func eq(field string, value any) clause.Expression {
	return clause.Expression{Conditions: []clause.Condition{{Field: field, Operator: clause.OpEqual, Value: value}}}
}
