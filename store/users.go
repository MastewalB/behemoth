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

// DeleteUser deletes the user with id and everything that lets someone act
// as that user: the user's sessions, accounts and database-backed tokens. It
// returns a NotFound error when there is no such user.
//
// The deletes share one transaction, the caller's when s is bound to one,
// and run children first, so they work whether or not the database enforces
// the foreign keys to users:
//
//  1. BeforeDelete (data.user.beforeDelete), which may refuse the delete
//  2. the user's sessions, revoked ones included
//  3. the user's accounts
//  4. the tokens whose subject is the user's id
//  5. the user
//  6. AfterDelete (data.user.afterDelete), whose error rolls all of it back
//
// The store does not rely on ON DELETE CASCADE: a cascade removes session
// rows without telling anyone, so their cache entries would keep the tokens
// valid and no hook would fire. AfterDelete is given the deleted sessions for
// that reason; under Boot it clears their cache entries and, once the
// transaction has committed, fires auth.session.afterRevoke for each one that
// was live, then data.user.deleted.
//
// Not covered: a token in a key-value storage can't be found by its subject
// and expires on its own, and a token issued to something other than the
// user's id (an email address) is the issuing plugin's to delete, from a
// handler on data.user.beforeDelete. Sessions in which the user is the
// impersonator are left alone.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.Transaction(ctx, func(ctx context.Context, tx *Store) error {
		ctx = tx.hooks.Begin(ctx, models.UserTable)
		user, err := tx.findUser(ctx, eq(models.UserID, id))
		if err != nil {
			return err
		}
		if err := tx.hooks.BeforeDelete(ctx, tx, models.UserTable, user); err != nil {
			return err // the hook's error is the abort; returned as-is
		}

		sessions, err := tx.ListSessionsForUser(ctx, id)
		if err != nil {
			return err
		}
		for _, owned := range []struct {
			model  behemoth.Model
			column string
		}{
			{&models.Session{}, models.SessionUserID},
			{&models.Account{}, models.AccountUserID},
			{&models.Token{}, models.TokenSubject},
		} {
			if err := tx.db.DeleteMany(ctx, owned.model, eq(owned.column, id)); err != nil {
				return err
			}
		}
		if err := tx.db.DeleteOne(ctx, &models.User{}, eq(models.UserID, id)); err != nil {
			return err
		}
		// The hook's error rolls the delete back; returned as-is.
		return tx.hooks.AfterDelete(ctx, tx, models.UserTable, user, sessions)
	})
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
