package store

import (
	"context"
	"fmt"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/clause"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/models"
)

// codeAttempts bounds the retries of the two verification code writes that
// can lose a race to another call for the same code.
const codeAttempts = 8

func codeKey(kind models.CodeKind, subject string) clause.Expression {
	return clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
		{Field: models.VerificationCodeKindColumn, Operator: clause.OpEqual, Value: string(kind)},
		{Field: models.VerificationCodeSubject, Operator: clause.OpEqual, Value: subject},
	}}
}

// ReplaceVerificationCode stores c as the one code for its kind and subject,
// assigning its id and created_at. A code that was there is removed first.
// Of two calls racing for one kind and subject, one row is left; which
// call's is not defined.
//
// The table fires no data hooks, so the writes are plain, like the rate
// limit counters'.
func (s *Store) ReplaceVerificationCode(ctx context.Context, c *models.VerificationCode) error {
	for range codeAttempts {
		if err := s.db.DeleteMany(ctx, &models.VerificationCode{}, codeKey(c.Kind, c.Subject)); err != nil {
			return err
		}
		c.ID, c.CreatedAt = s.newID(), s.now()
		err := s.db.Create(ctx, c)
		if errs.IsDuplicateKey(err) {
			continue // another call stored one in between
		}
		return err
	}
	return fmt.Errorf("store: verification code for %q still contended after %d attempts", c.Kind, codeAttempts)
}

// FindVerificationCode returns the code for kind and subject, expired or
// not, or a NotFound error.
func (s *Store) FindVerificationCode(ctx context.Context, kind models.CodeKind, subject string) (*models.VerificationCode, error) {
	found, err := s.db.FindOne(ctx, &models.VerificationCode{}, codeKey(kind, subject))
	if err != nil {
		return nil, err
	}
	return found.(*models.VerificationCode), nil
}

// SpendVerificationCodeAttempt takes one attempt off the code for kind and
// subject and returns the code as it was before, with AttemptsLeft still
// counting the attempt taken. It returns a NotFound error when there is no
// code or it has no attempt left.
//
// The write is guarded on the count that was read (UpdateOne re-checks its
// expression in the write), so several calls at once each take a different
// attempt, and no more calls succeed than the code had attempts.
func (s *Store) SpendVerificationCodeAttempt(ctx context.Context, kind models.CodeKind, subject string) (*models.VerificationCode, error) {
	for range codeAttempts {
		c, err := s.FindVerificationCode(ctx, kind, subject)
		if err != nil {
			return nil, err
		}
		if c.AttemptsLeft <= 0 {
			return nil, errs.NewNotFound("Store.SpendVerificationCodeAttempt", models.VerificationCodeTable, nil)
		}
		guard := clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
			{Field: models.VerificationCodeID, Operator: clause.OpEqual, Value: c.ID},
			{Field: models.VerificationCodeAttemptsLeft, Operator: clause.OpEqual, Value: c.AttemptsLeft},
		}}
		err = s.db.UpdateOne(ctx, &models.VerificationCode{}, guard, behemoth.M{models.VerificationCodeAttemptsLeft: c.AttemptsLeft - 1})
		if errs.IsNotFound(err) {
			continue // another call took this attempt, or the code was replaced
		}
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, fmt.Errorf("store: verification code for %q still contended after %d attempts", kind, codeAttempts)
}

// DeleteVerificationCode removes the code with id. It returns a NotFound
// error when the code is already gone, which is what makes using a code up
// an at-most-once step.
func (s *Store) DeleteVerificationCode(ctx context.Context, id string) error {
	return s.db.DeleteOne(ctx, &models.VerificationCode{}, eq(models.VerificationCodeID, id))
}

// DeleteVerificationCodeFor removes the code for kind and subject, if any.
func (s *Store) DeleteVerificationCodeFor(ctx context.Context, kind models.CodeKind, subject string) error {
	return s.db.DeleteMany(ctx, &models.VerificationCode{}, codeKey(kind, subject))
}

// PurgeExpiredVerificationCodes deletes the codes that have expired. A code
// is replaced when its subject asks for another and removed when it is used,
// so this reclaims the ones that were never used. Like the other purges it
// does one pass and is safe to run from several processes.
func (s *Store) PurgeExpiredVerificationCodes(ctx context.Context) error {
	return s.db.DeleteMany(ctx, &models.VerificationCode{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.VerificationCodeExpiresAt, Operator: clause.OpLessEq, Value: s.now()},
	}})
}
