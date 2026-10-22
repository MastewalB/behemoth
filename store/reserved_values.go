package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
)

// reserveAttempts bounds the retries of ReserveValue, whose write can lose a
// race to another call for the same value.
const reserveAttempts = 8

func reservationKey(column, value string) clause.Expression {
	return clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
		{Field: models.ReservedValueColumn, Operator: clause.OpEqual, Value: column},
		{Field: models.ReservedValueValue, Operator: clause.OpEqual, Value: value},
	}}
}

// ReserveValue keeps value of the users column column (a canonical name,
// such as models.UserEmail) for userID until until. Until then
// CheckReservedValue refuses the value to every other user. value is in the
// form the column stores it.
//
// A reservation userID already has that lasts longer is kept, and a shorter
// one is extended. A reservation of another user is replaced, expired or
// not: the caller reserves a value it holds, so another user's reservation of
// it is left over or was bypassed. Of calls that race for one value, the one
// that writes last sets the reservation.
//
// The table fires no data hooks, so the writes are plain, like the one-time
// codes'.
func (s *Store) ReserveValue(ctx context.Context, column, value, userID string, until time.Time) error {
	until = until.UTC()
	for range reserveAttempts {
		found, err := s.FindReservedValue(ctx, column, value)
		if errs.IsNotFound(err) {
			r := &models.ReservedValue{ID: s.newID(), Column: column, Value: value, UserID: userID, ExpiresAt: until, CreatedAt: s.now()}
			err = s.db.Create(ctx, r)
			if errs.IsDuplicateKey(err) {
				continue // another call stored one in between
			}
			return err
		}
		if err != nil {
			return err
		}
		if found.UserID == userID && !found.ExpiresAt.Before(until) {
			return nil
		}
		changes := behemoth.M{models.ReservedValueUserID: userID, models.ReservedValueExpiresAt: until}
		if found.UserID != userID {
			changes[models.ReservedValueCreatedAt] = s.now()
		}
		// Guarded on the holder that was read, so a call that replaced it in
		// between is not overwritten by a decision made without it.
		guard := clause.Expression{Logic: clause.OpAnd, Conditions: []clause.Condition{
			{Field: models.ReservedValueID, Operator: clause.OpEqual, Value: found.ID},
			{Field: models.ReservedValueUserID, Operator: clause.OpEqual, Value: found.UserID},
		}}
		err = s.db.UpdateOne(ctx, &models.ReservedValue{}, guard, changes)
		if errs.IsNotFound(err) {
			continue // released or replaced in between
		}
		return err
	}
	return fmt.Errorf("store: reservation of %s %q still contended after %d attempts", column, value, reserveAttempts)
}

// FindReservedValue returns the reservation of value in column, expired or
// not, or a NotFound error.
func (s *Store) FindReservedValue(ctx context.Context, column, value string) (*models.ReservedValue, error) {
	found, err := s.db.FindOne(ctx, &models.ReservedValue{}, reservationKey(column, value))
	if err != nil {
		return nil, err
	}
	return found.(*models.ReservedValue), nil
}

// CheckReservedValue returns the error a write gets when it gives value of
// column to a user other than the one it is reserved for. It is the
// conflict the store answers for a value another user holds: the column's
// code, such as email_taken (see errs.NewTaken), with a duplicate key on
// column inside, so errs.IsDuplicateKey and errs.DuplicateKeyColumns treat
// a reserved value as a taken one. It returns nil when value is not
// reserved, when its reservation has expired, and when it is userID's.
// userID is empty for a user being created.
//
// It is for a data.user.beforeCreate or beforeUpdate handler of the
// plugin that reserves the column's values. Call it on hctx.Tx.
func (s *Store) CheckReservedValue(ctx context.Context, column, value, userID string) error {
	const op = "Store.CheckReservedValue"
	found, err := s.FindReservedValue(ctx, column, value)
	if errs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if found.UserID == userID || !s.now().Before(found.ExpiresAt) {
		return nil
	}
	return s.taken(op, models.UserTable, errs.NewDuplicateKeyOn(op, models.UserTable, []string{column}, nil))
}

// ReleaseReservedValue removes the reservation of value in column if it is
// userID's. A value that is not reserved, or is reserved for another user,
// is left as it is.
func (s *Store) ReleaseReservedValue(ctx context.Context, column, value, userID string) error {
	key := reservationKey(column, value)
	key.Conditions = append(key.Conditions, clause.Condition{Field: models.ReservedValueUserID, Operator: clause.OpEqual, Value: userID})
	return s.db.DeleteMany(ctx, &models.ReservedValue{}, key)
}

// PurgeExpiredReservedValues deletes the reservations that have expired. An
// expired one refuses nothing already, so this only reclaims the rows. Like
// the other purges it does one pass and is safe to run from several
// processes.
func (s *Store) PurgeExpiredReservedValues(ctx context.Context) error {
	return s.db.DeleteMany(ctx, &models.ReservedValue{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.ReservedValueExpiresAt, Operator: clause.OpLessEq, Value: s.now()},
	}})
}
