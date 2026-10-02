package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
)

// ErrorCodeTokenAlreadyConsumed is the code ConsumeToken's error carries
// when another call consumed the token first.
const ErrorCodeTokenAlreadyConsumed = "token_already_consumed"

// CreateToken inserts tok, assigning its ID and creation time. Hashes, kind,
// subject and expiry are the token manager's to set.
func (s *Store) CreateToken(ctx context.Context, tok *models.Token) error {
	tok.ID = s.newID()
	tok.CreatedAt = s.now()
	return s.create(ctx, tok)
}

func (s *Store) FindTokenByID(ctx context.Context, id string) (*models.Token, error) {
	return s.findToken(ctx, eq(models.TokenID, id))
}

func (s *Store) FindTokenByLookupHash(ctx context.Context, kind models.TokenKind, lookupHash string) (*models.Token, error) {
	return s.findToken(ctx, clause.Expression{Conditions: []clause.Condition{
		{Field: models.TokenLookupHash, Operator: clause.OpEqual, Value: lookupHash},
		{Field: models.TokenKindColumn, Operator: clause.OpEqual, Value: string(kind)},
	}, Logic: clause.OpAnd})
}

// ConsumeToken marks the token with id consumed — at most once, however many
// calls race for it — and returns the time it recorded. A call that loses the
// race gets a token error with ErrorCodeTokenAlreadyConsumed; an unknown id
// gets NotFound.
//
// The update is guarded (consumed_at must still be NULL), and UpdateOne
// checks its expression against the row as written and returns NotFound when
// nothing matched (the behemoth.Database convention). So exactly one of
// several concurrent calls wins, at any isolation level, with or without an
// enclosing transaction.
func (s *Store) ConsumeToken(ctx context.Context, id string) (time.Time, error) {
	const op = "Store.ConsumeToken"
	at := s.now()
	err := s.db.UpdateOne(ctx, &models.Token{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.TokenID, Operator: clause.OpEqual, Value: id},
		{Field: models.TokenConsumedAt, Operator: clause.OpIsNull},
	}, Logic: clause.OpAnd}, behemoth.M{models.TokenConsumedAt: at})
	if behemotherr.IsNotFound(err) {
		if _, findErr := s.FindTokenByID(ctx, id); findErr != nil {
			return time.Time{}, findErr // no such token
		}
		return time.Time{}, behemotherr.NewTokenError(op, ErrorCodeTokenAlreadyConsumed, nil)
	}
	if err != nil {
		return time.Time{}, err
	}
	return at, nil
}

// RevokeToken marks the token with id revoked. Revoking a revoked token is a
// no-op — the first revocation time is kept; an unknown id gets NotFound.
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	err := s.db.UpdateOne(ctx, &models.Token{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.TokenID, Operator: clause.OpEqual, Value: id},
		{Field: models.TokenRevokedAt, Operator: clause.OpIsNull},
	}, Logic: clause.OpAnd}, behemoth.M{models.TokenRevokedAt: s.now()})
	if behemotherr.IsNotFound(err) {
		_, findErr := s.FindTokenByID(ctx, id)
		return findErr // nil: it exists, so it was already revoked
	}
	return err
}

// RevokeTokensForSubject revokes every unrevoked token of kind issued to
// subject.
func (s *Store) RevokeTokensForSubject(ctx context.Context, kind models.TokenKind, subject string) error {
	return s.db.UpdateMany(ctx, &models.Token{}, clause.Expression{Conditions: []clause.Condition{
		{Field: models.TokenKindColumn, Operator: clause.OpEqual, Value: string(kind)},
		{Field: models.TokenSubject, Operator: clause.OpEqual, Value: subject},
		{Field: models.TokenRevokedAt, Operator: clause.OpIsNull},
	}, Logic: clause.OpAnd}, behemoth.M{models.TokenRevokedAt: s.now()})
}

func (s *Store) findToken(ctx context.Context, where clause.Expression) (*models.Token, error) {
	found, err := s.db.FindOne(ctx, &models.Token{}, where)
	if err != nil {
		return nil, err
	}
	tok, ok := found.(*models.Token)
	if !ok {
		return nil, fmt.Errorf("store: unexpected %T in tokens", found)
	}
	return tok, nil
}
