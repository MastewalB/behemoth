package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/utils"
)

type dbJWKSStore struct {
	db  behemoth.Database
	enc types.Encryptor
}

func (s *dbJWKSStore) Current(ctx context.Context) (*types.JWKKeyPair, error) {
	m := &types.JWKKeyPair{}
	activeExpr := clause.Expression{}
	found, err := s.db.FindOne(ctx, m, activeExpr)
	if err != nil {
		return nil, newJWTError("JWKS.Current", "no_active_signing_key", err)
	}
	return found.(*types.JWKKeyPair), nil
}

func (s *dbJWKSStore) ByKid(ctx context.Context, kid string) (*types.JWKKeyPair, error) {
	m := &types.JWKKeyPair{}
	byIDExpr := clause.Expression{}
	found, err := s.db.FindOne(ctx, m, byIDExpr)
	if err != nil {
		return nil, newJWTError("JWKS.ByKid", "unknown_signing_key", err)
	}
	return found.(*types.JWKKeyPair), nil
}

func (s *dbJWKSStore) All(ctx context.Context) ([]*types.JWKKeyPair, error) {
	m := &types.JWKKeyPair{}
	expr := clause.Expression{}
	found, err := s.db.FindMany(ctx, m, expr, nil)
	if err != nil {
		return nil, newJWTError("JWKS.All", "error_retrieving_keys", err)
	}
	var pairs []*types.JWKKeyPair
	for _, p := range found {
		pairs = append(pairs, p.(*types.JWKKeyPair))
	}
	return pairs, nil
}

func (s *dbJWKSStore) Rotate(ctx context.Context) (*types.JWKKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, newJWTError("JWKS.Rotate", "keygen_failed", err)
	}

	encPriv, keyVersion, err := s.enc.Encrypt(priv)
	if err != nil {
		return nil, err // already classified by Encryptor
	}

	activeExpr := clause.Expression{}
	var kp *types.JWKKeyPair

	err = s.db.Transaction(ctx, func(ctx context.Context, tx behemoth.Database) (any, error) {
		// Demote the previous key before inserting the new one
		if err := tx.UpdateMany(ctx, &types.JWKKeyPair{}, activeExpr, behemoth.M{"active": false}); err != nil {
			return nil, err
		}
		kp = &types.JWKKeyPair{
			ID:                  utils.GenerateUUID(),
			Algorithm:           "EdDSA",
			PublicKey:           pub,
			EncryptedPrivateKey: encPriv,
			PrivateKeyVersion:   keyVersion,
			Active:              true,
			CreatedAt:           time.Now(),
		}
		return kp, tx.Create(ctx, kp)
	})

	if err != nil {
		return nil, newJWTError("JWKS.Rotate", "key_update_failed", err)
	}

	return kp, nil
}
