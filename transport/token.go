package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/clause"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/utils"
)

type DefaultTokenManager struct {
	db      behemoth.Database
	kv      behemoth.KeyValueStorage
	idb     types.InternalAdapter
	catalog types.TokenCatalog
	crypto  types.Crypto
	cfg     types.TokenConfig
	disp    types.Dispatcher
	tel     *types.Telemetry
}

func NewDefaultTokenManager(
	db behemoth.Database,
	kv behemoth.KeyValueStorage,
	idb types.InternalAdapter,
	catalog types.TokenCatalog,
	crypto types.Crypto,
	dispatcher types.Dispatcher,
	cfg types.TokenConfig,
) types.TokenManager {
	return &DefaultTokenManager{
		db:      db,
		kv:      kv,
		idb:     idb,
		catalog: catalog,
		crypto:  crypto,
		disp:    dispatcher,
		cfg:     cfg,
	}
}

func kvKey(kind types.TokenKind, lookupHash string) string {
	return "token:" + string(kind) + ":" + lookupHash
}

func resolveTTL(def types.TokenKindDef, cfg types.TokenConfig) time.Duration {
	if override, ok := cfg.TTLOverrides[def.Kind]; ok {
		return override
	}
	return def.DefaultTTL
}

func checkConsumable(tok *types.Token) error {
	const op = "TokenManager.checkConsumable"
	if tok.RevokedAt != nil {
		return behemotherr.NewTokenError(op, "token_revoked", nil)
	}
	if !tok.ExpiresAt.IsZero() && time.Now().After(tok.ExpiresAt) {
		return behemotherr.NewTokenError(op, "token_expired", nil)
	}
	if tok.ConsumedAt != nil {
		return behemotherr.NewTokenError(op, "token_already_consumed", nil)
	}
	return nil
}

func (tm *DefaultTokenManager) Issue(
	ctx context.Context,
	kind types.TokenKind,
	subject any,
	meta behemoth.M,
) (*types.Token, string, error) {
	const op = "TokenManager.Issue"

	def, ok := tm.catalog.Lookup(kind)
	if !ok {
		return nil, "", behemotherr.NewValidationError(op, "kind", fmt.Errorf("unknown token kind %q", kind))
	}

	if def.Backend == types.TokenBackendKV && tm.kv == nil {
		// this should already have been caught at Boot when
		// resolving backends, but a kind declared after boot misconfiguration
		// (or a bug in that check) must not silently fall through to a nil
		// pointer dereference below.
		return nil, "", behemotherr.NewConfigurationError(op, fmt.Sprintf("kind %q requires KV storage, none configured", kind), nil)
	}

	rawToken, err := tm.crypto.Random.SecureRandomString(32)
	if err != nil {
		return nil, "", behemotherr.NewSecurityError(op, "random_generation_failed", err)
	}

	hash, keyVersion, err := tm.crypto.Secrets.Hash(rawToken)
	if err != nil {
		return nil, "", err
	}

	ttl := resolveTTL(def, tm.cfg)
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	tok := &types.Token{
		ID:           utils.GenerateUUID(),
		Kind:         kind,
		Subject:      subjectString(subject),
		LookupHash:   utils.LookupHashOf(rawToken),
		TokenHash:    hash,
		KeyVersion:   keyVersion,
		ExpiresAt:    expiresAt,
		MetadataJSON: meta,
		CreatedAt:    time.Now(),
	}

	hctx := &types.HookContext{Ctx: ctx}

	if _, err := tm.disp.RunBefore(hctx, hooks.HookTokenBeforeIssue, behemoth.M{
		hooks.HookValueTokenKind:    string(kind),
		hooks.HookValueTokenSubject: subjectString(subject),
	}); err != nil {
		return nil, "", err
	}

	if err := tm.persist(ctx, def, tok, ttl); err != nil {
		return nil, "", behemotherr.WrapOp(op, "token", err)
	}

	tm.disp.RunAfter(&types.HookContext{Ctx: ctx}, hooks.HookTokenIssue, tok)
	return tok, rawToken, nil
}

func subjectString(subject any) string {
	if subject == nil {
		return ""
	}
	return fmt.Sprint(subject)
}

func (tm *DefaultTokenManager) persist(ctx context.Context, def types.TokenKindDef, token *types.Token, ttl time.Duration) error {
	const op = "TokenManager.persist"
	switch def.Backend {
	case types.TokenBackendKV:
		data, err := json.Marshal(token)
		if err != nil {
			return behemotherr.NewValidationError(op, "token", err)
		}
		ttlSeconds := int(ttl.Seconds())
		if ttlSeconds <= 0 {
			// A KV entry with no TTL never expires at the store level; for
			// BackendKV kinds this should never happen (they're declared with
			// a real DefaultTTL), but guard rather than silently persist forever.
			return behemotherr.NewConfigurationError(op, "BackendKV token kind must have a positive TTL", nil)
		}
		return tm.kv.Set(ctx, kvKey(types.TokenKind(token.Kind), token.LookupHash), string(data), ttlSeconds)
	default: // BackendDB
		return tm.db.Transaction(ctx, func(ctx context.Context, tx behemoth.Database) (any, error) {
			return nil, tx.Create(ctx, token)
		})
	}
}

// fetch is the shared lookup & authenticity check path used by Verify and
// Consume, so the two entry points can never drift on that logic.
func (tm *DefaultTokenManager) fetch(ctx context.Context, def types.TokenKindDef, kind types.TokenKind, rawToken string) (*types.Token, error) {
	const op = "TokenManager.fetch"
	lookupHash := utils.LookupHashOf(rawToken)

	var m *types.Token
	switch def.Backend {
	case types.TokenBackendKV:
		raw, err := tm.kv.Get(ctx, kvKey(kind, lookupHash))
		if err != nil {
			return nil, behemotherr.NewTokenError(op, behemotherr.ErrorCodeTokenNotFound, err)
		}
		m = &types.Token{}
		if err := json.Unmarshal([]byte(raw), m); err != nil {
			return nil, behemotherr.NewTokenError(op, behemotherr.ErrorCodeTokenNotFound, err) // corrupted cache entry treated as absent
		}
	default:
		found, err := tm.db.FindOne(ctx, &types.Token{}, byLookupHashAndKind(lookupHash, kind))
		if err != nil {
			return nil, behemotherr.WrapOp(op, "token", err) // NotFound re-contextualized from adapter's raw "FindOne"/"tokens"
		}
		m = found.(*types.Token)
	}

	ok, err := tm.crypto.Secrets.Verify(rawToken, m.TokenHash, m.KeyVersion)
	if err != nil {
		return nil, err
	}
	if !ok {
		// LookupHash matched but keyed HMAC didn't
		return nil, behemotherr.NewTokenError(op, behemotherr.ErrorCodeTokenNotFound, nil)
	}
	return m, nil
}

func (tm *DefaultTokenManager) Verify(ctx context.Context, kind types.TokenKind, rawToken string) (*types.Token, error) {
	const op = "TokenManager.Verify"

	def, ok := tm.catalog.Lookup(kind)
	if !ok {
		return nil, behemotherr.NewValidationError(op, "kind", fmt.Errorf("unknown token kind %q", kind))
	}

	m, err := tm.fetch(ctx, def, kind, rawToken)
	if err != nil {
		return nil, err // already fully classified inside fetch
	}
	if err := checkConsumable(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (tm *DefaultTokenManager) Consume(ctx context.Context, kind types.TokenKind, rawToken string) (*types.Token, error) {
	const op = "TokenManager.Consume"

	def, ok := tm.catalog.Lookup(kind)
	if !ok {
		return nil, behemotherr.NewValidationError(op, "kind", fmt.Errorf("unknown token kind %q", kind))
	}

	if !def.SingleUse {
		// Calling Consume() a multi-use credential (an API key) would permanently
		// disable it on first use
		return nil, behemotherr.NewTokenError(op, behemotherr.ErrorCodeTokenInvalidUsage, nil)
	}

	hctx := &types.HookContext{Ctx: ctx}

	var result *types.Token
	var consumeErr error

	switch def.Backend {
	case types.TokenBackendDB:
		// Start transaction to fetch, validate, & consume the token
		consumeErr = tm.db.Transaction(ctx, func(ctx context.Context, tx behemoth.Database) (any, error) {
			tok, err := tm.fetch(ctx, def, kind, rawToken)
			if err != nil {
				return nil, err // already fully classified inside fetch
			}
			if err := checkConsumable(tok); err != nil {
				return nil, err
			}

			now := time.Now()
			if err := tx.UpdateOne(ctx, &types.Token{}, tokenByID(tok.ID), behemoth.M{"consumed_at": now}); err != nil {
				return nil, err
			}
			tok.ConsumedAt = &now
			result = tok
			return tok, nil
		})
	case types.TokenBackendKV:
		// KeyValueStorage exposes no transaction primitive, so this is
		// non-atomic Get-then-Delete. Two concurrent Consume calls for the
		// same token can both pass Get before either Delete runs, and both
		// would appear to succeed.
		tok, err := tm.fetch(ctx, def, kind, rawToken)
		if err != nil {
			consumeErr = err // already fully classified inside fetch
			break
		}
		if err := checkConsumable(tok); err != nil {
			consumeErr = err
			break
		}
		now := time.Now()
		tok.ConsumedAt = &now
		result = tok
	}

	if consumeErr != nil {
		tm.disp.Fail(hctx, hooks.HookTokenFailed, types.FailureReason{Code: behemotherr.ClassifyCode(consumeErr), Cause: consumeErr})
		return nil, consumeErr
	}
	tm.disp.RunAfter(hctx, hooks.HookTokenConsumed, result)
	return result, nil
}

// Revoke implements [types.TokenManager].
func (tm *DefaultTokenManager) Revoke(ctx context.Context, tokenID string) error {
	const op = "TokenManager.Revoke"

	found, err := tm.db.FindOne(ctx, &types.Token{}, tokenByID(tokenID))
	if err != nil {
		return behemotherr.WrapOp(op, "token", err)
	}

	m := found.(*types.Token)
	if m.RevokedAt != nil {
		return nil // idempotent, matches Session.Revoke's posture
	}
	now := time.Now()
	if err := tm.db.UpdateOne(ctx, &types.Token{}, tokenByID(tokenID), behemoth.M{"revoked_at": now}); err != nil {
		return behemotherr.WrapOp(op, "token", err)
	}

	return nil
}

// RevokeAllForSubject implements [types.TokenManager].
func (tm *DefaultTokenManager) RevokeAllForSubject(ctx context.Context, kind types.TokenKind, subject any) error {
	const op = "TokenManager.RevokeAllForSubject"

	def, ok := tm.catalog.Lookup(kind)
	if !ok {
		return behemotherr.NewValidationError(op, "kind", fmt.Errorf("unknown token kind %q", kind))
	}
	if def.Backend == types.TokenBackendKV {
		return behemotherr.NewConfigurationError(op, fmt.Sprintf("kind %q is KV-backed; bulk revoke by subject is not supported", kind), nil)
	}
	where := clause.Expression{Conditions: []clause.Condition{
		{Field: "kind", Operator: clause.OpEqual, Value: string(kind)},
		{Field: "subject", Operator: clause.OpEqual, Value: subjectString(subject)},
		{Field: "revoked_at", Operator: clause.OpIsNull},
	}, Logic: clause.OpAnd}
	if err := tm.db.UpdateMany(ctx, &types.Token{}, where, behemoth.M{"revoked_at": time.Now()}); err != nil {
		return behemotherr.WrapOp(op, "token", err)
	}
	return nil
}

func tokenByID(id string) clause.Expression {
	return clause.Expression{Conditions: []clause.Condition{{Field: "id", Operator: clause.OpEqual, Value: id}}}
}

func byLookupHashAndKind(hash string, kind types.TokenKind) clause.Expression {
	return clause.Expression{
		Conditions: []clause.Condition{
			{
				Field:    "lookup_hash",
				Operator: clause.OpEqual,
				Value:    hash,
			},
			{
				Field:    "kind",
				Operator: clause.OpEqual,
				Value:    kind,
			},
		},
		Logic: clause.OpAnd,
	}
}

var _ types.TokenManager = (*DefaultTokenManager)(nil)
