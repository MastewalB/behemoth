package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/utils"
)

type DefaultSessionManager struct {
	st     *store.Store
	kv     behemoth.KeyValueStorage
	crypto types.Crypto
	cfg    types.SessionConfig
	disp   types.Dispatcher
	tel    *types.Telemetry
}

func cacheKey(lookupHash string) string { return "session:" + lookupHash }

func NewSessionManager(
	st *store.Store,
	kv behemoth.KeyValueStorage,
	crypto types.Crypto,
	cfg types.SessionConfig,
	disp types.Dispatcher,
	tel *types.Telemetry,
) types.SessionManager {
	return &DefaultSessionManager{
		st:     st,
		kv:     kv,
		crypto: crypto,
		cfg:    cfg,
		disp:   disp,
		tel:    tel,
	}
}

func (sm *DefaultSessionManager) Create(ctx context.Context, userID any, meta types.SessionMeta) (*models.Session, string, error) {
	const op = "SessionManager.Create"

	if meta.State != types.SessionActive && meta.State != types.SessionPending {
		return nil, "", behemotherr.NewValidationError(op, "state", fmt.Errorf("SessionMeta.State must be Active or Pending"))
	}

	// MaxConcurrent enforcement (SessionConfig)
	if sm.cfg.MaxConcurrent > 0 {
		count, err := sm.st.CountLiveSessions(ctx, fmt.Sprint(userID))
		if err != nil {
			return nil, "", behemotherr.WrapOp(op, "session", err)
		}
		if count >= int64(sm.cfg.MaxConcurrent) {
			if sm.cfg.EvictOldestOnLimit {
				if err := sm.evictOldest(ctx, userID); err != nil {
					return nil, "", err
				}
			} else {
				return nil, "", behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionLimitReached, nil)

			}
		}
	}

	// Token generation & hashing
	rawToken, err := sm.crypto.Random.SecureRandomString(32)
	if err != nil {
		return nil, "", behemotherr.NewSecurityError(op, "random_generation_failed", err)
	}
	lookupHash := utils.LookupHashOf(rawToken)

	tokenHash, keyVersion, err := sm.crypto.Secrets.Hash(rawToken)
	if err != nil {
		return nil, "", err // already classified (CategorySecurity) by SecretHasher/KeyManager
	}

	// SessionConfig: expiry selection, IP/UA capture toggle
	ttl := sm.cfg.ExpiresIn
	if meta.State == types.SessionPending {
		ttl = sm.cfg.PendingExpiresIn
	}
	ip, ua := meta.IPAddress, meta.UserAgent
	if !sm.cfg.CaptureIPAndAgent {
		ip, ua = "", ""
	}

	now := time.Now()
	hctx := hookContext(ctx)
	payload, err := sm.disp.RunBefore(hctx, hooks.HookSessionCreate, behemoth.M{
		hooks.HookValueUserID: fmt.Sprint(userID), hooks.HookValueState: string(meta.State),
		hooks.HookValueIPAddress: ip, hooks.HookValueUserAgent: ua,
	})
	if err != nil {
		return nil, "", err
	}

	// A before-hook may have annotated ip/userAgent (e.g. a geo-lookup plugin)
	// pull any such enrichment back out; unknown keys are simply absent, no error.
	if v, ok := payload[hooks.HookValueUserAgent].(string); ok {
		ua = v
	}

	m := &models.Session{
		UserID:       fmt.Sprint(userID),
		LookupHash:   lookupHash,
		TokenHash:    tokenHash,
		KeyVersion:   keyVersion,
		State:        models.SessionState(meta.State),
		ExpiresAt:    now.Add(ttl),
		LastActiveAt: now,
		FreshAt:      now,
		IPAddress:    ip,
		UserAgent:    ua,
	}
	if err := sm.st.CreateSession(ctx, m); err != nil {
		return nil, "", behemotherr.WrapOp(op, "session", err)
	}

	sm.cacheSet(ctx, m)
	sm.disp.RunAfter(hctx, hooks.HookSessionCreate, m)

	return m, rawToken, nil

}

func (sm *DefaultSessionManager) evictOldest(ctx context.Context, userID any) error {
	oldest, err := sm.st.ListLiveSessions(ctx, fmt.Sprint(userID), "", 1)
	if err != nil || len(oldest) == 0 {
		return err
	}
	return sm.revokeModel(ctx, oldest[0], "evicted_over_limit")
}

func (sm *DefaultSessionManager) Get(ctx context.Context, rawToken string) (*models.Session, error) {
	const op = "SessionManager.Get"
	lookupHash := utils.LookupHashOf(rawToken)

	m, fromCache, err := sm.fetchByLookupHash(ctx, lookupHash)
	if err != nil {
		return nil, behemotherr.WrapOp(op, "session", err)
	}

	ok, err := sm.crypto.Secrets.Verify(rawToken, m.TokenHash, m.KeyVersion)
	if err != nil {
		return nil, err
	}

	if !ok {
		// LookupHash matched but the keyed HMAC didn't; collapse into the
		// same NotFound response
		return nil, behemotherr.NewNotFound(op, "session", nil)
	}

	if m.State == models.SessionRevoked {
		return nil, behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionRevoked, nil)
	}
	if time.Now().After(m.ExpiresAt) {
		return nil, behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionExpired, nil)
	}

	// Rotate key on-use: migrate to the current key version transparently
	if m.KeyVersion != sm.crypto.Keys.CurrentVersion() {
		newHash, newVersion, err := sm.crypto.Secrets.Hash(rawToken)
		if err == nil {
			if _, err := sm.st.UpdateSession(ctx, m.ID,
				behemoth.M{models.SessionTokenHash: newHash, models.SessionKeyVersion: newVersion}); err == nil {
				m.TokenHash, m.KeyVersion = newHash, newVersion
			}
		}
	}

	if !fromCache {
		sm.cacheSet(ctx, m) // populate cache on the way back from a DB read
	}

	return m, nil
}

func (sm *DefaultSessionManager) Validate(ctx context.Context, rawToken string) (*models.Session, error) {
	session, err := sm.Get(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if session.State == models.SessionPending {
		return nil, behemotherr.NewSessionError("SessionManager.Validate", behemotherr.ErrorCodeSessionPending, nil)
	}

	return session, nil
}

func (sm *DefaultSessionManager) Promote(ctx context.Context, sessionID string) (*models.Session, error) {
	const op = "SessionManager.Promote"
	m, err := sm.st.FindSessionByID(ctx, sessionID)
	if err != nil {
		return nil, behemotherr.WrapOp(op, "session", err)
	}

	// Transition rule enforcement
	if m.State == models.SessionRevoked {
		return nil, behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionRevoked, nil) // Revoked never transitions anywhere
	}
	if m.State != models.SessionPending {
		return nil, behemotherr.NewSessionError(op, "invalid_state_transition",
			fmt.Errorf("only a Pending session can be promoted (was %q)", m.State))
	}
	if time.Now().After(m.ExpiresAt) {
		// An abandoned pending session (2FA never completed in time) cannot
		// be resurrected by promotion; it must re-authenticate from scratch.
		return nil, behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionExpired, nil)
	}

	now := time.Now()
	// Promotion resets to the FULL Active expiry window.
	promoted, err := sm.st.UpdateSession(ctx, sessionID, behemoth.M{
		models.SessionStateColumn: string(models.SessionActive),
		models.SessionFreshAt:     now,
		models.SessionExpiresAt:   now.Add(sm.cfg.ExpiresIn),
	})
	if err != nil {
		return nil, behemotherr.WrapOp(op, "session", err)
	}
	sm.cacheSet(ctx, promoted)
	return promoted, nil
}

func (sm *DefaultSessionManager) Touch(ctx context.Context, sessionID string) error {
	const op = "SessionManager.Touch"

	m, err := sm.st.FindSessionByID(ctx, sessionID)
	if err != nil {
		return behemotherr.WrapOp(op, "session", err)
	}
	if m.State == models.SessionRevoked {
		return nil // silently no-op; a revoked session being "used" isn't an error worth surfacing to request middleware
	}

	// Throttle: only actually write if we've crossed (ExpiresAt - UpdateAge).
	// Extending on every request would mean a write per authenticated
	// request at scale.
	threshold := m.ExpiresAt.Add(-sm.cfg.UpdateAge)
	if time.Now().Before(threshold) {
		return nil // not due yet
	}

	now := time.Now()
	ttl := sm.cfg.ExpiresIn
	if m.State == models.SessionPending {
		ttl = sm.cfg.PendingExpiresIn
	}
	touched, err := sm.st.UpdateSession(ctx, sessionID, behemoth.M{
		models.SessionLastActiveAt: now,
		models.SessionExpiresAt:    now.Add(ttl),
	})
	if err != nil {
		return behemotherr.WrapOp(op, "session", err)
	}
	sm.cacheSet(ctx, touched)
	return nil
}

// ListForUser implements [types.SessionManager].
func (sm *DefaultSessionManager) ListForUser(ctx context.Context, userID any) ([]*models.Session, error) {
	sessions, err := sm.st.ListSessionsForUser(ctx, fmt.Sprint(userID))
	if err != nil {
		return nil, behemotherr.WrapOp("SessionManager.ListForUser", "session", err)
	}
	return sessions, nil
}

// Revoke implements [types.SessionManager].
func (sm *DefaultSessionManager) Revoke(ctx context.Context, sessionID string, reason string) error {
	const op = "SessionManager.Revoke"

	m, err := sm.st.FindSessionByID(ctx, sessionID)
	if err != nil {
		return behemotherr.WrapOp(op, "session", err)
	}
	err = sm.revokeModel(ctx, m, reason)
	if err != nil {
		return behemotherr.WrapOp(op, "session", err)
	}
	return nil
}

// RevokeAllForUser implements [types.SessionManager].
func (sm *DefaultSessionManager) RevokeAllForUser(ctx context.Context, userID any, reason string, except string) error {
	const op = "SessionManager.RevokeAllForUser"

	live, err := sm.st.ListLiveSessions(ctx, fmt.Sprint(userID), except, 0)
	if err != nil {
		return behemotherr.WrapOp(op, "session", err)
	}
	for _, m := range live {
		if err := sm.revokeModel(ctx, m, reason); err != nil {
			return behemotherr.WrapOp(op, "session", err)
		}
	}
	return nil
}

// SupportsRevocation implements [types.SessionManager].
func (sm *DefaultSessionManager) SupportsRevocation() bool { return true }

func (sm *DefaultSessionManager) WriteToken(rctx *types.RequestContext, rawToken string, session *models.Session) {
	if sm.cfg.Transport == types.TransportCookie || sm.cfg.Transport == types.TransportBoth {
		rctx.Response.Cookie(&http.Cookie{
			Name: "session_token", Value: rawToken, Expires: session.ExpiresAt,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/",
		})
	}
	if sm.cfg.Transport == types.TransportHeader || sm.cfg.Transport == types.TransportBoth {
		rctx.Values["token"] = rawToken // included in the JSON response body
	}
}

func (sm *DefaultSessionManager) ExtractToken(r *http.Request) (string, bool) {
	if sm.cfg.Transport == types.TransportHeader || sm.cfg.Transport == types.TransportBoth {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer "), true
		}
	}
	if sm.cfg.Transport == types.TransportCookie || sm.cfg.Transport == types.TransportBoth {
		if c, err := r.Cookie("session_token"); err == nil {
			return c.Value, true
		}
	}
	return "", false
}

// revokeModel is the single internal path every revocation (explicit eviction,
// bulk revoke-all) funnels through
// a single-point that enforces the terminal-state rule and fires hooks/cache invalidation consistently.
func (sm *DefaultSessionManager) revokeModel(ctx context.Context, m *models.Session, reason string) error {
	if m.State == models.SessionRevoked {
		return nil // already revoked
	}

	hctx := hookContext(ctx)
	if _, err := sm.disp.RunBefore(hctx, hooks.HookSessionRevoke,
		behemoth.M{hooks.HookValueSessionID: m.ID, hooks.HookValueReason: reason}); err != nil {
		return err
	}

	now := time.Now()
	revoked, err := sm.st.UpdateSession(ctx, m.ID, behemoth.M{
		models.SessionStateColumn:   string(models.SessionRevoked),
		models.SessionRevokedAt:     now,
		models.SessionRevokedReason: reason,
	})
	if err != nil {
		return err
	}
	*m = *revoked

	// Active invalidation without relying on the KV entry's TTL to lapse
	// naturally, which would leave a revoked session validatable from cache
	// for up to its remaining TTL. This is the one place cacheSet is wrong
	// and an explicit Delete is required instead.
	sm.cacheDelete(ctx, m.LookupHash)

	sm.disp.RunAfter(hctx, hooks.HookSessionRevoke, m)
	return nil
}

func (sm *DefaultSessionManager) fetchByLookupHash(ctx context.Context, lookupHash string) (*models.Session, bool, error) {
	if sm.kv != nil {
		if raw, err := sm.kv.Get(ctx, cacheKey(lookupHash)); err == nil {
			var m models.Session
			if json.Unmarshal([]byte(raw), &m) == nil {
				return &m, true, nil
			}
		}
		// Cache miss OR unavailable — fall through to DB. A down/misbehaving
		// KV must never turn into a hard failure here; it's an optimization,
		// never a correctness dependency (same fail-open posture as Rate Limiting).
	}
	m, err := sm.st.FindSessionByLookupHash(ctx, lookupHash)
	if err != nil {
		return nil, false, err
	}
	return m, false, nil
}

func (sm *DefaultSessionManager) cacheSet(ctx context.Context, m *models.Session) {
	if sm.kv == nil {
		return
	}

	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	ttl := int(time.Until(m.ExpiresAt).Seconds())
	if ttl <= 0 {
		return
	}
	if err := sm.kv.Set(ctx, cacheKey(m.LookupHash), string(data), ttl); err != nil && sm.tel != nil {
		sm.tel.Logger.Warn(ctx, "session cache write failed", behemoth.M{"error": err.Error()}) // logged, never propagated
	}
}

func (sm *DefaultSessionManager) cacheDelete(ctx context.Context, lookupHash string) {
	if sm.kv == nil {
		return
	}
	if err := sm.kv.Delete(ctx, cacheKey(lookupHash)); err != nil && sm.tel != nil {
		sm.tel.Logger.Warn(ctx, "session cache invalidation failed", behemoth.M{"error": err.Error()})
	}
}

// hookContext is the HookContext a manager dispatches its own (semantic)
// hooks with: the request being handled, if any, and fresh chain Values.
func hookContext(ctx context.Context) *types.HookContext {
	return &types.HookContext{Ctx: ctx, Values: behemoth.M{}, Request: types.RequestFrom(ctx)}
}

var _ types.SessionManager = (*DefaultSessionManager)(nil)
