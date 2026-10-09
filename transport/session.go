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
	"github.com/MastewalB/behemoth/telemetry"
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
	tel    *telemetry.Telemetry
	auth   *types.AuthContext
	ipCfg  *types.ClientIPConfig // how the client's address is resolved from a request; see requestMeta
}

func cacheKey(lookupHash string) string { return "session:" + lookupHash }

// NewSessionManager builds the default SessionManager. auth is the
// AuthContext the manager belongs to; it is only handed to hook handlers as
// HookContext.Auth and is not read during construction, so Boot may pass it
// before all of its fields are set.
//
// ipCfg is the client-IP configuration the router uses (trusted proxies and
// the forwarding header), so a session records the same address rate limiting
// sees. nil means no proxy is trusted: the address is the direct peer's.
func NewSessionManager(
	st *store.Store,
	kv behemoth.KeyValueStorage,
	crypto types.Crypto,
	cfg types.SessionConfig,
	disp types.Dispatcher,
	tel *telemetry.Telemetry,
	auth *types.AuthContext,
	ipCfg *types.ClientIPConfig,
) types.SessionManager {
	if ipCfg == nil {
		ipCfg = &types.ClientIPConfig{}
	}
	return &DefaultSessionManager{
		st:     st,
		kv:     kv,
		crypto: crypto,
		cfg:    cfg.WithDefaults(), // a zero field means its default, here and nowhere else
		disp:   disp,
		tel:    telemetry.OrDefault(tel).Named("session"),
		auth:   auth,
		ipCfg:  ipCfg,
	}
}

// requestMeta returns the IP address and user agent a new session records.
// A value the caller set in meta is used as it is. An empty one is taken from
// the request being handled (types.RequestFrom), and stays empty when ctx
// carries none: a CLI, a job, or a caller that did not pass on the request's
// context.
func (sm *DefaultSessionManager) requestMeta(ctx context.Context, meta types.SessionMeta) (ip, ua string) {
	ip, ua = meta.IPAddress, meta.UserAgent
	rc := types.RequestFrom(ctx)
	if rc == nil || rc.Request == nil {
		return ip, ua
	}
	if ip == "" {
		ip = types.ClientIP(rc.Request, sm.ipCfg)
	}
	if ua == "" {
		ua = rc.Request.UserAgent()
	}
	return ip, ua
}

func (sm *DefaultSessionManager) Create(ctx context.Context, userID any, meta types.SessionMeta) (*models.Session, string, error) {
	ctx, span := sm.tel.StartSpan(ctx, telemetry.SpanSessionCreate, nil)
	session, rawToken, err := sm.create(ctx, userID, meta)
	telemetry.FinishSpan(span, err)
	return session, rawToken, err
}

// create is Create without its span.
func (sm *DefaultSessionManager) create(ctx context.Context, userID any, meta types.SessionMeta) (*models.Session, string, error) {
	const op = "SessionManager.Create"
	ctx = types.BeginOperation(ctx) // beforeCreate and afterCreate share Values

	// The user is also published in Values, where a rate-limit rule on
	// auth.session.beforeCreate keys on it: HookRateLimitRule.KeyFunc gets
	// the HookContext and not the payload.
	types.HookValuesFrom(ctx)[hooks.HookValueUserID] = fmt.Sprint(userID)

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
	ip, ua := sm.requestMeta(ctx, meta)
	if !sm.cfg.CaptureIPAndAgent {
		ip, ua = "", ""
	}

	now := time.Now()
	payload, err := sm.disp.RunBefore(hookContext(ctx, sm.auth, hooks.HookSessionBeforeCreate, types.BeforeHookPhase), hooks.HookSessionBeforeCreate, behemoth.M{
		hooks.HookValueUserID: fmt.Sprint(userID), hooks.HookValueState: string(meta.State),
		hooks.HookValueIPAddress: ip, hooks.HookValueUserAgent: ua,
	})
	if err != nil {
		return nil, "", err
	}

	// A before-hook may have rewritten the IP address or user agent (a
	// plugin that masks the address, for example). Only these two keys are
	// read back: the user and the state are the caller's decision. With
	// CaptureIPAndAgent off the config wins and a handler's values are not
	// stored either.
	if sm.cfg.CaptureIPAndAgent {
		if v, ok := payload[hooks.HookValueIPAddress].(string); ok {
			ip = v
		}
		if v, ok := payload[hooks.HookValueUserAgent].(string); ok {
			ua = v
		}
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
	if err := sm.disp.RunAfter(hookContext(ctx, sm.auth, hooks.HookSessionAfterCreate, types.AfterHookPhase), hooks.HookSessionAfterCreate, m); err != nil {
		return nil, "", err
	}

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
	ctx, span := sm.tel.StartSpan(ctx, telemetry.SpanSessionValidate, nil)
	session, err := sm.get(ctx, rawToken)
	telemetry.FinishSpan(span, err)
	return session, err
}

// get is Get without its span.
func (sm *DefaultSessionManager) get(ctx context.Context, rawToken string) (*models.Session, error) {
	const op = "SessionManager.Get"
	lookupHash := utils.LookupHashOf(rawToken)

	m, fromCache, err := sm.fetchByLookupHash(ctx, lookupHash)
	if err != nil {
		err = behemotherr.WrapOp(op, "session", err)
		sm.countValidated(ctx, false, err)
		return nil, err
	}

	ok, err := sm.crypto.Secrets.Verify(rawToken, m.TokenHash, m.KeyVersion)
	if err != nil {
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}

	if !ok {
		// LookupHash matched but the keyed HMAC didn't; collapse into the
		// same NotFound response
		err := behemotherr.NewNotFound(op, "session", nil)
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}

	if m.State == models.SessionRevoked {
		err := behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionRevoked, nil)
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}
	if time.Now().After(m.ExpiresAt) {
		err := behemotherr.NewSessionError(op, behemotherr.ErrorCodeSessionExpired, nil)
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}
	sm.countValidated(ctx, fromCache, nil)

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

// countValidated counts one session lookup by token: whether the session
// came from the cache, and how the lookup ended. A refused lookup carries the
// error's code as its reason (session_expired, session_revoked, ...).
func (sm *DefaultSessionManager) countValidated(ctx context.Context, fromCache bool, err error) {
	if !sm.tel.MetricsEnabled() {
		return
	}
	attrs := behemoth.M{telemetry.AttrCache: "miss", telemetry.AttrOutcome: string(telemetry.OutcomeSuccess)}
	if fromCache {
		attrs[telemetry.AttrCache] = "hit"
	}
	if err != nil {
		attrs[telemetry.AttrOutcome] = string(telemetry.OutcomeFailure)
		attrs[telemetry.AttrReason] = behemotherr.ClassifyCode(err)
	}
	sm.tel.Count(ctx, telemetry.MetricSessionValidated, attrs)
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
	ctx, span := sm.tel.StartSpan(ctx, telemetry.SpanSessionRevoke, nil)
	err := sm.revoke(ctx, sessionID, reason)
	telemetry.FinishSpan(span, err)
	return err
}

// revoke is Revoke without its span.
func (sm *DefaultSessionManager) revoke(ctx context.Context, sessionID string, reason string) error {
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

// IsFresh implements [types.SessionManager].
func (sm *DefaultSessionManager) IsFresh(session *models.Session) bool {
	if session == nil || session.State != models.SessionActive || session.FreshAt.IsZero() {
		return false
	}
	return time.Since(session.FreshAt) <= sm.cfg.FreshAge
}

// Evict implements [types.SessionManager].
func (sm *DefaultSessionManager) Evict(ctx context.Context, sessions []*models.Session) {
	for _, m := range sessions {
		sm.cacheDelete(ctx, m.LookupHash)
	}
}

// Discard implements [types.SessionManager]. Each session that was live is
// handed to the handlers as a revoked one, with the time and the reason,
// although no row holds that state: the row is gone. sessions is not
// modified.
func (sm *DefaultSessionManager) Discard(ctx context.Context, sessions []*models.Session, reason string) error {
	now := time.Now()
	for _, m := range sessions {
		sm.cacheDelete(ctx, m.LookupHash)
		if m.State == models.SessionRevoked {
			continue // its revoke was reported when it happened
		}
		ended := *m
		ended.State, ended.RevokedAt, ended.RevokedReason = models.SessionRevoked, &now, reason
		opCtx := types.BeginOperation(ctx)
		if err := sm.disp.RunAfter(hookContext(opCtx, sm.auth, hooks.HookSessionAfterRevoke, types.AfterHookPhase), hooks.HookSessionAfterRevoke, &ended); err != nil {
			return err
		}
	}
	return nil
}

// SupportsRevocation implements [types.SessionManager].
func (sm *DefaultSessionManager) SupportsRevocation() bool { return true }

// WriteToken implements [types.SessionManager].
func (sm *DefaultSessionManager) WriteToken(rctx *types.RequestContext, rawToken string, session *models.Session) (inBody bool) {
	switch sm.cfg.Transport {
	case types.TransportCookie, types.TransportBoth:
		rctx.Response.Cookie(&http.Cookie{
			Name: sm.cfg.CookieName, Value: rawToken, Expires: session.ExpiresAt,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/",
		})
	}
	switch sm.cfg.Transport {
	case types.TransportHeader, types.TransportBoth:
		rctx.Response.SetHeader(types.SessionTokenHeader, rawToken)
	}
	// The body is the route's to write, so for TransportBody the caller is
	// told to put the token there.
	return sm.cfg.Transport == types.TransportBody
}

// ExtractToken implements [types.SessionManager]. A client of
// TransportHeader and of TransportBody sends the token the same way, as a
// bearer token; the two differ only in how the sign-in delivered it.
func (sm *DefaultSessionManager) ExtractToken(r *http.Request) (string, bool) {
	switch sm.cfg.Transport {
	case types.TransportHeader, types.TransportBody, types.TransportBoth:
		if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && token != "" {
			return token, true
		}
	}
	switch sm.cfg.Transport {
	case types.TransportCookie, types.TransportBoth:
		if c, err := r.Cookie(sm.cfg.CookieName); err == nil && c.Value != "" {
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
	ctx = types.BeginOperation(ctx) // beforeRevoke and afterRevoke share Values

	// The returned payload is not read: a handler can stop the revoke, but
	// it can't point it at another session or change the reason.
	if _, err := sm.disp.RunBefore(hookContext(ctx, sm.auth, hooks.HookSessionBeforeRevoke, types.BeforeHookPhase), hooks.HookSessionBeforeRevoke,
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

	return sm.disp.RunAfter(hookContext(ctx, sm.auth, hooks.HookSessionAfterRevoke, types.AfterHookPhase), hooks.HookSessionAfterRevoke, m)
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
	if err := sm.kv.Set(ctx, cacheKey(m.LookupHash), string(data), ttl); err != nil {
		sm.tel.Logger.Warn(ctx, "session cache write failed", telemetry.ErrorFields(err)) // logged, never propagated
	}
}

func (sm *DefaultSessionManager) cacheDelete(ctx context.Context, lookupHash string) {
	if sm.kv == nil {
		return
	}
	if err := sm.kv.Delete(ctx, cacheKey(lookupHash)); err != nil {
		sm.tel.Logger.Warn(ctx, "session cache invalidation failed", telemetry.ErrorFields(err))
	}
}

// hookContext builds the context the session and token managers dispatch
// one hook point with, the way dataHooks.hookContext does for data points.
//
// The managers' points are Tier 2, so Tx stays nil. Values are the
// operation's: each manager method that fires points calls
// types.BeginOperation first, so its before and after points share one map,
// which starts as a copy of the caller's operation (a sign-in's). Request is
// the request being handled, or nil outside one (a CLI, a job).
func hookContext(ctx context.Context, auth *types.AuthContext, point types.HookPoint, phase types.HookPhase) *types.HookContext {
	values := types.HookValuesFrom(ctx)
	if values == nil {
		values = behemoth.M{}
	}
	return &types.HookContext{
		Ctx: ctx, Point: point, Phase: phase,
		Auth:    auth,
		Values:  values,
		Request: types.RequestFrom(ctx),
	}
}

var _ types.SessionManager = (*DefaultSessionManager)(nil)
