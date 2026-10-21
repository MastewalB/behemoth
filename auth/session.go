// Package auth implements Behemoth's credential services: the session manager,
// the token and code managers with the token catalog, session tokens for
// other services, the authenticator, and Access. The contracts it implements
// are in package core, and their HTTP routes in package httpapi.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/utils"
)

type DefaultSessionManager struct {
	st     *store.Store
	kv     behemoth.KeyValueStorage
	crypto crypto.Services
	cfg    core.SessionConfig
	disp   core.Dispatcher
	tel    *telemetry.Telemetry
	auth   *core.AuthContext
}

func cacheKey(lookupHash string) string { return "session:" + lookupHash }

// NewSessionManager builds the default SessionManager. auth is the
// AuthContext the manager belongs to; it is only handed to hook handlers as
// HookContext.Auth and is not read during construction, so Boot may pass it
// before all of its fields are set.
//
// A new session's IP address and user agent come from the caller on the
// context Create is given (see requestMeta), so a session records the
// address the transport resolved.
//
// The manager takes every session time from the store's clock (st.Now), in
// UTC, both what it writes and what it compares. The session limit compares
// expires_at in the database, and SQLite stores a time as text with its zone:
// expiries stamped in local time would compare wrongly with the store's
// clock there.
func NewSessionManager(
	st *store.Store,
	kv behemoth.KeyValueStorage,
	crypto crypto.Services,
	cfg core.SessionConfig,
	disp core.Dispatcher,
	tel *telemetry.Telemetry,
	auth *core.AuthContext,
) core.SessionManager {
	return &DefaultSessionManager{
		st:     st,
		kv:     kv,
		crypto: crypto,
		cfg:    cfg.WithDefaults(), // a zero field means its default, here and nowhere else
		disp:   disp,
		tel:    telemetry.OrDefault(tel).Named("session"),
		auth:   auth,
	}
}

// requestMeta returns the IP address and user agent a new session records.
// A value set in meta is used as it is. An empty one is taken from the
// caller on ctx, which the transport filled (identity.Peer), and stays empty
// for a caller no transport authenticated: a CLI, a job, or code that did
// not pass on the request's context.
func (sm *DefaultSessionManager) requestMeta(ctx context.Context, meta core.SessionMeta) (ip, ua string) {
	peer := identity.CallerFrom(ctx).Peer()
	ip, ua = meta.IPAddress, meta.UserAgent
	if ip == "" {
		ip = peer.IPAddress
	}
	if ua == "" {
		ua = peer.UserAgent
	}
	return ip, ua
}

func (sm *DefaultSessionManager) Create(ctx context.Context, userID any, meta core.SessionMeta) (*models.Session, string, error) {
	ctx, span := sm.tel.StartSpan(ctx, telemetry.SpanSessionCreate, nil)
	session, rawToken, err := sm.create(ctx, userID, meta)
	telemetry.FinishSpan(span, err)
	return session, rawToken, err
}

// create is Create without its span.
func (sm *DefaultSessionManager) create(ctx context.Context, userID any, meta core.SessionMeta) (*models.Session, string, error) {
	const op = "SessionManager.Create"
	ctx = core.BeginOperation(ctx) // beforeCreate and afterCreate share Values

	// The user is also published in Values, where a rate-limit rule on
	// auth.session.beforeCreate keys on it: HookRateLimitRule.KeyFunc gets
	// the HookContext and not the payload.
	core.HookValuesFrom(ctx)[hooks.HookValueUserID] = fmt.Sprint(userID)

	if meta.State != models.SessionActive && meta.State != models.SessionPending {
		return nil, "", errs.NewValidationError(op, "state", fmt.Errorf("SessionMeta.State must be Active or Pending"))
	}
	factors, err := firstFactor(op, meta.Factor)
	if err != nil {
		return nil, "", err
	}

	if err := sm.makeRoom(ctx, op, fmt.Sprint(userID), meta.State == models.SessionActive); err != nil {
		return nil, "", err
	}

	rawToken, lookupHash, tokenHash, keyVersion, err := sm.newToken(op)
	if err != nil {
		return nil, "", err
	}

	// SessionConfig: expiry selection, IP/UA capture toggle
	ttl := sm.cfg.ExpiresIn
	if meta.State == models.SessionPending {
		ttl = sm.cfg.PendingExpiresIn
	}
	ip, ua := sm.requestMeta(ctx, meta)
	if !sm.cfg.CaptureIPAndAgent {
		ip, ua = "", ""
	}

	now := sm.st.Now()
	payload, err := sm.disp.RunBefore(hookContext(ctx, sm.auth, hooks.HookSessionBeforeCreate, core.BeforeHookPhase), hooks.HookSessionBeforeCreate, behemoth.M{
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
		State:        meta.State,
		ExpiresAt:    now.Add(ttl),
		LastActiveAt: now,
		FreshAt:      now,
		Factors:      factors,
		IPAddress:    ip,
		UserAgent:    ua,
	}
	if err := sm.st.CreateSession(ctx, m); err != nil {
		return nil, "", errs.WrapOp(op, "session", err)
	}

	sm.cacheSet(ctx, m)
	if err := sm.disp.RunAfter(hookContext(ctx, sm.auth, hooks.HookSessionAfterCreate, core.AfterHookPhase), hooks.HookSessionAfterCreate, m); err != nil {
		return nil, "", err
	}

	return m, rawToken, nil

}

// newToken returns a new raw session token with the two hashes a session row
// stores: the unkeyed lookup hash it is found by, and the keyed hash, with
// its key version, that verifies it.
func (sm *DefaultSessionManager) newToken(op string) (rawToken, lookupHash, tokenHash string, keyVersion int, err error) {
	rawToken, err = sm.crypto.Random.SecureRandomString(32)
	if err != nil {
		return "", "", "", 0, errs.NewSecurityError(op, "random_generation_failed", err)
	}
	tokenHash, keyVersion, err = sm.crypto.Secrets.Hash(rawToken)
	if err != nil {
		return "", "", "", 0, err // already classified (CategorySecurity) by SecretHasher/KeyManager
	}
	return rawToken, utils.LookupHashOf(rawToken), tokenHash, keyVersion, nil
}

// maxFactorLength bounds a factor name, so that a session's factors fit
// their column.
const maxFactorLength = 32

// firstFactor returns the factors a new session records: the sign-in's
// factor, or none. The column holds the names separated by spaces, so a name
// that is not lowercase snake case is a configuration error: it would be
// read back as other names. See ADR-0009.
func firstFactor(op, factor string) ([]string, error) {
	if factor == "" {
		return nil, nil
	}
	if !isFactorName(factor) {
		return nil, errs.NewConfigurationError(op, fmt.Sprintf(
			"SessionMeta.Factor %q is not a factor name: lowercase letters, digits and underscores, starting with a letter, at most %d", factor, maxFactorLength), nil)
	}
	return []string{factor}, nil
}

// isFactorName reports whether name is lowercase snake case, starts with a
// letter, and is at most maxFactorLength long.
func isFactorName(name string) bool {
	if name == "" || len(name) > maxFactorLength || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// makeRoom applies SessionConfig.MaxConcurrent before a session of userID is
// created, or promoted. The limit counts the sessions the user can use:
// active ones that have not expired (Store.CountActiveSessions). At the
// limit, the oldest of them is revoked with EvictOldestOnLimit, and the new
// session is refused without it.
//
// evict is false for a session that will be pending. It is refused at the
// limit without eviction as an active one is, so that the user is not asked
// for a second factor that can't complete. It never makes room: whoever has
// only the password must not end the user's sessions. Promote makes room
// once the second factor has passed.
func (sm *DefaultSessionManager) makeRoom(ctx context.Context, op, userID string, evict bool) error {
	if sm.cfg.MaxConcurrent <= 0 {
		return nil
	}
	count, err := sm.st.CountActiveSessions(ctx, userID)
	if err != nil {
		return errs.WrapOp(op, "session", err)
	}
	switch {
	case count < int64(sm.cfg.MaxConcurrent):
		return nil
	case !sm.cfg.EvictOldestOnLimit:
		return errs.NewSessionError(op, errs.CodeSessionLimitReached, nil)
	case !evict:
		return nil
	}
	oldest, err := sm.st.ListActiveSessions(ctx, userID, 1)
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
		err = errs.WrapOp(op, "session", err)
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
		err := errs.NewNotFound(op, "session", nil)
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}

	if m.State == models.SessionRevoked {
		err := errs.NewSessionError(op, errs.CodeSessionRevoked, nil)
		sm.countValidated(ctx, fromCache, err)
		return nil, err
	}
	if sm.st.Now().After(m.ExpiresAt) {
		err := errs.NewSessionError(op, errs.CodeSessionExpired, nil)
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
		attrs[telemetry.AttrReason] = errs.ClassifyCode(err)
	}
	sm.tel.Count(ctx, telemetry.MetricSessionValidated, attrs)
}

func (sm *DefaultSessionManager) Validate(ctx context.Context, rawToken string) (*models.Session, error) {
	session, err := sm.Get(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if session.State == models.SessionPending {
		return nil, errs.NewSessionError("SessionManager.Validate", errs.CodeSessionPending, nil)
	}

	return session, nil
}

// Promote implements [core.SessionManager]. The session gets a new token, so
// that one copied while it was pending never authenticates it. See ADR-0008.
func (sm *DefaultSessionManager) Promote(ctx context.Context, sessionID, factor string) (*models.Session, string, error) {
	const op = "SessionManager.Promote"
	if !isFactorName(factor) {
		return nil, "", errs.NewConfigurationError(op, fmt.Sprintf(
			"the second factor %q is not a factor name: lowercase letters, digits and underscores, starting with a letter, at most %d", factor, maxFactorLength), nil)
	}
	m, err := sm.st.FindSessionByID(ctx, sessionID)
	if err != nil {
		return nil, "", errs.WrapOp(op, "session", err)
	}

	// Transition rule enforcement
	if m.State == models.SessionRevoked {
		return nil, "", errs.NewSessionError(op, errs.CodeSessionRevoked, nil) // Revoked never transitions anywhere
	}
	if m.State != models.SessionPending {
		return nil, "", errs.NewSessionError(op, errs.CodeInvalidSessionState,
			fmt.Errorf("only a Pending session can be promoted (was %q)", m.State))
	}
	if sm.st.Now().After(m.ExpiresAt) {
		// An abandoned pending session (2FA never completed in time) cannot
		// be resurrected by promotion; it must re-authenticate from scratch.
		return nil, "", errs.NewSessionError(op, errs.CodeSessionExpired, nil)
	}
	if err := sm.makeRoom(ctx, op, m.UserID, true); err != nil {
		return nil, "", err
	}

	rawToken, lookupHash, tokenHash, keyVersion, err := sm.newToken(op)
	if err != nil {
		return nil, "", err
	}
	now := sm.st.Now()
	// The new token and the new state are one write, guarded on the pending
	// state: no request finds the active session under the pending token, and
	// of two promotions of one session one wins. Promotion resets to the FULL
	// Active expiry window.
	promoted, err := sm.st.UpdateSessionIn(ctx, sessionID, models.SessionPending, behemoth.M{
		models.SessionStateColumn: string(models.SessionActive),
		models.SessionLookupHash:  lookupHash,
		models.SessionTokenHash:   tokenHash,
		models.SessionKeyVersion:  keyVersion,
		models.SessionFactors:     models.SessionFactorsValue(append(slices.Clone(m.Factors), factor)),
		models.SessionFreshAt:     now,
		models.SessionExpiresAt:   now.Add(sm.cfg.ExpiresIn),
	})
	if errs.IsNotFound(err) {
		return nil, "", errs.NewSessionError(op, errs.CodeInvalidSessionState,
			fmt.Errorf("the session stopped being pending while it was promoted"))
	}
	if err != nil {
		return nil, "", errs.WrapOp(op, "session", err)
	}
	// The pending token no longer works, so its cache entry goes.
	sm.cacheDelete(ctx, m.LookupHash)
	sm.cacheSet(ctx, promoted)
	return promoted, rawToken, nil
}

// Touch implements [core.SessionManager]. It returns the session only when
// it extended it, so the caller knows to extend the client's cookie too.
//
// It runs on every authenticated request, so the usual case has to cost
// nothing: whether an extension is due is read off session, the copy the
// caller validated, and a session that is not due is neither read nor
// written. When that copy says an extension is due, the row decides. The
// copy may come from the cache, and another request may have extended or
// revoked the session since.
func (sm *DefaultSessionManager) Touch(ctx context.Context, session *models.Session) (*models.Session, error) {
	const op = "SessionManager.Touch"

	if session == nil || !sm.extensionDue(session) {
		return nil, nil
	}

	m, err := sm.st.FindSessionByID(ctx, session.ID)
	if err != nil {
		return nil, errs.WrapOp(op, "session", err)
	}
	// A revoked session being "used" isn't an error worth surfacing to
	// request middleware, and one another request has just extended needs
	// nothing more.
	if m.State == models.SessionRevoked || !sm.extensionDue(m) {
		return nil, nil
	}

	now := sm.st.Now()
	ttl := sm.cfg.ExpiresIn
	if m.State == models.SessionPending {
		ttl = sm.cfg.PendingExpiresIn
	}
	touched, err := sm.st.UpdateSession(ctx, m.ID, behemoth.M{
		models.SessionLastActiveAt: now,
		models.SessionExpiresAt:    now.Add(ttl),
	})
	if err != nil {
		return nil, errs.WrapOp(op, "session", err)
	}
	sm.cacheSet(ctx, touched)
	return touched, nil
}

// extensionDue reports whether m is in the last UpdateAge of its life, which
// is when the rolling expiration extends it. Extending on every request
// would mean a write per authenticated request. With UpdateAge at zero the
// rolling expiration is off, and no session is ever due.
func (sm *DefaultSessionManager) extensionDue(m *models.Session) bool {
	if sm.cfg.UpdateAge <= 0 {
		return false
	}
	return !sm.st.Now().Before(m.ExpiresAt.Add(-sm.cfg.UpdateAge))
}

// ListForUser implements [core.SessionManager].
func (sm *DefaultSessionManager) ListForUser(ctx context.Context, userID any) ([]*models.Session, error) {
	sessions, err := sm.st.ListSessionsForUser(ctx, fmt.Sprint(userID))
	if err != nil {
		return nil, errs.WrapOp("SessionManager.ListForUser", "session", err)
	}
	return sessions, nil
}

// Revoke implements [core.SessionManager].
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
		return errs.WrapOp(op, "session", err)
	}
	err = sm.revokeModel(ctx, m, reason)
	if err != nil {
		return errs.WrapOp(op, "session", err)
	}
	return nil
}

// RevokeAllForUser implements [core.SessionManager].
func (sm *DefaultSessionManager) RevokeAllForUser(ctx context.Context, userID any, reason string, except string) error {
	const op = "SessionManager.RevokeAllForUser"

	live, err := sm.st.ListLiveSessions(ctx, fmt.Sprint(userID), except, 0)
	if err != nil {
		return errs.WrapOp(op, "session", err)
	}
	for _, m := range live {
		if err := sm.revokeModel(ctx, m, reason); err != nil {
			return errs.WrapOp(op, "session", err)
		}
	}
	return nil
}

// IsFresh implements [core.SessionManager].
func (sm *DefaultSessionManager) IsFresh(session *models.Session) bool {
	if session == nil || session.State != models.SessionActive || session.FreshAt.IsZero() {
		return false
	}
	return sm.st.Now().Sub(session.FreshAt) <= sm.cfg.FreshAge
}

// Evict implements [core.SessionManager].
func (sm *DefaultSessionManager) Evict(ctx context.Context, sessions []*models.Session) {
	for _, m := range sessions {
		sm.cacheDelete(ctx, m.LookupHash)
	}
}

// Discard implements [core.SessionManager]. Each session that was live is
// handed to the handlers as a revoked one, with the time and the reason,
// although no row holds that state: the row is gone. sessions is not
// modified.
func (sm *DefaultSessionManager) Discard(ctx context.Context, sessions []*models.Session, reason string) error {
	now := sm.st.Now()
	for _, m := range sessions {
		sm.cacheDelete(ctx, m.LookupHash)
		if m.State == models.SessionRevoked {
			continue // its revoke was reported when it happened
		}
		ended := *m
		ended.State, ended.RevokedAt, ended.RevokedReason = models.SessionRevoked, &now, reason
		opCtx := core.BeginOperation(ctx)
		if err := sm.disp.RunAfter(hookContext(opCtx, sm.auth, hooks.HookSessionAfterRevoke, core.AfterHookPhase), hooks.HookSessionAfterRevoke, &ended); err != nil {
			return err
		}
	}
	return nil
}

// SupportsRevocation implements [core.SessionManager].
func (sm *DefaultSessionManager) SupportsRevocation() bool { return true }

// revokeModel is the single internal path every revocation (explicit eviction,
// bulk revoke-all) funnels through
// a single-point that enforces the terminal-state rule and fires hooks/cache invalidation consistently.
func (sm *DefaultSessionManager) revokeModel(ctx context.Context, m *models.Session, reason string) error {
	if m.State == models.SessionRevoked {
		return nil // already revoked
	}
	ctx = core.BeginOperation(ctx) // beforeRevoke and afterRevoke share Values

	// The returned payload is not read: a handler can stop the revoke, but
	// it can't point it at another session or change the reason.
	if _, err := sm.disp.RunBefore(hookContext(ctx, sm.auth, hooks.HookSessionBeforeRevoke, core.BeforeHookPhase), hooks.HookSessionBeforeRevoke,
		behemoth.M{hooks.HookValueSessionID: m.ID, hooks.HookValueReason: reason}); err != nil {
		return err
	}

	now := sm.st.Now()
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

	return sm.disp.RunAfter(hookContext(ctx, sm.auth, hooks.HookSessionAfterRevoke, core.AfterHookPhase), hooks.HookSessionAfterRevoke, m)
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
	ttl := int(m.ExpiresAt.Sub(sm.st.Now()).Seconds())
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
// one hook point with, the way the data hooks of package dispatch do for data points.
//
// The managers' points are Tier 2, so Tx stays nil. Values are the
// operation's: each manager method that fires points calls
// core.BeginOperation first, so its before and after points share one map,
// which starts as a copy of the caller's operation (a sign-in's). Request is
// the request being handled, or nil outside one (a CLI, a job).
func hookContext(ctx context.Context, auth *core.AuthContext, point core.HookPoint, phase core.HookPhase) *core.HookContext {
	values := core.HookValuesFrom(ctx)
	if values == nil {
		values = behemoth.M{}
	}
	return &core.HookContext{
		Ctx: ctx, Point: point, Phase: phase,
		Auth:   auth,
		Values: values,
	}
}

var _ core.SessionManager = (*DefaultSessionManager)(nil)
