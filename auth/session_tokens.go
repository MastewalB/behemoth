package auth

import (
	"context"
	"errors"
	"slices"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/core/hooks"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/identity"
	"github.com/go-behemoth/behemoth/models"
)

// DefaultSessionTokens is the SessionTokens of behemoth: it signs external
// JWTs with the JWT provider, for the session a request comes with. The
// route that exposes it is POST /session/token (httpapi.SessionTokenRoutes).
type DefaultSessionTokens struct {
	jwt  crypto.JWTProvider
	disp core.Dispatcher
	auth *core.AuthContext
	sm   core.SessionManager
	cfg  crypto.JWTConfig
}

// NewSessionTokens returns the session token flow over jwt. cfg is the JWT
// configuration with its defaults applied: its external audiences are the
// ones a token may be issued for, and none means session tokens are off.
func NewSessionTokens(jwt crypto.JWTProvider, disp core.Dispatcher, auth *core.AuthContext, sm core.SessionManager, cfg crypto.JWTConfig) *DefaultSessionTokens {
	return &DefaultSessionTokens{jwt: jwt, disp: disp, auth: auth, sm: sm, cfg: cfg}
}

// Issue implements [core.SessionTokens].
func (s *DefaultSessionTokens) Issue(ctx context.Context, req core.SessionTokenRequest) (*core.SessionToken, error) {
	const op = "SessionTokens.Issue"
	if !s.cfg.ExternalEnabled() {
		return nil, errs.NewConfigurationErrorCode(op, errs.CodeJWTExternalNotConfigured,
			"session tokens need JWTConfig.Audiences[JWTExternal]")
	}
	// A signed-in user, or the reason the caller is not one: the
	// authenticator checked the session's state and expiry.
	userID, err := s.auth.Access.RequireUser(ctx, core.PermissionSessionTokenIssue)
	if err != nil {
		return nil, err
	}
	session, ok := identity.CallerFrom(ctx).Session()
	if !ok {
		// A system caller acting for the user: the token's sid would name
		// no session.
		return nil, errs.NewSessionError(op, errs.CodeSessionMissing, nil)
	}
	allowed := s.cfg.Audiences[crypto.JWTExternal]
	audience := req.Audience
	if audience == "" {
		audience = allowed[0]
	}
	if !slices.Contains(allowed, audience) {
		return nil, errs.NewInvalidInputError(op, core.SessionTokenAudienceKey, "audience is not allowed", nil)
	}
	// One operation: the three points share Values, where a rate-limit
	// rule finds the user and the session.
	opCtx := core.BeginOperation(ctx)
	values := core.HookValuesFrom(opCtx)
	values[hooks.HookValueUserID] = userID
	values[hooks.HookValueSessionID] = session.ID

	// The payload is veto-only but for the claims: a handler can't change
	// who the token is about, or for whom.
	payload, err := s.disp.RunBefore(hookContext(opCtx, s.auth, hooks.HookSessionTokenBeforeIssue, core.BeforeHookPhase),
		hooks.HookSessionTokenBeforeIssue, behemoth.M{
			hooks.HookValueUserID:        userID,
			hooks.HookValueSessionID:     session.ID,
			core.SessionTokenAudienceKey: audience,
			core.SessionTokenClaimsKey:   behemoth.M{},
		})
	if err != nil {
		return nil, core.FailIfRejected(s.disp, hookContext(opCtx, s.auth, hooks.HookSessionTokenIssueFailed, core.FailedHookPhase),
			hooks.HookSessionTokenIssueFailed, err, core.FailureReason{SubjectType: models.UserTable, SubjectID: userID})
	}
	var custom behemoth.M
	switch claims := payload[core.SessionTokenClaimsKey].(type) {
	case nil:
	case behemoth.M:
		custom = claims
	case map[string]any:
		custom = claims
	default:
		return nil, errors.New("session tokens: a handler on auth.sessionToken.beforeIssue set claims to something that is not an object")
	}
	if len(custom) == 0 {
		custom = nil
	}

	token, err := s.jwt.Sign(opCtx, crypto.JWTExternal, crypto.JWTRequest{
		Subject: userID, Audience: audience, SessionID: session.ID, Custom: custom,
	})
	if err != nil {
		return nil, err
	}
	// The token's id and expiry, read back from what was signed.
	claims, err := s.jwt.Verify(opCtx, crypto.JWTExternal, token)
	if err != nil {
		return nil, err
	}
	result := &core.SessionToken{
		Token: token, ID: claims.ID, UserID: userID, SessionID: session.ID,
		Audience: audience, ExpiresAt: claims.ExpiresAt,
	}

	// Handlers learn that a token was issued, and not the token.
	record := *result
	record.Token = ""
	if err := s.disp.RunAfter(hookContext(opCtx, s.auth, hooks.HookSessionTokenAfterIssue, core.AfterHookPhase),
		hooks.HookSessionTokenAfterIssue, &record); err != nil {
		return nil, err
	}
	return result, nil
}

var _ core.SessionTokens = (*DefaultSessionTokens)(nil)
