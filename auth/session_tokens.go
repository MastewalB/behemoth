package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

// DefaultSessionTokens is the SessionTokens of behemoth: it signs external
// JWTs with the JWT provider, for the session a request comes with. The
// route that exposes it is POST /session/token (Routes).
type DefaultSessionTokens struct {
	jwt  crypto.JWTProvider
	disp types.Dispatcher
	auth *types.AuthContext
	sm   types.SessionManager
	cfg  crypto.JWTConfig
}

// NewSessionTokens returns the session token flow over jwt. cfg is the JWT
// configuration with its defaults applied: its external audiences are the
// ones a token may be issued for, and none means session tokens are off.
func NewSessionTokens(jwt crypto.JWTProvider, disp types.Dispatcher, auth *types.AuthContext, sm types.SessionManager, cfg crypto.JWTConfig) *DefaultSessionTokens {
	return &DefaultSessionTokens{jwt: jwt, disp: disp, auth: auth, sm: sm, cfg: cfg}
}

// Issue implements [types.SessionTokens].
func (s *DefaultSessionTokens) Issue(ctx context.Context, req types.SessionTokenRequest) (*types.SessionToken, error) {
	const op = "SessionTokens.Issue"
	if !s.cfg.ExternalEnabled() {
		return nil, errs.NewConfigurationErrorCode(op, errs.CodeJWTExternalNotConfigured,
			"session tokens need JWTConfig.Audiences[JWTExternal]")
	}
	session := req.Session
	switch {
	case session == nil:
		return nil, errs.NewInvalidInputError(op, "session", "a session is required", nil)
	case session.State == models.SessionPending:
		// A second factor is still asked for: not a signed-in user.
		return nil, errs.NewSessionError(op, errs.CodeSessionPending, nil)
	case session.State != models.SessionActive || session.RevokedAt != nil:
		return nil, errs.NewSessionError(op, errs.CodeSessionRevoked, nil)
	case !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt):
		return nil, errs.NewSessionError(op, errs.CodeSessionExpired, nil)
	}
	allowed := s.cfg.Audiences[crypto.JWTExternal]
	audience := req.Audience
	if audience == "" {
		audience = allowed[0]
	}
	if !slices.Contains(allowed, audience) {
		return nil, errs.NewInvalidInputError(op, types.SessionTokenAudienceKey, "audience is not allowed", nil)
	}
	userID := session.UserID

	// One operation: the three points share Values, where a rate-limit
	// rule finds the user and the session.
	opCtx := types.BeginOperation(ctx)
	values := types.HookValuesFrom(opCtx)
	values[hooks.HookValueUserID] = userID
	values[hooks.HookValueSessionID] = session.ID

	// The payload is veto-only but for the claims: a handler can't change
	// who the token is about, or for whom.
	payload, err := s.disp.RunBefore(hookContext(opCtx, s.auth, hooks.HookSessionTokenBeforeIssue, types.BeforeHookPhase),
		hooks.HookSessionTokenBeforeIssue, behemoth.M{
			hooks.HookValueUserID:         userID,
			hooks.HookValueSessionID:      session.ID,
			types.SessionTokenAudienceKey: audience,
			types.SessionTokenClaimsKey:   behemoth.M{},
		})
	if err != nil {
		return nil, types.FailIfRejected(s.disp, hookContext(opCtx, s.auth, hooks.HookSessionTokenIssueFailed, types.FailedHookPhase),
			hooks.HookSessionTokenIssueFailed, err, types.FailureReason{SubjectType: models.UserTable, SubjectID: userID})
	}
	var custom behemoth.M
	switch claims := payload[types.SessionTokenClaimsKey].(type) {
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
	result := &types.SessionToken{
		Token: token, ID: claims.ID, UserID: userID, SessionID: session.ID,
		Audience: audience, ExpiresAt: claims.ExpiresAt,
	}

	// Handlers learn that a token was issued, and not the token.
	record := *result
	record.Token = ""
	if err := s.disp.RunAfter(hookContext(opCtx, s.auth, hooks.HookSessionTokenAfterIssue, types.AfterHookPhase),
		hooks.HookSessionTokenAfterIssue, &record); err != nil {
		return nil, err
	}
	return result, nil
}

// Routes returns POST /session/token, behind RequireSession. It is nil when
// session tokens are off.
func (s *DefaultSessionTokens) Routes() []types.Route {
	if !s.cfg.ExternalEnabled() {
		return nil
	}
	return []types.Route{{
		Method: http.MethodPost, Path: types.PathSessionToken, Handler: s.handleIssue,
		Middlewares: []types.Middleware{types.RequireSession(s.sm)},
	}}
}

// handleIssue answers with the token, its expiry and its audience. The body
// is optional: an empty one asks for the default audience.
//
//	{"token": "...", "expires_at": "2026-10-14T10:15:00Z", "audience": "https://api.example.com"}
func (s *DefaultSessionTokens) handleIssue(rctx *types.RequestContext) error {
	const op = "SessionTokens.Issue"
	var body behemoth.M
	if err := json.NewDecoder(rctx.Request.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return errs.NewValidationError(op, "request", err)
	}
	audience, ok := body[types.SessionTokenAudienceKey].(string)
	if !ok && body[types.SessionTokenAudienceKey] != nil {
		return errs.NewInvalidInputError(op, types.SessionTokenAudienceKey, "audience must be a string", nil)
	}
	session, _ := rctx.Values["session"].(*models.Session)

	issued, err := s.Issue(rctx.Ctx, types.SessionTokenRequest{Session: session, Audience: audience})
	if err != nil {
		return err
	}
	// The body is a credential.
	rctx.Response.SetHeader("Cache-Control", "no-store")
	return rctx.Response.JSON(http.StatusOK, behemoth.M{
		"token":                       issued.Token,
		"expires_at":                  issued.ExpiresAt.UTC().Format(time.RFC3339),
		types.SessionTokenAudienceKey: issued.Audience,
	})
}

var _ types.SessionTokens = (*DefaultSessionTokens)(nil)
