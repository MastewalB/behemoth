package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/models"
)

// PathSessionToken is the route that exchanges the caller's session for a
// session token: POST, below the router's base path.
const PathSessionToken = "/session/token"

// Keys of the session token route's body and of the auth.sessionToken.beforeIssue
// payload that are not hooks.HookValue keys.
const (
	// SessionTokenAudienceKey is the audience a token is asked for.
	SessionTokenAudienceKey = "audience"
	// SessionTokenClaimsKey is the object of claims a before handler adds
	// to the token. They travel under the token's "custom" claim.
	SessionTokenClaimsKey = "claims"
)

// SessionTokenRequest is the input of SessionTokens.Issue.
type SessionTokenRequest struct {
	// Session is the caller's session: active and not expired, as
	// RequireSession resolves it. Required.
	Session *models.Session
	// Audience is the service the token is for: one of
	// JWTConfig.Audiences[JWTExternal]. Empty means the first of them.
	Audience string
}

// SessionToken is an issued session token, and its record. Handlers on
// auth.sessionToken.afterIssue receive it without Token.
type SessionToken struct {
	// Token is the JWT. It is a bearer credential for other services.
	Token     string
	ID        string // the token's jti
	UserID    string // sub
	SessionID string // sid
	Audience  string // aud
	ExpiresAt time.Time
}

// AuditSubject implements [AuditSubject]: a session token is about its user.
func (t *SessionToken) AuditSubject() (subjectType, subjectID string) {
	if t == nil {
		return "", ""
	}
	return models.UserTable, t.UserID
}

// SessionTokens issues session tokens: short-lived external JWTs that tell
// another service which user and session a request is from. The service
// checks one with the published key set, without a call to behemoth. A
// session that ends gets no new token, and a token issued before stays valid
// until it expires (JWTConfig.TTL[JWTExternal], DefaultJWTTTL).
//
// Behemoth never accepts a session token as a session: RequireSession takes
// the session's own token only.
type SessionTokens interface {
	// Issue signs a session token for req.Session. It fires
	// auth.sessionToken.beforeIssue, .afterIssue and .issueFailed. A session
	// that is not active or has expired is a session error, an audience that
	// is not configured a validation error (code "audience_invalid_input"),
	// and session tokens that are not configured a configuration error
	// (errs.CodeJWTExternalNotConfigured).
	Issue(ctx context.Context, req SessionTokenRequest) (*SessionToken, error)
}
