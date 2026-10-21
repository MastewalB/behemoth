package core

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth/models"
)

// Keys of the session token route's body and of the auth.sessionToken.beforeIssue
// payload that are not hooks.HookValue keys.
const (
	// SessionTokenAudienceKey is the audience a token is asked for.
	SessionTokenAudienceKey = "audience"
	// SessionTokenClaimsKey is the object of claims a before handler adds
	// to the token. They travel under the token's "custom" claim.
	SessionTokenClaimsKey = "claims"
)

// PermissionSessionTokenIssue is the permission SessionTokens.Issue
// requires: a session token for another service, for the caller's own
// session. Core declares it.
const PermissionSessionTokenIssue Permission = "session_token:issue"

// SessionTokenRequest is the input of SessionTokens.Issue. The token is for
// the caller on the context and the session it signed in with; nothing in
// the request names them.
type SessionTokenRequest struct {
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
// Behemoth never accepts a session token as a session: httpapi.RequireSession takes
// the session's own token only.
type SessionTokens interface {
	// Issue signs a session token for the caller on ctx and its session.
	// The caller needs PermissionSessionTokenIssue (Access.RequireUser) and
	// a session: a caller that is not signed in gets the reason as a
	// session error, and a system caller acting for a user, which has no
	// session, gets errs.CodeSessionMissing. It fires
	// auth.sessionToken.beforeIssue, .afterIssue and .issueFailed. An
	// audience that is not configured is a validation error (code
	// "audience_invalid_input"), and session tokens that are not configured
	// a configuration error (errs.CodeJWTExternalNotConfigured).
	Issue(ctx context.Context, req SessionTokenRequest) (*SessionToken, error)
}
