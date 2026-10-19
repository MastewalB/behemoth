package core

import (
	"context"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
)

// SessionManager creates, resolves, extends and revokes sessions. It knows
// nothing of HTTP: the token carrier (TokenCarrier) hands a session's token
// to a client and reads it from a request, and the authenticator
// (Authenticator) joins the two on every request.
type SessionManager interface {
	// Create starts a session for userID in meta.State and returns it with
	// its raw token. Pass the context of the request being handled: the
	// session's IP address and user agent are read from it (see SessionMeta).
	Create(ctx context.Context, userID any, meta SessionMeta) (*models.Session, string /* raw token */, error)

	// Validate resolves a raw bearer token to its Session.
	// Only returns State == Active; Use Get() to resolve a Pending session.
	Validate(ctx context.Context, rawToken string) (*models.Session, error)

	// Get resolves a raw token to its Session regardless of State (Pending or
	// Active) only enforcing expiry/revocation.
	// This can be used by plugins like 2FA at verification stage to look up a Pending session before
	// promoting it.
	Get(ctx context.Context, rawToken string) (*models.Session, error)

	// Promote transitions Pending -> Active. Only reachable from a hook
	// handler that has actually verified a second factor.
	Promote(ctx context.Context, sessionID string) (*models.Session, error)

	// Touch applies the rolling expiration: it extends a session in use
	// once less than SessionConfig.UpdateAge is left of it. The
	// authenticator calls it on every request that carries a session's
	// token, with the session it resolved. Whether an extension is due is
	// read off that session, so a request that is not due costs no read and
	// no write. It returns the session with its new expiry when it extended
	// it, and nil when it did not. The caller then extends the client's
	// copy of the token, as the authentication stage does with
	// TokenCarrier.Extend.
	Touch(ctx context.Context, session *models.Session) (*models.Session, error)

	Revoke(ctx context.Context, sessionID string, reason string) error

	RevokeAllForUser(ctx context.Context, userID any, reason string, except string) error

	// IsFresh reports whether session's credentials were checked recently:
	// it is active, and its last sign-in or second factor (FreshAt) is no
	// older than SessionConfig.FreshAge. A route that changes something
	// sensitive, such as the account's email, asks for a fresh session so
	// that a stolen long-lived session is not enough (RequireFreshSession).
	// Nothing refreshes a session in place yet: signing in again is how a
	// user gets a fresh one.
	IsFresh(session *models.Session) bool

	// Evict removes sessions from the session cache and does nothing else.
	// It is for sessions whose rows are being deleted with their user
	// (Store.DeleteUser), and is safe to repeat.
	Evict(ctx context.Context, sessions []*models.Session)

	// Discard is for sessions whose rows no longer exist: they were deleted
	// with their user, and the delete has committed. It removes them from
	// the session cache and fires auth.session.afterRevoke with reason for
	// each one that was not revoked already, so a handler that reacts to a
	// session ending sees these too. It writes nothing to the database, and
	// auth.session.beforeRevoke does not fire: there is nothing left to
	// refuse. An implementation without revocation does nothing.
	Discard(ctx context.Context, sessions []*models.Session, reason string) error

	ListForUser(ctx context.Context, userID any) ([]*models.Session, error)

	// SupportsRevocation lets callers (admin UI, HTTP layer) know whether
	// Revoke/RevokeAllForUser are meaningful or a no-op; false for purely
	// stateless/self-verifying implementations.
	SupportsRevocation() bool
}

// SessionRevokedUserDeleted is the revoke reason of a session that ended
// because its user was deleted.
const SessionRevokedUserDeleted = "user_deleted"

// SessionMeta is caller-supplied context at creation time.
type SessionMeta struct {
	// IPAddress and UserAgent are optional. Left empty, the session manager
	// takes them from the request being handled, which it finds on the
	// context passed to Create (ContextWithRequest); without a request they
	// stay empty. Set them only to override that, e.g. from a job acting on
	// a recorded request. Neither is stored unless
	// SessionConfig.CaptureIPAndAgent is on.
	IPAddress string
	UserAgent string
	State     models.SessionState // Active or Pending: set by the caller (SignIn passes Active or Pending depending on whether 2FA is required)
}

// RequireFreshSession is RequireSession plus a check that the session is
// fresh (SessionManager.IsFresh). A session that is valid but too old gets a
// typed session error with errs.CodeSessionNotFresh, which the router
// answers with 401: the client asks the user to sign in again and retries.
// Use it on its own; it does what RequireSession does first.
func RequireFreshSession(sm SessionManager) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return RequireSession()(func(rctx *RequestContext) error {
			session, _ := identity.CallerFrom(rctx.Ctx).Session()
			if !sm.IsFresh(&models.Session{State: models.SessionState(session.State), FreshAt: session.FreshAt}) {
				return errs.NewSessionError("RequireFreshSession", errs.CodeSessionNotFresh, nil)
			}
			return next(rctx)
		})
	}
}

// RequireSession lets a request through only when its caller signed in with
// an active session. The router has authenticated the request already
// (AuthenticateRequests), so the handler reads the session from the caller:
// identity.CallerFrom(rctx.Ctx).Session().
//
// A request it refuses gets the reason the caller is anonymous, a typed
// session error that the router answers with 401 and the error's public
// message and code:
//
//	no token in the request                session_missing
//	a token that belongs to no session     session_invalid
//	a revoked or expired session           session_revoked, session_expired
//	a session waiting for a second factor  session_pending
//
// It writes no response itself. A lookup that failed, such as a database
// that is down, is returned unchanged: the router answers it with 500, logs
// it, and keeps its text from the client. Answering it with 401 would tell a
// signed-in client that its session is gone.
//
// A caller that is not signed in with a session, such as a system caller on
// a request's context, is refused with session_missing.
func RequireSession() Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			caller := identity.CallerFrom(rctx.Ctx)
			if _, ok := caller.Session(); ok && !caller.IsAnonymous() {
				return next(rctx)
			}
			if err := caller.AuthError(); err != nil {
				return err
			}
			return errs.NewSessionError("RequireSession", errs.CodeSessionMissing, nil)
		}
	}
}
