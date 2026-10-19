package core

import (
	"context"
	"net/http"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
)

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
	// once less than SessionConfig.UpdateAge is left of it. RequireSession
	// calls it on every authenticated request, with the session Validate
	// returned. Whether an extension is due is read off that session, so a
	// request that is not due costs no read and no write. It returns the
	// session with its new expiry when it extended it, and nil when it did
	// not. The caller then extends the client's copy of the token
	// (ExtendToken).
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

	// WriteToken hands a new session's token to the client the way
	// SessionConfig.Transport says: a Set-Cookie header for
	// TransportCookie, the SessionTokenHeader response header for
	// TransportHeader, both for TransportBoth.
	//
	// For TransportBody it writes nothing, because the body is the route's
	// to write. It returns true then, and the route puts the token in its
	// JSON body. WriteSignIn does both steps, and is what a sign-in route
	// calls; a route that calls WriteToken itself has to act on the result.
	WriteToken(rctx *RequestContext, rawToken string, session *models.Session) (inBody bool)

	// ClearToken takes the token back from the client once the session the
	// request presented has ended: a route calls it after it ended its
	// caller's own session, such as sign-out, and RequireSession calls it
	// when it finds the session gone. It is the counterpart of WriteToken.
	// For TransportCookie and TransportBoth it sets the session cookie
	// again, empty and already expired, so that the browser drops it: the
	// cookie is HttpOnly, which a script can't remove. It does so for the
	// request that presented its token in that cookie. Under TransportBoth
	// a request that came with a bearer token keeps its cookie, which may
	// be another session's. For TransportHeader and TransportBody it writes
	// nothing, because the client holds the token itself and discards it.
	//
	// It only writes to the response. Ending the session is Revoke's job,
	// and a route calls ClearToken after the revoke has succeeded.
	ClearToken(rctx *RequestContext)

	// ExtendToken keeps the client's copy of the token in step with a
	// session that Touch extended. A browser drops a cookie at the date the
	// cookie was set with, however long the session lasts on the server, so
	// for TransportCookie and TransportBoth it sets the cookie again with
	// session's new expiry. It does so only when the request carried
	// rawToken in that cookie: under TransportBoth a request may present the
	// token as a bearer token while its cookie holds another session's. For
	// TransportHeader and TransportBody it writes nothing, because those
	// clients keep the token without a date.
	//
	// It reports whether it wrote the cookie. The response then carries the
	// session token, and the caller keeps it out of caches, as RequireSession
	// does with Cache-Control: no-store.
	ExtendToken(rctx *RequestContext, rawToken string, session *models.Session) (written bool)

	// ExtractToken reads the token from a request per Transport: the
	// session cookie, the Authorization header ("Bearer <token>"), or
	// either. The header is where a client of TransportHeader and of
	// TransportBody sends it.
	ExtractToken(r *http.Request) (string, bool)

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

// TokenTransport is where the session token travels, in both directions:
// how a sign-in hands it to the client, and where the client's later
// requests carry it.
//
//	transport  the sign-in response has it in      a request carries it in
//	cookie     a Set-Cookie header                 the cookie
//	header     the Set-Auth-Token header           Authorization: Bearer <token>
//	body       the JSON body, under "token"        Authorization: Bearer <token>
//	both       the cookie and Set-Auth-Token       either
type TokenTransport string

const (
	// TransportCookie keeps the token in an HttpOnly cookie, which the
	// browser stores and sends by itself and scripts can't read. The
	// default.
	TransportCookie TokenTransport = "cookie"
	// TransportHeader returns the token in the SessionTokenHeader response
	// header. The client keeps it and sends it as a bearer token. A browser
	// script on another origin can read the header only if the application
	// exposes it (Access-Control-Expose-Headers).
	TransportHeader TokenTransport = "header"
	// TransportBody returns the token in the JSON body of the sign-in
	// response, under SignInTokenKey. It differs from TransportHeader in
	// that one respect: the client sends it back the same way, as a bearer
	// token. Nothing is ever read from a request's body.
	TransportBody TokenTransport = "body"
	// TransportBoth is the cookie and the header together: a sign-in sets
	// both, and a request may carry either. It is for an application with
	// browser and non-browser clients, or one moving between the two.
	TransportBoth TokenTransport = "both"
)

// ReadsCookie reports whether a request under t is authenticated by a cookie
// the browser attaches by itself. Those are the transports a cross-site
// request can abuse, and the ones Boot installs the origin check for.
func (t TokenTransport) ReadsCookie() bool {
	return t == TransportCookie || t == TransportBoth
}

// SessionTokenHeader is the response header a sign-in returns the session
// token in under TransportHeader and TransportBoth. It mirrors Set-Cookie:
// the server sets a credential, and the client stores it.
const SessionTokenHeader = "Set-Auth-Token"

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
