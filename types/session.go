package types

import (
	"context"
	"net/http"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/models"
)

type SessionState string

const (
	SessionPending SessionState = "pending" // credentials verified, awaiting a secondary factor
	SessionActive  SessionState = "active"
	SessionRevoked SessionState = "revoked"
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

	// Touch applies the rolling-expiration throttle. Called by middleware
	// after a successful Validate; implementations decide internally whether
	// enough time has passed (per UpdateAge) to actually write.
	Touch(ctx context.Context, sessionID string) error // rolling-expiration throttle, internal use

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
	State     SessionState // Active or Pending: set by the caller (SignIn passes Active or Pending depending on whether 2FA is required)
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

// SessionTokenHeader is the response header a sign-in returns the session
// token in under TransportHeader and TransportBoth. It mirrors Set-Cookie:
// the server sets a credential, and the client stores it.
const SessionTokenHeader = "Set-Auth-Token"

// RequireFreshSession is RequireSession plus a check that the session is
// fresh (SessionManager.IsFresh). A session that is valid but too old gets a
// typed session error with behemotherr.ErrorCodeSessionNotFresh, which the
// router answers with 401: the client asks the user to sign in again and
// retries. Use it on its own; it does what RequireSession does first.
func RequireFreshSession(sm SessionManager) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return RequireSession(sm)(func(rctx *RequestContext) error {
			session, _ := rctx.Values["session"].(*models.Session)
			if session == nil || !sm.IsFresh(session) {
				return behemotherr.NewSessionError("RequireFreshSession", behemotherr.ErrorCodeSessionNotFresh, nil)
			}
			return next(rctx)
		})
	}
}

func RequireSession(sm SessionManager) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			token, ok := sm.ExtractToken(rctx.Request)
			if !ok {
				return rctx.Response.Error(http.StatusUnauthorized, "missing session token")
			}
			session, err := sm.Validate(rctx.Ctx, token)
			if err != nil {
				return rctx.Response.Error(http.StatusUnauthorized, err.Error())
			}
			rctx.Values["session"] = session
			rctx.Values["sessionID"] = session.ID
			_ = sm.Touch(rctx.Ctx, session.ID) // rolling-expiration throttle, best-effort
			return next(rctx)
		}
	}
}
