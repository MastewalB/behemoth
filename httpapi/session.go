package httpapi

import (
	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/identity"
	"github.com/go-behemoth/behemoth/models"
)

// RequireFreshSession is RequireSession plus a check that the session is
// fresh (SessionManager.IsFresh). A session that is valid but too old gets a
// typed session error with errs.CodeSessionNotFresh, which the router
// answers with 401: the client asks the user to sign in again and retries.
// Use it on its own; it does what RequireSession does first.
func RequireFreshSession(sm core.SessionManager) Middleware {
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
