package core

import (
	"context"

	"github.com/MastewalB/behemoth/identity"
)

// CredentialKind says what a Credential is.
type CredentialKind string

// CredentialSession is a session token: the opaque value a sign-in hands to
// the client, which the session manager resolves to its session.
const CredentialSession CredentialKind = "session"

// Credential is what a transport takes from a request to authenticate it.
type Credential struct {
	Kind  CredentialKind
	Value string // the raw secret
}

// AuthOutcome is what a transport may have to write back after it
// authenticated a call.
type AuthOutcome struct {
	// Extended is the session with its new expiry, when the rolling
	// expiration extended it. A transport whose client keeps the token with
	// a date, such as a cookie, sends the token again with that date.
	Extended *identity.SessionRef
	// Ended says that the credential belongs to a session that has ended for
	// good: it is invalid, revoked, or expired. A transport whose client
	// can't drop the token itself, such as an HttpOnly cookie, takes it back.
	Ended bool
}

// Authenticator turns the credential of a call into its caller. Every
// transport authenticates through it, so that a call gets the same caller
// whichever way it arrived; a transport only reads the credential and writes
// the outcome back. AuthContext.Authenticator is one, for an application's
// own transport as well.
type Authenticator interface {
	// Authenticate returns the caller of a call that presented cred, with
	// what its transport knows about it in peer. A nil cred means the call
	// presented no credential, and the caller is anonymous.
	//
	// A credential that fails is not an error either. The caller is then
	// anonymous, and its AuthError says why: a session error such as
	// errs.CodeSessionExpired, or the failure of the lookup, which the
	// authenticator also logs. A flow that requires a user returns that
	// error, so the client learns the precise reason.
	Authenticate(ctx context.Context, cred *Credential, peer identity.Peer) (identity.Caller, AuthOutcome)
}

// AuthenticateRequests returns the stage that authenticates a request before
// its route's own middlewares run. It reads the session token where the
// carrier's delivery says (TokenCarrier.Extract), has authn build the
// caller, and puts the
// caller on the context, replacing any caller the context carried. It then
// has the carrier write back what the outcome asks for: a session that has
// ended loses its cookie (Clear), and the cookie of a session the rolling
// expiration extended comes back with the new date (Extend). That response carries the session token, so it is
// marked Cache-Control: no-store after the handler has run.
//
// The router applies it to every route (Router.ApplyAuthentication). ipCfg
// resolves the client's address; nil trusts no proxy.
func AuthenticateRequests(authn Authenticator, carrier *TokenCarrier, ipCfg *ClientIPConfig) Middleware {
	if ipCfg == nil {
		ipCfg = &ClientIPConfig{}
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			peer := identity.Peer{Transport: "http"}
			var cred *Credential
			var token string
			if r := rctx.Request; r != nil {
				peer.IPAddress = ClientIP(r, ipCfg)
				peer.UserAgent = r.UserAgent()
				if t, ok := carrier.Extract(r); ok {
					token = t
					cred = &Credential{Kind: CredentialSession, Value: t}
				}
			}
			caller, outcome := authn.Authenticate(rctx.Ctx, cred, peer)
			rctx.Ctx = identity.WithCaller(rctx.Ctx, caller)

			if outcome.Ended {
				carrier.Clear(rctx)
			}
			tokenWritten := false
			if outcome.Extended != nil {
				tokenWritten = carrier.Extend(rctx, token, outcome.Extended.ExpiresAt)
			}
			err := next(rctx)
			if tokenWritten {
				rctx.Response.SetHeader("Cache-Control", "no-store")
			}
			return err
		}
	}
}

// ApplyAuthentication wraps every mounted route in AuthenticateRequests.
// Call it after the routes are mounted and before ApplyRateLimiting, so that
// a route's rate limit runs first and a flood of requests is refused before
// it costs a session lookup.
func (r *Router) ApplyAuthentication(authn Authenticator, carrier *TokenCarrier, ipCfg *ClientIPConfig) {
	stage := AuthenticateRequests(authn, carrier, ipCfg)
	for i := range r.routes {
		r.routes[i].Handler = stage(r.routes[i].Handler)
	}
}
