package httpapi

import (
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/identity"
)

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
func AuthenticateRequests(authn core.Authenticator, carrier *TokenCarrier, ipCfg *ClientIPConfig) Middleware {
	if ipCfg == nil {
		ipCfg = &ClientIPConfig{}
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(rctx *RequestContext) error {
			peer := identity.Peer{Transport: "http"}
			var cred *core.Credential
			var token string
			if r := rctx.Request; r != nil {
				peer.IPAddress = ClientIP(r, ipCfg)
				peer.UserAgent = r.UserAgent()
				if t, ok := carrier.Extract(r); ok {
					token = t
					cred = &core.Credential{Kind: core.CredentialSession, Value: t}
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

// ApplyAuthentication wraps every mounted route in AuthenticateRequests, with
// the router's carrier. Call it after the routes are mounted and before
// ApplyRateLimiting, so that a route's rate limit runs first and a flood of
// requests is refused before it costs a session lookup.
func (r *Router) ApplyAuthentication(authn core.Authenticator, ipCfg *ClientIPConfig) {
	stage := AuthenticateRequests(authn, r.carrier, ipCfg)
	for i := range r.routes {
		r.routes[i].Handler = stage(r.routes[i].Handler)
	}
}
