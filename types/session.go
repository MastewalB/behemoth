package types

import (
	"context"
	"net/http"

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

	ListForUser(ctx context.Context, userID any) ([]*models.Session, error)

	// WriteToken puts rawToken wherever Transport dictates - Set-Cookie for
	// TransportCookie, and/or staging it in rctx.Values for TransportHeader
	// (a header-transport client gets the token back in the JSON body; there's
	// nothing to "write" server-side for a bearer token, since the client owns
	// re-attaching it on subsequent requests).
	WriteToken(rctx *RequestContext, rawToken string, session *models.Session)

	// ExtractToken reads the token per Transport - checks the Authorization
	// header, the cookie, or both, depending on config.
	ExtractToken(r *http.Request) (string, bool)

	// SupportsRevocation lets callers (admin UI, HTTP layer) know whether
	// Revoke/RevokeAllForUser are meaningful or a no-op; false for purely
	// stateless/self-verifying implementations.
	SupportsRevocation() bool
}

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

type TokenTransport string

const (
	TransportCookie TokenTransport = "cookie"
	TransportHeader TokenTransport = "header" // Authorization: Bearer <token>
	TransportBoth   TokenTransport = "both"   // accept either; useful during a migration
)

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
