// Package identity says who an operation runs for and where the call came
// from: the Caller, which flows, hook handlers, and rate-limit rules read
// from the context. A transport builds the caller of a call through an
// authenticator, and code in the process names itself with System. The zero
// Caller is anonymous and holds no permission, so a call that nobody
// identified is never trusted.
//
// identity imports no other Behemoth package, so that every package can read
// the caller.
package identity

import (
	"context"
	"errors"
	"time"
)

// PrincipalType says what kind of identity a Principal names.
type PrincipalType string

const (
	PrincipalUser    PrincipalType = "user"    // ID is a user id
	PrincipalService PrincipalType = "service" // ID is a client id: another system with a key of its own
	PrincipalSystem  PrincipalType = "system"  // ID names code in the process, such as "purge-sessions"
)

// Principal is who an operation runs for. The zero value is nobody.
type Principal struct {
	Type PrincipalType
	ID   string
}

// IsZero reports whether p names nobody.
func (p Principal) IsZero() bool { return p.Type == "" }

// SessionRef is the session a caller was authenticated with, as plain data:
// what flows and the audit log read of it, and no secret.
type SessionRef struct {
	ID             string
	UserID         string
	State          string // "active", or "pending" while a second factor is outstanding
	ExpiresAt      time.Time
	FreshAt        time.Time // when the user last proved a credential
	Factors        []string  // what the session's sign-in proved, in order: core's Factor names, such as "password"
	ImpersonatorID string    // the user who impersonates UserID, if any
}

// Peer is what a transport knows about a call besides its credential.
type Peer struct {
	Transport string // the protocol the call arrived by, such as "http"; empty for a call from code in the process
	IPAddress string // the client's address, resolved with the trusted proxies
	UserAgent string
}

// Caller is who an operation runs for, and where the call came from. Its
// fields are unexported: a caller comes from System, from For, or from an
// authenticator, through Anonymous, Unauthenticated, or SignedIn. The zero
// value is an anonymous caller about which nothing is known, and it holds no
// permission.
type Caller struct {
	principal Principal
	delegate  Principal
	session   *SessionRef
	grant     grant
	authErr   error
	peer      Peer
}

// grant is the set of permissions a caller holds. The zero value holds none.
// A grant that lists permissions one by one, for a delegated credential, is
// not built: every caller holds either all of a kind or none of it.
type grant struct {
	self  bool // every self-service permission, over the principal's own account
	admin bool // every admin permission
}

// Principal returns who the operation runs for. It is zero for an anonymous
// caller.
func (c Caller) Principal() Principal { return c.principal }

// Delegate returns who acts for the principal when it isn't the principal
// itself: the system for a job that acts for a user (For), or the user who
// impersonates the principal. It is zero when the principal acts itself.
func (c Caller) Delegate() Principal { return c.delegate }

// Session returns the session the caller was authenticated with. ok is false
// when there is none: for a system caller, a service, and an anonymous caller
// without a session that waits for a second factor.
func (c Caller) Session() (session SessionRef, ok bool) {
	if c.session == nil {
		return SessionRef{}, false
	}
	return *c.session, true
}

// AuthError returns why the caller is anonymous although it presented a
// credential, such as an expired session. It is nil for a caller that
// presented none, and for a caller that authenticated.
func (c Caller) AuthError() error { return c.authErr }

// Peer returns what the transport knew about the call. It is zero for a call
// from code in the process.
func (c Caller) Peer() Peer { return c.peer }

// IsAnonymous reports whether the caller authenticated as nobody.
func (c Caller) IsAnonymous() bool { return c.principal.IsZero() }

// Holds reports whether the caller holds permission. admin says whether the
// permission is an admin permission, which acts on an account named in the
// input, or a self-service one, which acts on the caller's own account. A
// signed-in user holds every self-service permission, a system caller holds
// every permission, and an anonymous caller holds none.
func (c Caller) Holds(permission string, admin bool) bool {
	if admin {
		return c.grant.admin
	}
	return c.grant.self
}

// System returns a caller for code in the process, such as a job or a CLI
// command, named for the audit log. Its principal is the system with ID
// name, and it holds every permission. A transport never builds one.
func System(name string) Caller {
	return Caller{
		principal: Principal{Type: PrincipalSystem, ID: name},
		grant:     grant{self: true, admin: true},
	}
}

// ErrInvalidFor is the AuthError of the caller For returns when it is called
// on a caller that isn't a system caller, or with an empty user id.
var ErrInvalidFor = errors.New("identity: For needs a system caller and a user id")

// For returns a caller that acts for the user with userID: its principal is
// the user, and its delegate is the system caller c, so that the audit log
// records who acted. It holds every self-service permission over the user's
// account, and no admin permission. On a caller that isn't a system caller,
// or with an empty userID, For returns an anonymous caller whose AuthError is
// ErrInvalidFor.
func (c Caller) For(userID string) Caller {
	if c.principal.Type != PrincipalSystem || !c.delegate.IsZero() || userID == "" {
		return Caller{authErr: ErrInvalidFor, peer: c.peer}
	}
	return Caller{
		principal: Principal{Type: PrincipalUser, ID: userID},
		delegate:  c.principal,
		grant:     grant{self: true},
		peer:      c.peer,
	}
}

// Anonymous returns the caller of a call that presented no credential, with
// what its transport knew about it.
func Anonymous(peer Peer) Caller {
	return Caller{peer: peer}
}

// Unauthenticated returns the caller of a call whose credential
// authenticated nobody. reason says why, and is what a flow that requires a
// user returns: the session error of an invalid, revoked, expired, or pending
// session, or the failure of the lookup. pending is the session of a
// credential that waits for a second factor, so that a second-factor flow
// can find it, or nil.
func Unauthenticated(peer Peer, reason error, pending *SessionRef) Caller {
	c := Caller{peer: peer, authErr: reason}
	if pending != nil {
		s := *pending
		c.session = &s
	}
	return c
}

// SignedIn returns the caller of a call that session authenticated: its
// principal is the session's user, and it holds every self-service
// permission over that account. When the session is an impersonation, the
// impersonating user is the delegate. It is for an authenticator: within
// Behemoth, only package auth calls it, and a test checks that.
func SignedIn(session SessionRef, peer Peer) Caller {
	s := session
	c := Caller{
		principal: Principal{Type: PrincipalUser, ID: session.UserID},
		session:   &s,
		grant:     grant{self: true},
		peer:      peer,
	}
	if session.ImpersonatorID != "" {
		c.delegate = Principal{Type: PrincipalUser, ID: session.ImpersonatorID}
	}
	return c
}

type callerKey struct{}

// WithCaller returns ctx carrying c. A transport calls it once per call, with
// the caller its authenticator built, and replaces any caller ctx carried.
// Code in the process calls it with System, or with System(...).For(userID).
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller ctx carries, or the zero Caller, which is
// anonymous, when it carries none.
func CallerFrom(ctx context.Context) Caller {
	if ctx == nil {
		return Caller{}
	}
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}
