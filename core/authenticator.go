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
