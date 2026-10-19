package core

import "context"

// Permission names an action that a flow requires of its caller, in the form
// resource:action in lowercase snake case, such as "email:change" or
// "session_token:issue". A plugin declares the permissions its flows require
// in its Declare, through PluginInitContext.Permissions. A name that has
// shipped doesn't change: grants store it.
type Permission string

// PermissionKind says whose account a permission acts on. A self-service
// permission never satisfies an admin requirement, and an admin permission
// never satisfies a self-service one.
type PermissionKind string

const (
	PermissionSelf  PermissionKind = "self"  // the caller's own account: a self-service flow
	PermissionAdmin PermissionKind = "admin" // an account named in the input: an admin operation
)

// PermissionDef declares one permission.
type PermissionDef struct {
	Name Permission
	Kind PermissionKind
	// Description says what the permission allows, in words a user can read
	// on a consent screen or on a form that creates an API key. Required.
	Description string
	// Owner is the plugin that declared the permission, or "core". The
	// catalog a declarer receives sets it.
	Owner string
}

// PermissionCatalog holds the permissions of every flow. Prepare fills it
// from core's declarations and each plugin's Declare, and freezes it.
type PermissionCatalog interface {
	// Declare adds def. It is a configuration error when def's name isn't of
	// the form resource:action in lowercase snake case, when its kind is
	// neither PermissionSelf nor PermissionAdmin, when its description is
	// empty, when the name is declared already, or when the catalog is
	// frozen.
	Declare(def PermissionDef) error

	// Lookup returns the declaration of p.
	Lookup(p Permission) (PermissionDef, bool)

	// All returns every declaration, ordered by name.
	All() []PermissionDef
}

// Access answers whether the caller on a context may run a flow. A
// self-service flow calls RequireUser, RequireFreshUser, or OptionalUser
// first, with the permission it declared, and acts on the user it returns,
// never on a user named in its input. An admin operation calls RequireAdmin.
// The caller is identity.CallerFrom(ctx).
//
// A permission that was never declared, or that is declared with the other
// kind, is a configuration error.
type Access interface {
	// RequireUser returns the user the caller acts for, when the caller holds
	// p, a self-service permission. Otherwise it returns:
	//
	//	anonymous, no credential presented       a session error, errs.CodeSessionMissing
	//	anonymous, its credential failed         the caller's AuthError: a session error such as
	//	                                         errs.CodeSessionExpired, or the failure of the lookup
	//	a user or service without p              a forbidden error, errs.CodeInsufficientScope
	//	a system caller that acts for nobody     a configuration error: name the user with For
	RequireUser(ctx context.Context, p Permission) (userID string, err error)

	// RequireFreshUser is RequireUser, and the caller's session must be
	// fresh as well (SessionManager.IsFresh), or it returns a session error
	// with errs.CodeSessionNotFresh. A system caller that acts for a user
	// passes without a session.
	RequireFreshUser(ctx context.Context, p Permission) (userID string, err error)

	// OptionalUser is for a flow that acts for a user when there is one, and
	// runs as a public flow when there is none. ok is false, with a nil
	// error, for an anonymous caller that presented no credential. Any other
	// caller is checked as RequireUser checks it, so a credential that failed
	// is reported and not taken for its absence.
	OptionalUser(ctx context.Context, p Permission) (userID string, ok bool, err error)

	// RequireAdmin lets an admin operation through when the caller holds p,
	// an admin permission. A system caller holds every admin permission. An
	// anonymous caller gets what RequireUser gives it, and any other caller a
	// forbidden error with errs.CodeInsufficientScope.
	RequireAdmin(ctx context.Context, p Permission) error
}
