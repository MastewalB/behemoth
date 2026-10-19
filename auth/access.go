package auth

import (
	"context"
	"fmt"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
)

// forbiddenMessage is what a client is told when its credential doesn't
// hold the permission an operation requires.
const forbiddenMessage = "the credential is not allowed this action"

// DefaultAccess is the Access Boot builds. It checks the caller on a context
// against the declarations of a permission catalog.
type DefaultAccess struct {
	catalog core.PermissionCatalog
	isFresh func(*models.Session) bool
}

// NewAccess returns the Access of the permissions in catalog. isFresh says
// whether a session's credentials were checked recently enough for
// RequireFreshUser; Boot passes SessionManager.IsFresh.
func NewAccess(catalog core.PermissionCatalog, isFresh func(*models.Session) bool) *DefaultAccess {
	return &DefaultAccess{catalog: catalog, isFresh: isFresh}
}

// RequireUser implements [core.Access].
func (a *DefaultAccess) RequireUser(ctx context.Context, p core.Permission) (string, error) {
	const op = "Access.RequireUser"
	if err := a.declared(op, p, core.PermissionSelf); err != nil {
		return "", err
	}
	return user(op, identity.CallerFrom(ctx), p)
}

// RequireFreshUser implements [core.Access].
func (a *DefaultAccess) RequireFreshUser(ctx context.Context, p core.Permission) (string, error) {
	const op = "Access.RequireFreshUser"
	if err := a.declared(op, p, core.PermissionSelf); err != nil {
		return "", err
	}
	caller := identity.CallerFrom(ctx)
	userID, err := user(op, caller, p)
	if err != nil {
		return "", err
	}
	if caller.Delegate().Type == identity.PrincipalSystem {
		return userID, nil // code in the process vouches for the call
	}
	session, ok := caller.Session()
	if !ok || !a.isFresh(&models.Session{State: models.SessionState(session.State), FreshAt: session.FreshAt}) {
		return "", errs.NewSessionError(op, errs.CodeSessionNotFresh, nil)
	}
	return userID, nil
}

// OptionalUser implements [core.Access].
func (a *DefaultAccess) OptionalUser(ctx context.Context, p core.Permission) (string, bool, error) {
	const op = "Access.OptionalUser"
	if err := a.declared(op, p, core.PermissionSelf); err != nil {
		return "", false, err
	}
	caller := identity.CallerFrom(ctx)
	if caller.IsAnonymous() && caller.AuthError() == nil {
		return "", false, nil
	}
	userID, err := user(op, caller, p)
	if err != nil {
		return "", false, err
	}
	return userID, true, nil
}

// RequireAdmin implements [core.Access].
func (a *DefaultAccess) RequireAdmin(ctx context.Context, p core.Permission) error {
	const op = "Access.RequireAdmin"
	if err := a.declared(op, p, core.PermissionAdmin); err != nil {
		return err
	}
	caller := identity.CallerFrom(ctx)
	switch {
	case caller.IsAnonymous():
		return anonymousRefusal(op, caller)
	case caller.Holds(string(p), true):
		return nil
	default:
		return errs.NewForbidden(op, errs.CodeInsufficientScope, forbiddenMessage)
	}
}

// declared checks that p was declared, and with kind, so that a typo or a
// missing declaration fails the first call instead of passing until a
// partial grant meets it.
func (a *DefaultAccess) declared(op string, p core.Permission, kind core.PermissionKind) error {
	def, ok := a.catalog.Lookup(p)
	if !ok {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q was never declared", p), nil)
	}
	if def.Kind != kind {
		return errs.NewConfigurationError(op, fmt.Sprintf("permission %q is declared %s, and %s takes a %s permission", p, def.Kind, op, kind), nil)
	}
	return nil
}

// user returns the user caller acts for, when it holds the self-service
// permission p.
func user(op string, caller identity.Caller, p core.Permission) (string, error) {
	principal := caller.Principal()
	switch principal.Type {
	case identity.PrincipalUser:
		if !caller.Holds(string(p), false) {
			return "", errs.NewForbidden(op, errs.CodeInsufficientScope, forbiddenMessage)
		}
		return principal.ID, nil
	case identity.PrincipalSystem:
		return "", errs.NewConfigurationError(op, fmt.Sprintf("system caller %q acts for no user: name the user with For", principal.ID), nil)
	case "":
		return "", anonymousRefusal(op, caller)
	default:
		// A service has no account of its own to act on.
		return "", errs.NewForbidden(op, errs.CodeInsufficientScope, forbiddenMessage)
	}
}

// anonymousRefusal is the error of an anonymous caller: why its credential
// failed, or that it presented none.
func anonymousRefusal(op string, caller identity.Caller) error {
	if err := caller.AuthError(); err != nil {
		return err
	}
	return errs.NewSessionError(op, errs.CodeSessionMissing, nil)
}

var _ core.Access = (*DefaultAccess)(nil)
