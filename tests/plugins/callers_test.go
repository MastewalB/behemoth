package plugins_test

import (
	"context"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/identity"
)

// actingFor returns ctx with a caller that acts for the user with userID:
// test code that runs a self-service flow for a user, as a job would. An
// empty userID returns ctx as it is, an anonymous caller.
func actingFor(ctx context.Context, userID string) context.Context {
	if userID == "" {
		return ctx
	}
	return identity.WithCaller(ctx, identity.System("test").For(userID))
}

// asAdmin returns ctx with a system caller, which holds every admin
// permission: test code that runs an admin operation, as a job would.
func asAdmin(ctx context.Context) context.Context {
	return identity.WithCaller(ctx, identity.System("test-admin"))
}

// presenting returns ctx with the caller the authenticator makes of the
// session token raw, as a transport would put it on the context: signed in
// for a live session, anonymous with the reason otherwise.
func presenting(ctx context.Context, ac *core.AuthContext, raw string) context.Context {
	caller, _ := ac.Authenticator.Authenticate(ctx, &core.Credential{Kind: core.CredentialSession, Value: raw}, identity.Peer{Transport: "test"})
	return identity.WithCaller(ctx, caller)
}
