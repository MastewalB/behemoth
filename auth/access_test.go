package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/identity"
	"github.com/MastewalB/behemoth/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	permSelf  core.Permission = "email:change"
	permAdmin core.Permission = "user:set_password"
)

// testAccess returns an Access over a catalog with one self-service and one
// admin permission. A session is fresh when its FreshAt is within a minute.
func testAccess(t *testing.T) *DefaultAccess {
	t.Helper()
	catalog := NewDefaultPermissionCatalog()
	require.NoError(t, catalog.Declare(core.PermissionDef{Name: permSelf, Kind: core.PermissionSelf, Description: "Change the account's email address", Owner: "test"}))
	require.NoError(t, catalog.Declare(core.PermissionDef{Name: permAdmin, Kind: core.PermissionAdmin, Description: "Set any user's password", Owner: "test"}))
	catalog.Freeze()
	return NewAccess(catalog, func(s *models.Session) bool {
		return s.State == models.SessionActive && time.Since(s.FreshAt) < time.Minute
	})
}

func ctxWith(c identity.Caller) context.Context {
	return identity.WithCaller(context.Background(), c)
}

func signedIn(freshAt time.Time) identity.Caller {
	return identity.SignedIn(identity.SessionRef{ID: "s1", UserID: "user-1", State: "active", FreshAt: freshAt}, identity.Peer{Transport: "http"})
}

// The answers of RequireUser, caller by caller, as the plan's table lists
// them.
func TestRequireUser(t *testing.T) {
	a := testAccess(t)
	expired := errs.NewSessionError("Authenticate", errs.CodeSessionExpired, nil)
	lookupFailed := errors.New("database down")
	pending := errs.NewSessionError("Authenticate", errs.CodeSessionPending, nil)

	cases := []struct {
		name     string
		caller   identity.Caller
		wantUser string
		check    func(t *testing.T, err error)
	}{
		{"anonymous without a credential", identity.Anonymous(identity.Peer{}), "", func(t *testing.T, err error) {
			assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "got %v", err)
		}},
		{"anonymous with an expired session", identity.Unauthenticated(identity.Peer{}, expired, nil), "", func(t *testing.T, err error) {
			assert.Equal(t, expired, err, "the precise reason reaches the client")
		}},
		{"a failed lookup", identity.Unauthenticated(identity.Peer{}, lookupFailed, nil), "", func(t *testing.T, err error) {
			assert.Equal(t, lookupFailed, err, "a failure of the system stays one")
		}},
		{"a session waiting for a second factor", identity.Unauthenticated(identity.Peer{}, pending, &identity.SessionRef{ID: "s1", UserID: "user-1", State: "pending"}), "", func(t *testing.T, err error) {
			assert.True(t, errs.IsCode(err, errs.CodeSessionPending), "got %v", err)
		}},
		{"a system caller acting for nobody", identity.System("job"), "", func(t *testing.T, err error) {
			assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
		}},
		{"a signed-in user", signedIn(time.Now()), "user-1", nil},
		{"a system caller acting for a user", identity.System("job").For("user-2"), "user-2", nil},
		{"a misused For", identity.SignedIn(identity.SessionRef{UserID: "user-1"}, identity.Peer{}).For("user-2"), "", func(t *testing.T, err error) {
			assert.ErrorIs(t, err, identity.ErrInvalidFor)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userID, err := a.RequireUser(ctxWith(tc.caller), permSelf)
			if tc.check == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.wantUser, userID)
				return
			}
			require.Error(t, err)
			assert.Empty(t, userID)
			tc.check(t, err)
		})
	}
}

// A context without a caller is anonymous.
func TestRequireUserWithoutACaller(t *testing.T) {
	_, err := testAccess(t).RequireUser(context.Background(), permSelf)
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "got %v", err)
}

// A permission nobody declared, or one of the other kind, is a mistake in the
// flow, refused for every caller.
func TestRequireChecksTheDeclaration(t *testing.T) {
	a := testAccess(t)
	ctx := ctxWith(identity.System("job").For("user-1"))

	_, err := a.RequireUser(ctx, "email:chnage")
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "undeclared: got %v", err)
	_, err = a.RequireUser(ctx, permAdmin)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "admin permission on RequireUser: got %v", err)
	err = a.RequireAdmin(ctxWith(identity.System("job")), permSelf)
	assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "self-service permission on RequireAdmin: got %v", err)
}

func TestRequireFreshUser(t *testing.T) {
	a := testAccess(t)

	userID, err := a.RequireFreshUser(ctxWith(signedIn(time.Now())), permSelf)
	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)

	_, err = a.RequireFreshUser(ctxWith(signedIn(time.Now().Add(-time.Hour))), permSelf)
	assert.True(t, errs.IsCode(err, errs.CodeSessionNotFresh), "a stale session: got %v", err)

	userID, err = a.RequireFreshUser(ctxWith(identity.System("support-tool").For("user-2")), permSelf)
	require.NoError(t, err, "code in the process vouches for the call")
	assert.Equal(t, "user-2", userID)

	_, err = a.RequireFreshUser(context.Background(), permSelf)
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "anonymous: got %v", err)
}

func TestOptionalUser(t *testing.T) {
	a := testAccess(t)

	userID, ok, err := a.OptionalUser(ctxWith(identity.Anonymous(identity.Peer{})), permSelf)
	require.NoError(t, err)
	assert.False(t, ok, "no credential: the flow runs as a public one")
	assert.Empty(t, userID)

	expired := errs.NewSessionError("Authenticate", errs.CodeSessionExpired, nil)
	_, ok, err = a.OptionalUser(ctxWith(identity.Unauthenticated(identity.Peer{}, expired, nil)), permSelf)
	assert.False(t, ok)
	assert.Equal(t, expired, err, "a credential that failed is not taken for its absence")

	userID, ok, err = a.OptionalUser(ctxWith(signedIn(time.Now())), permSelf)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "user-1", userID)
}

func TestRequireAdmin(t *testing.T) {
	a := testAccess(t)

	assert.NoError(t, a.RequireAdmin(ctxWith(identity.System("cli")), permAdmin))

	err := a.RequireAdmin(ctxWith(signedIn(time.Now())), permAdmin)
	assert.True(t, errs.IsCode(err, errs.CodeInsufficientScope), "a user is no admin: got %v", err)
	assert.True(t, errs.IsCategory(err, errs.CategoryForbidden))

	err = a.RequireAdmin(ctxWith(identity.System("job").For("user-1")), permAdmin)
	assert.True(t, errs.IsCode(err, errs.CodeInsufficientScope), "acting for a user is no admin: got %v", err)

	err = a.RequireAdmin(context.Background(), permAdmin)
	assert.True(t, errs.IsCode(err, errs.CodeSessionMissing), "anonymous: got %v", err)
}
