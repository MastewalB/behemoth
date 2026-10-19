package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MastewalB/behemoth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The zero caller, and the one a context without a caller gives, is
// anonymous and holds no permission.
func TestZeroCallerIsAnonymous(t *testing.T) {
	for name, c := range map[string]identity.Caller{
		"zero value":               {},
		"empty context":            identity.CallerFrom(context.Background()),
		"nil context":              identity.CallerFrom(nilContext()),
		"no credential":            identity.Anonymous(identity.Peer{Transport: "http"}),
		"a credential that failed": identity.Unauthenticated(identity.Peer{}, errors.New("expired"), nil),
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, c.IsAnonymous())
			assert.True(t, c.Principal().IsZero())
			assert.False(t, c.Holds("email:change", false))
			assert.False(t, c.Holds("user:set_password", true))
			_, ok := c.Session()
			assert.False(t, ok)
		})
	}
}

func TestWithCallerRoundTrip(t *testing.T) {
	c := identity.System("purge-sessions")
	got := identity.CallerFrom(identity.WithCaller(context.Background(), c))
	assert.Equal(t, identity.Principal{Type: identity.PrincipalSystem, ID: "purge-sessions"}, got.Principal())

	replaced := identity.CallerFrom(identity.WithCaller(identity.WithCaller(context.Background(), c), identity.Caller{}))
	assert.True(t, replaced.IsAnonymous(), "the last caller set wins")
}

func TestSystemHoldsEveryPermission(t *testing.T) {
	c := identity.System("cli")
	assert.False(t, c.IsAnonymous())
	assert.True(t, c.Delegate().IsZero())
	assert.True(t, c.Holds("email:change", false))
	assert.True(t, c.Holds("user:set_password", true))
}

// For makes the user the principal and keeps the system as the delegate,
// with the self-service permissions of the user's account only.
func TestForActsForAUser(t *testing.T) {
	c := identity.System("support-tool").For("user-1")
	assert.Equal(t, identity.Principal{Type: identity.PrincipalUser, ID: "user-1"}, c.Principal())
	assert.Equal(t, identity.Principal{Type: identity.PrincipalSystem, ID: "support-tool"}, c.Delegate())
	assert.True(t, c.Holds("email:change", false))
	assert.False(t, c.Holds("user:set_password", true), "acting for a user is not an admin")
	assert.NoError(t, c.AuthError())
}

// For on anything but a system caller fails closed: the result is anonymous
// and says why.
func TestForNeedsASystemCallerAndAUser(t *testing.T) {
	signedIn := identity.SignedIn(identity.SessionRef{ID: "s1", UserID: "user-1", State: "active"}, identity.Peer{})
	for name, c := range map[string]identity.Caller{
		"anonymous":                identity.Caller{}.For("user-1"),
		"signed in":                signedIn.For("user-2"),
		"system acting for a user": identity.System("job").For("user-1").For("user-2"),
		"empty user id":            identity.System("job").For(""),
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, c.IsAnonymous())
			assert.ErrorIs(t, c.AuthError(), identity.ErrInvalidFor)
			assert.False(t, c.Holds("email:change", false))
		})
	}
}

func TestSignedIn(t *testing.T) {
	ref := identity.SessionRef{ID: "s1", UserID: "user-1", State: "active", FreshAt: time.Now()}
	peer := identity.Peer{Transport: "http", IPAddress: "203.0.113.7", UserAgent: "test"}
	c := identity.SignedIn(ref, peer)

	assert.Equal(t, identity.Principal{Type: identity.PrincipalUser, ID: "user-1"}, c.Principal())
	assert.True(t, c.Delegate().IsZero())
	assert.Equal(t, peer, c.Peer())
	assert.True(t, c.Holds("email:change", false))
	assert.False(t, c.Holds("user:set_password", true))
	got, ok := c.Session()
	require.True(t, ok)
	assert.Equal(t, ref, got)

	got.UserID = "someone-else"
	again, _ := c.Session()
	assert.Equal(t, "user-1", again.UserID, "Session returns a copy")

	impersonated := identity.SignedIn(identity.SessionRef{ID: "s2", UserID: "user-1", ImpersonatorID: "admin-1"}, peer)
	assert.Equal(t, identity.Principal{Type: identity.PrincipalUser, ID: "admin-1"}, impersonated.Delegate())
}

// A credential that authenticates nobody keeps its reason, and the session
// of a pending second factor, without making the caller anyone.
func TestUnauthenticatedKeepsTheReasonAndThePendingSession(t *testing.T) {
	reason := errors.New("session pending")
	pending := &identity.SessionRef{ID: "s1", UserID: "user-1", State: "pending"}
	c := identity.Unauthenticated(identity.Peer{}, reason, pending)

	assert.True(t, c.IsAnonymous())
	assert.Equal(t, reason, c.AuthError())
	got, ok := c.Session()
	require.True(t, ok)
	assert.Equal(t, "pending", got.State)

	pending.UserID = "changed"
	again, _ := c.Session()
	assert.Equal(t, "user-1", again.UserID, "the caller keeps its own copy")
}

// nilContext returns a nil context, which CallerFrom treats as one without a
// caller.
func nilContext() context.Context { return nil }
