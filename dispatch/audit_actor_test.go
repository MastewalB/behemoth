package dispatch

import (
	"context"
	"testing"

	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/identity"
	"github.com/go-behemoth/behemoth/models"
	"github.com/go-behemoth/behemoth/telemetry"
)

// The audit event of a dispatch names the caller: its principal as the
// actor, its delegate, and the session it signed in with. An anonymous
// caller that a transport authenticated is credited with a successful
// operation on its own account, and code that did not name itself is the
// system.
func TestAuditEventNamesTheCaller(t *testing.T) {
	def := core.HookPointDef{Point: "auth.test.after", Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}}
	d := NewDefaultDispatcher(NewDefaultHookCatalog(), nil, nil, core.AuditConfig{}, nil)
	peer := identity.Peer{Transport: "http", IPAddress: "203.0.113.7", UserAgent: "agent/1"}
	signedUp := &models.User{ID: "u3"} // a result whose subject is a user
	failed := &core.FailureReason{Code: "invalid_credentials"}

	for name, tc := range map[string]struct {
		caller       identity.Caller
		result       any
		reason       *core.FailureReason
		actorType    telemetry.ActorType
		actorID      string
		delegateType telemetry.ActorType
		delegateID   string
		session      string
	}{
		"signed in": {
			caller:    identity.SignedIn(identity.SessionRef{ID: "s1", UserID: "u1", State: "active"}, peer),
			actorType: telemetry.ActorUser, actorID: "u1", session: "s1",
		},
		"impersonated": {
			caller:    identity.SignedIn(identity.SessionRef{ID: "s2", UserID: "u2", State: "active", ImpersonatorID: "admin1"}, peer),
			actorType: telemetry.ActorUser, actorID: "u2", delegateType: telemetry.ActorUser, delegateID: "admin1", session: "s2",
		},
		"a job for a user": {
			caller:    identity.System("support-tool").For("u1"),
			actorType: telemetry.ActorUser, actorID: "u1", delegateType: telemetry.ActorSystem, delegateID: "support-tool",
		},
		"a job": {
			caller:    identity.System("purge-sessions"),
			actorType: telemetry.ActorSystem, actorID: "purge-sessions",
		},
		"anonymous, its own sign-up": {
			caller: identity.Anonymous(peer), result: signedUp,
			actorType: telemetry.ActorUser, actorID: "u3",
		},
		"anonymous, a failed sign-in": {
			caller: identity.Anonymous(peer), result: signedUp, reason: failed,
			actorType: telemetry.ActorAnonymous,
		},
		"no transport, no name": {
			caller: identity.Caller{}, result: signedUp,
			actorType: telemetry.ActorSystem,
		},
	} {
		hctx := &core.HookContext{Ctx: identity.WithCaller(context.Background(), tc.caller)}
		event := d.auditEvent(hctx, def.Point, def, tc.result, tc.reason)
		if event.ActorType != tc.actorType || event.ActorID != tc.actorID {
			t.Errorf("%s: actor %s %q, want %s %q", name, event.ActorType, event.ActorID, tc.actorType, tc.actorID)
		}
		if event.DelegateType != tc.delegateType || event.DelegateID != tc.delegateID {
			t.Errorf("%s: delegate %s %q, want %s %q", name, event.DelegateType, event.DelegateID, tc.delegateType, tc.delegateID)
		}
		if event.SessionID != tc.session {
			t.Errorf("%s: session %q, want %q", name, event.SessionID, tc.session)
		}
		wantIP, wantAgent := tc.caller.Peer().IPAddress, tc.caller.Peer().UserAgent
		if event.IPAddress != wantIP || event.UserAgent != wantAgent {
			t.Errorf("%s: address %q and agent %q, want the caller's %q and %q", name, event.IPAddress, event.UserAgent, wantIP, wantAgent)
		}
	}
}

// AuditConfig.OmitIPAndAgent leaves the caller's address and user agent out
// of the event, and nothing else.
func TestAuditEventOmitsTheAddressWhenConfigured(t *testing.T) {
	def := core.HookPointDef{Point: "auth.test.after", Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}}
	d := NewDefaultDispatcher(NewDefaultHookCatalog(), nil, nil, core.AuditConfig{OmitIPAndAgent: true}, nil)
	caller := identity.SignedIn(identity.SessionRef{ID: "s1", UserID: "u1", State: "active"},
		identity.Peer{Transport: "http", IPAddress: "203.0.113.7", UserAgent: "agent/1"})

	event := d.auditEvent(&core.HookContext{Ctx: identity.WithCaller(context.Background(), caller)}, def.Point, def, nil, nil)
	if event.IPAddress != "" || event.UserAgent != "" {
		t.Errorf("address %q and agent %q recorded", event.IPAddress, event.UserAgent)
	}
	if event.ActorID != "u1" || event.SessionID != "s1" {
		t.Errorf("the actor and the session are still recorded: %q, %q", event.ActorID, event.SessionID)
	}
}
