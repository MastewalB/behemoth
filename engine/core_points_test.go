package engine

import (
	"github.com/MastewalB/behemoth/dispatch"
	"testing"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
)

// Core declares every point its own code fires, each in the phase it is
// fired in, and the data points the store fires pass the Boot check.
func TestCoreDeclaresTheHookPointsItFires(t *testing.T) {
	catalog := dispatch.NewDefaultHookCatalog()
	ic := newScopedInitContext(catalog, nil, nil, nil, nil, coreOwner)
	if err := CoreDeclareHookPoints(ic); err != nil {
		t.Fatal(err)
	}
	want := map[core.HookPoint]core.HookPhase{
		hooks.HookSignUpBefore: core.BeforeHookPhase, hooks.HookSignUpAfter: core.AfterHookPhase, hooks.HookSignUpFailed: core.FailedHookPhase,
		hooks.HookSignInBefore: core.BeforeHookPhase, hooks.HookSignInCredentialsVerified: core.BeforeHookPhase,
		hooks.HookSignInAfter: core.AfterHookPhase, hooks.HookSignInFailed: core.FailedHookPhase,
		hooks.HookSignOutBefore: core.BeforeHookPhase, hooks.HookSignOutAfter: core.AfterHookPhase,
		hooks.HookSessionBeforeCreate: core.BeforeHookPhase, hooks.HookSessionAfterCreate: core.AfterHookPhase,
		hooks.HookSessionBeforeRevoke: core.BeforeHookPhase, hooks.HookSessionAfterRevoke: core.AfterHookPhase,
		hooks.HookSessionTokenBeforeIssue: core.BeforeHookPhase, hooks.HookSessionTokenAfterIssue: core.AfterHookPhase,
		hooks.HookSessionTokenIssueFailed: core.FailedHookPhase,
		hooks.HookTokenBeforeIssue:        core.BeforeHookPhase, hooks.HookTokenAfterIssue: core.AfterHookPhase,
		hooks.HookTokenConsumed: core.AfterHookPhase, hooks.HookTokenFailed: core.FailedHookPhase,
		hooks.HookUserBeforeCreate: core.BeforeHookPhase, hooks.HookUserAfterCreate: core.AfterHookPhase,
		hooks.HookUserBeforeUpdate: core.BeforeHookPhase, hooks.HookUserAfterUpdate: core.AfterHookPhase,
		hooks.HookUserCreated: core.AfterHookPhase, hooks.HookUserUpdated: core.AfterHookPhase,
		hooks.HookUserBeforeDelete: core.BeforeHookPhase, hooks.HookUserAfterDelete: core.AfterHookPhase,
		hooks.HookUserDeleted: core.AfterHookPhase,
	}
	for point, phase := range want {
		def, ok := catalog.Lookup(point)
		if !ok {
			t.Errorf("%q is not declared", point)
		} else if def.Phase != phase || def.Owner != coreOwner {
			t.Errorf("%q declared as phase %q by %q, want %q by %q", point, def.Phase, def.Owner, phase, coreOwner)
		}
	}
	if got := len(catalog.All()); got != len(want) {
		t.Errorf("core declares %d points, the test knows %d", got, len(want))
	}

	if err := dispatch.CheckDataHookPoints(catalog); err != nil {
		t.Errorf("CheckDataHookPoints(core) = %v", err)
	}
}
