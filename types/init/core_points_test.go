package types

import (
	"github.com/MastewalB/behemoth/dispatch"
	"testing"

	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
)

// Core declares every point its own code fires, each in the phase it is
// fired in, and the data points the store fires pass the Boot check.
func TestCoreDeclaresTheHookPointsItFires(t *testing.T) {
	catalog := dispatch.NewDefaultHookCatalog()
	ic := newScopedInitContext(catalog, nil, nil, nil, coreOwner)
	if err := CoreDeclareHookPoints(ic); err != nil {
		t.Fatal(err)
	}
	want := map[types.HookPoint]types.HookPhase{
		hooks.HookSignUpBefore: types.BeforeHookPhase, hooks.HookSignUpAfter: types.AfterHookPhase, hooks.HookSignUpFailed: types.FailedHookPhase,
		hooks.HookSignInBefore: types.BeforeHookPhase, hooks.HookSignInCredentialsVerified: types.BeforeHookPhase,
		hooks.HookSignInAfter: types.AfterHookPhase, hooks.HookSignInFailed: types.FailedHookPhase,
		hooks.HookSignOutBefore: types.BeforeHookPhase, hooks.HookSignOutAfter: types.AfterHookPhase,
		hooks.HookSessionBeforeCreate: types.BeforeHookPhase, hooks.HookSessionAfterCreate: types.AfterHookPhase,
		hooks.HookSessionBeforeRevoke: types.BeforeHookPhase, hooks.HookSessionAfterRevoke: types.AfterHookPhase,
		hooks.HookSessionTokenBeforeIssue: types.BeforeHookPhase, hooks.HookSessionTokenAfterIssue: types.AfterHookPhase,
		hooks.HookSessionTokenIssueFailed: types.FailedHookPhase,
		hooks.HookTokenBeforeIssue:        types.BeforeHookPhase, hooks.HookTokenAfterIssue: types.AfterHookPhase,
		hooks.HookTokenConsumed: types.AfterHookPhase, hooks.HookTokenFailed: types.FailedHookPhase,
		hooks.HookUserBeforeCreate: types.BeforeHookPhase, hooks.HookUserAfterCreate: types.AfterHookPhase,
		hooks.HookUserBeforeUpdate: types.BeforeHookPhase, hooks.HookUserAfterUpdate: types.AfterHookPhase,
		hooks.HookUserCreated: types.AfterHookPhase, hooks.HookUserUpdated: types.AfterHookPhase,
		hooks.HookUserBeforeDelete: types.BeforeHookPhase, hooks.HookUserAfterDelete: types.AfterHookPhase,
		hooks.HookUserDeleted: types.AfterHookPhase,
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
