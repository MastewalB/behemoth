package plugins

import "github.com/MastewalB/behemoth/types"

const (
	HookUserBeforeCreate    types.HookPoint = "data.user.beforeCreate"
	HookUserAfterCreate     types.HookPoint = "data.user.afterCreate"
	HookSignUpBefore        types.HookPoint = "auth.signUp.before"
	HookSignUpAfter         types.HookPoint = "auth.signUp.after"
	HookSignInBefore        types.HookPoint = "auth.signIn.before"
	HookSignInCredentialsOK types.HookPoint = "auth.signIn.credentialsVerified"
	HookSignInSuccess       types.HookPoint = "auth.signIn.success"
	HookSignInFailed        types.HookPoint = "auth.signIn.failed"
)
