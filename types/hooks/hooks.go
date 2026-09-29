package hooks

import "github.com/MastewalB/behemoth/types"

const (
	HookUserBeforeCreate          types.HookPoint = "data.user.beforeCreate"
	HookUserAfterCreate           types.HookPoint = "data.user.afterCreate"
	HookSignUpBefore              types.HookPoint = "auth.signUp.before"
	HookSignUpAfter               types.HookPoint = "auth.signUp.after"
	HookSignUpFailed              types.HookPoint = "auth.signUp.failed"
	HookSignInBefore              types.HookPoint = "auth.signIn.before"
	HookSignInCredentialsVerified types.HookPoint = "auth.signIn.credentialsVerified"
	HookSignInAfter               types.HookPoint = "auth.signIn.after"
	HookSignInFailed              types.HookPoint = "auth.signIn.failed"
	HookSignOutBefore             types.HookPoint = "auth.signOut.before"
	HookSignOutAfter              types.HookPoint = "auth.signOut.after"
	HookSessionCreate             types.HookPoint = "auth.session.create"
	HookSessionRevoke             types.HookPoint = "auth.session.revoke"
	HookTokenIssue                types.HookPoint = "token.issue"

	HookTokenBeforeIssue = types.HookPoint("token.beforeIssue")
	HookTokenAfterIssue  = types.HookPoint("token.afterIssue") // Phase: After
	HookTokenConsumed    = types.HookPoint("token.consumed")   // Phase: After
	HookTokenFailed      = types.HookPoint("token.failed")     // Phase: Failed
)

// HookPayloadKey values are the published contract for well-known behemoth.M keys
// carried in hook payloads. Any hook point whose payload conveys one of these
// concepts MUST use the same key here
// This communication is what lets an unrelated plugin's handler read or enrich a value
// (e.g. a geo-IP plugin setting resolved city's IPAddress to the session during
// session.create.before hook call) will need to use the HookValueIPAddress.
// The keys have type string to make sure a direct compatibility to behemoth.M's map[string]any type
// to avoid unnecessary conversion string(Type) on each use
const (
	HookValueUserID    = "userID"
	HookValueSessionID = "sessionID"
	HookValueIPAddress = "ipAddress"
	HookValueUserAgent = "userAgent"
	HookValueState     = "state"
	HookValueReason    = "reason"
	HookValueEmail     = "email"

	HookValueTokenID      = "tokenID"
	HookValueTokenKind    = "kind"
	HookValueTokenSubject = "subject"
)
