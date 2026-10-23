// Package hooks names the hook points core declares and fires, and the keys of
// the values a firing site publishes for handlers and rate-limit rules.
package hooks

import "github.com/go-behemoth/behemoth/core"

const (
	HookUserBeforeCreate          core.HookPoint = "data.user.beforeCreate"
	HookUserAfterCreate           core.HookPoint = "data.user.afterCreate"
	HookUserBeforeUpdate          core.HookPoint = "data.user.beforeUpdate"
	HookUserAfterUpdate           core.HookPoint = "data.user.afterUpdate"
	HookUserCreated               core.HookPoint = "data.user.created" // after commit
	HookUserUpdated               core.HookPoint = "data.user.updated" // after commit
	HookUserBeforeDelete          core.HookPoint = "data.user.beforeDelete"
	HookUserAfterDelete           core.HookPoint = "data.user.afterDelete"
	HookUserDeleted               core.HookPoint = "data.user.deleted" // after commit
	HookSignUpBefore              core.HookPoint = "auth.signUp.before"
	HookSignUpAfter               core.HookPoint = "auth.signUp.after"
	HookSignUpFailed              core.HookPoint = "auth.signUp.failed"
	HookSignInBefore              core.HookPoint = "auth.signIn.before"
	HookSignInCredentialsVerified core.HookPoint = "auth.signIn.credentialsVerified"
	HookSignInAfter               core.HookPoint = "auth.signIn.after"
	HookSignInFailed              core.HookPoint = "auth.signIn.failed"
	HookSignOutBefore             core.HookPoint = "auth.signOut.before"
	HookSignOutAfter              core.HookPoint = "auth.signOut.after"
	HookSessionBeforeCreate       core.HookPoint = "auth.session.beforeCreate"
	HookSessionAfterCreate        core.HookPoint = "auth.session.afterCreate"
	HookSessionBeforeRevoke       core.HookPoint = "auth.session.beforeRevoke"
	HookSessionAfterRevoke        core.HookPoint = "auth.session.afterRevoke"

	// fired by the session token flow (core.SessionTokens)
	HookSessionTokenBeforeIssue = core.HookPoint("auth.sessionToken.beforeIssue")
	HookSessionTokenAfterIssue  = core.HookPoint("auth.sessionToken.afterIssue")
	HookSessionTokenIssueFailed = core.HookPoint("auth.sessionToken.issueFailed")

	HookTokenBeforeIssue = core.HookPoint("token.beforeIssue")
	HookTokenAfterIssue  = core.HookPoint("token.afterIssue") // Phase: After
	HookTokenConsumed    = core.HookPoint("token.consumed")   // Phase: After
	HookTokenFailed      = core.HookPoint("token.failed")     // Phase: Failed
)

// HookPayloadKey values are the published contract for well-known behemoth.M keys
// carried in hook payloads. Any hook point whose payload conveys one of these
// concepts MUST use the same key here
// This communication is what lets an unrelated plugin's handler read or enrich a value
// (e.g. a geo-IP plugin setting resolved city's IPAddress to the session during
// auth.session.beforeCreate hook call) will need to use the HookValueIPAddress.
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
	// HookValueMethod is how a sign-in or a sign-up is done: the name of
	// the plugin whose flow runs it, such as "emailpassword" or
	// "magiclink". Every sign-in and sign-up flow publishes it in the
	// operation's Values before auth.signIn.before and auth.signUp.before,
	// so a rate-limit rule there can count each method apart.
	HookValueMethod = "method"

	// HookValueFactor is the factor a sign-in checked, one of core's Factor
	// names such as core.FactorPassword, in the payload of
	// auth.signIn.credentialsVerified. A handler reads it; nothing is read
	// back.
	HookValueFactor = "factor"
	// HookValueRequireStepUp is the key a handler on
	// auth.signIn.credentialsVerified sets to true in the payload it returns,
	// to make the new session wait for a second factor.
	HookValueRequireStepUp = "requireStepUp"

	HookValueTokenID      = "tokenID"
	HookValueTokenKind    = "kind"
	HookValueTokenSubject = "subject"
)
