package types

import "github.com/MastewalB/behemoth/models"

// SignInResult is what a sign-in produces and what handlers on
// auth.signIn.after receive, whichever plugin signed the user in: the
// email/password plugin, the magic link plugin. A handler can rely on one
// type and read Method when the way in matters.
type SignInResult struct {
	User    *models.User
	Session *models.Session
	// RawToken is the session token to deliver to the client. Only its hash
	// is stored, so this is the one place it exists.
	RawToken string
	// Method names how the user signed in: the name of the plugin that ran
	// the flow, such as "emailpassword" or "magiclink".
	Method string
}

// AuditSubject implements [AuditSubject]: a sign-in is about its user.
func (r *SignInResult) AuditSubject() (subjectType, subjectID string) {
	if r == nil || r.User == nil {
		return "", ""
	}
	return models.UserTable, r.User.ID
}
