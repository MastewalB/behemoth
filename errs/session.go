package errs

const (
	CodeSessionExpired      = "session_expired"
	CodeSessionRevoked      = "session_revoked"
	CodeSessionPending      = "session_pending"
	CodeSessionLimitReached = "session_limit_reached"
	CodeInvalidSessionState = "invalid_state_transition"
	// CodeSessionNotFresh is the code of a request refused because it
	// needs a recent sign-in and the session's is too old
	// (httpapi.RequireFreshSession). The client asks the user to sign in
	// again and retries.
	CodeSessionNotFresh = "session_not_fresh"
	// CodeSessionMissing is the code of a request to a route that needs
	// a session (httpapi.RequireSession) and carries no session token.
	CodeSessionMissing = "session_missing"
	// CodeSessionInvalid is the code of a request to such a route whose
	// token belongs to no session: it was never issued, or its session no
	// longer exists.
	CodeSessionInvalid = "session_invalid"
)

func NewSessionError(op, code string, original error) error {
	return &DomainError{
		Category: CategorySession,
		Op:       op,
		Code:     code,

		PublicMessage:   sessionPublicMessage(code), // generic message for the client
		InternalMessage: code,
		Original:        original,
	}
}

func sessionPublicMessage(code string) string {
	switch code {
	case CodeSessionExpired:
		return "session expired"
	case CodeSessionRevoked:
		return "session has been revoked"
	case CodeSessionPending:
		return "additional verification required"
	case CodeSessionLimitReached:
		return "maximum number of active sessions reached"
	case CodeInvalidSessionState:
		return "invalid session state"
	case CodeSessionNotFresh:
		return "recent sign-in required"
	case CodeSessionMissing:
		return "missing session token"
	case CodeSessionInvalid:
		return "invalid session"
	default:
		return "invalid session"
	}
}
