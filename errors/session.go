package behemotherr

import (
	"errors"
	"net/http"

	"github.com/MastewalB/behemoth"
)

const (
	ErrorCodeSessionExpired      = "session_expired"
	ErrorCodeSessionRevoked      = "session_revoked"
	ErrorCodeSessionPending      = "session_pending"
	ErrorCodeSessionLimitReached = "session_limit_reached"
	ErrorCodeInvalidSessionState = "invalid_state_transition"
	// ErrorCodeSessionNotFresh is the code of a request refused because it
	// needs a recent sign-in and the session's is too old
	// (types.RequireFreshSession). The client asks the user to sign in
	// again and retries.
	ErrorCodeSessionNotFresh = "session_not_fresh"
	// ErrorCodeSessionMissing is the code of a request to a route that needs
	// a session (types.RequireSession) and carries no session token.
	ErrorCodeSessionMissing = "session_missing"
	// ErrorCodeSessionInvalid is the code of a request to such a route whose
	// token belongs to no session: it was never issued, or its session no
	// longer exists.
	ErrorCodeSessionInvalid = "session_invalid"
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
	case ErrorCodeSessionExpired:
		return "session expired"
	case ErrorCodeSessionRevoked:
		return "session has been revoked"
	case ErrorCodeSessionPending:
		return "additional verification required"
	case ErrorCodeSessionLimitReached:
		return "maximum number of active sessions reached"
	case ErrorCodeInvalidSessionState:
		return "invalid session state"
	case ErrorCodeSessionNotFresh:
		return "recent sign-in required"
	case ErrorCodeSessionMissing:
		return "missing session token"
	case ErrorCodeSessionInvalid:
		return "invalid session"
	default:
		return "invalid session"
	}
}

type DefaultErrorMapper struct{}

func (dem *DefaultErrorMapper) Map(err error) (status int, body behemoth.M) {
	var de *DomainError
	var ok bool

	if de, ok = errors.AsType[*DomainError](err); !ok {
		return http.StatusInternalServerError, behemoth.M{"error": "internal server error"}
	}
	status, ok = categoryToStatus[de.Category]
	if !ok {
		// Errors like CategoryConfiguration and CategoryInternal deliberately have no entry; they should never reach a client looking like a normal response
		return http.StatusInternalServerError, behemoth.M{"error": "internal server error"}
	}
	return status, behemoth.M{"error": de.PublicMessage, "code": de.Code}

	// switch {
	// case IsCode(err, ErrorCodeSessionExpired), IsCode(err, ErrorCodeSessionRevoked):
	// 	return http.StatusUnauthorized, behemoth.M{"error": err.Error()}
	// case IsCode(err, ErrorCodeSessionPending):
	// 	return http.StatusOK, behemoth.M{"status": "requires_second_factor"} // not an error state to the client
	// case IsNotFound(err):
	// 	return http.StatusNotFound, behemoth.M{"error": err.Error()}
	// case IsValidationError(err):
	// 	return http.StatusBadRequest, behemoth.M{"error": err.Error()}
	// case IsDuplicateKey(err):
	// 	return http.StatusConflict, behemoth.M{"error": err.Error()}
	// default:
	// 	return http.StatusInternalServerError, behemoth.M{"error": "internal server error"} // never leak raw err.Error() for unclassified errors
	// }
}
