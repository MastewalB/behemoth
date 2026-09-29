package behemotherr

const (
	ErrorCodeTokenNotFound        = "token_not_found"
	ErrorCodeTokenExpired         = "token_expired"
	ErrorCodeTokenRevoked         = "token_revoked"
	ErrorCodeTokenAlreadyConsumed = "token_already_consumed"
	ErrorCodeTokenInvalidUsage    = "token_invalid_usage" // Calling Consume() on multi-use credential token
)

func NewTokenError(op, code string, original error) *DomainError {
	return &DomainError{
		Category:      CategoryToken,
		Op:            op,
		Entity:        "token",
		Code:          code,
		PublicMessage: tokenPublicMessage(code),
		Original:      original,
	}
}

// tokenPublicMessage stays deliberately generic across expired/revoked/
// already-consumed/not-found, to avoid attackers distinguishing between non-existing
// and already used tokens
func tokenPublicMessage(code string) string {
	switch code {
	case ErrorCodeTokenExpired, ErrorCodeTokenRevoked, ErrorCodeTokenAlreadyConsumed:
		return "invalid or expired token"
	case ErrorCodeTokenInvalidUsage:
		return "this token cannot be consumed this way"
	default:
		return "invalid or expired token"
	}
}
