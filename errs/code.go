package errs

// CodeCodeInvalid is the code of the error for a one-time code that is
// not accepted: there is none, it expired, the guess was wrong, or it has no
// attempts left. The four share one code and one message, so the answer does
// not tell a caller which it was.
const CodeCodeInvalid = "code_invalid"

// NewCodeError returns the error for a one-time code that is not accepted.
// reason says which of the four cases it was, for logs and audit events; it
// is not sent to a client.
func NewCodeError(op, reason string) *DomainError {
	return &DomainError{
		Category:        CategoryToken,
		Op:              op,
		Entity:          "code",
		Code:            CodeCodeInvalid,
		PublicMessage:   "invalid or expired code",
		InternalMessage: op + ": " + reason,
	}
}

// IsCodeRejection reports whether err says a one-time code was not accepted,
// as opposed to a failure of the system.
func IsCodeRejection(err error) bool { return IsCode(err, CodeCodeInvalid) }
