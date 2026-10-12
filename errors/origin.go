package behemotherr

// ErrorCodeUntrustedOrigin is the code of the forbidden error (403) for a
// state-changing request that a browser sent from a page behemoth does not
// trust: its Origin header names neither behemoth's own origin nor a
// trusted one, or the browser reports the request as cross-site.
const ErrorCodeUntrustedOrigin = "untrusted_origin"

// NewUntrustedOrigin returns the error for a request the origin check
// refused. reason says which case it was, for logs and metrics; it is not
// sent to a client.
func NewUntrustedOrigin(op, reason string) *DomainError {
	return &DomainError{
		Category:        CategoryForbidden,
		Op:              op,
		Code:            ErrorCodeUntrustedOrigin,
		PublicMessage:   "request from an untrusted origin",
		InternalMessage: op + ": " + reason,
	}
}
