package errs

// CodeUntrustedOrigin is the code of the forbidden error (403) for a
// state-changing request that a browser sent from a page behemoth does not
// trust: its Origin header names neither behemoth's own origin nor a
// trusted one, or the browser reports the request as cross-site.
const CodeUntrustedOrigin = "untrusted_origin"

// NewUntrustedOrigin returns the error for a request the origin check
// refused. reason says which case it was, for logs and metrics; it is not
// sent to a client.
func NewUntrustedOrigin(op, reason string) *DomainError {
	return &DomainError{
		Category:        CategoryForbidden,
		Op:              op,
		Code:            CodeUntrustedOrigin,
		PublicMessage:   "request from an untrusted origin",
		InternalMessage: op + ": " + reason,
	}
}

// CodeUnsupportedContentType is the code of the error (415) for a
// state-changing request whose Content-Type is one an HTML form can send:
// text/plain, application/x-www-form-urlencoded or multipart/form-data. The
// client sends its JSON body as application/json.
const CodeUnsupportedContentType = "unsupported_content_type"

// NewUnsupportedContentType returns the error for a request refused for its
// Content-Type. contentType is the refused type, for logs; it is not sent
// to a client.
func NewUnsupportedContentType(op, contentType string) *DomainError {
	return &DomainError{
		Category:        CategoryUnsupportedMedia,
		Op:              op,
		Code:            CodeUnsupportedContentType,
		PublicMessage:   "unsupported content type, send application/json",
		InternalMessage: op + ": " + contentType,
	}
}
