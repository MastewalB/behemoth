package behemotherr

// Codes of the errors for a JWT that is refused. They are CategoryToken,
// which a route answers with 401, and share one public message, so that a
// client is not told which check failed. An expired JWT has
// ErrorCodeTokenExpired, the code of every expired token.
const (
	// ErrorCodeJWTMalformed: the input is not a JWT, or a segment can't be
	// decoded.
	ErrorCodeJWTMalformed = "malformed_token"
	// ErrorCodeJWTAlgorithmMismatch: the header names another algorithm than
	// the token's kind is signed with.
	ErrorCodeJWTAlgorithmMismatch = "algorithm_mismatch"
	// ErrorCodeJWTInvalidSignature: the signature does not match the key the
	// header names.
	ErrorCodeJWTInvalidSignature = "invalid_signature"
	// ErrorCodeJWTNotYetValid: nbf is in the future.
	ErrorCodeJWTNotYetValid = "token_not_yet_valid"
	// ErrorCodeJWTIssuerMismatch: iss is not the configured issuer.
	ErrorCodeJWTIssuerMismatch = "issuer_mismatch"
	// ErrorCodeJWTAudienceMismatch: aud does not name the kind's audience.
	ErrorCodeJWTAudienceMismatch = "audience_mismatch"
	// ErrorCodeJWTMissingClaim: a required claim, exp or aud, is absent.
	ErrorCodeJWTMissingClaim = "missing_claim"
	// ErrorCodeJWTInvalidClaims: a registered claim fails a check that has
	// no code of its own.
	ErrorCodeJWTInvalidClaims = "invalid_claims"
	// ErrorCodeJWTUnknownKey: the header names a key the key set does not
	// have.
	ErrorCodeJWTUnknownKey = "unknown_signing_key"
)

// Codes of the errors for a JWT that could not be issued or checked because
// of the system, not the token. They are not CategoryToken.
const (
	// ErrorCodeJWTUnknownKind: the kind is neither internal nor external.
	ErrorCodeJWTUnknownKind = "unknown_jwt_kind"
	// ErrorCodeJWTExternalNotConfigured: an external JWT was asked for, and
	// the provider has no key set.
	ErrorCodeJWTExternalNotConfigured = "external_jwt_not_configured"
	// ErrorCodeJWTEncodingFailed: the claims could not be encoded.
	ErrorCodeJWTEncodingFailed = "claims_marshal_failed"
	// ErrorCodeJWTSigningFailed: the signature could not be made.
	ErrorCodeJWTSigningFailed = "signing_failed"
	// ErrorCodeJWKSNoActiveKey: the key set has no current key to sign with.
	ErrorCodeJWKSNoActiveKey = "no_active_signing_key"
	// ErrorCodeJWKSReadFailed: the key set could not be read.
	ErrorCodeJWKSReadFailed = "error_retrieving_keys"
	// ErrorCodeJWKSKeygenFailed: a new key pair could not be generated.
	ErrorCodeJWKSKeygenFailed = "keygen_failed"
	// ErrorCodeJWKSRotateFailed: a new key could not be stored as the
	// current one.
	ErrorCodeJWKSRotateFailed = "key_update_failed"
)

// NewJWTError returns the error for a JWT that is refused, with one of the
// refusal codes above.
func NewJWTError(op, code string, original error) *DomainError {
	return &DomainError{
		Category:        CategoryToken,
		Op:              op,
		Entity:          "jwt",
		Code:            code,
		PublicMessage:   "invalid or expired token",
		InternalMessage: op + ": " + code,
		Original:        original,
	}
}

// NewConfigurationErrorCode is NewConfigurationError with a code of its own,
// for a misconfiguration a caller tells apart, such as
// ErrorCodeJWTExternalNotConfigured.
func NewConfigurationErrorCode(op, code, detail string) *DomainError {
	e := NewConfigurationError(op, detail, nil)
	e.Code = code
	return e
}
