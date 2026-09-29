package behemotherr

import (
	"errors"
	"fmt"
)

// type ErrorType string

func NewNotFound(op, entity string, original error) error {
	return &DomainError{
		Category:        CategoryNotFound,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_not_found",
		PublicMessage:   entity + " not found",
		InternalMessage: fmt.Sprintf("%s: %s not found", op, entity),
		Original:        original,
	}
}

func NewDuplicateKey(op, entity string, original error) error {
	return &DomainError{
		Category:        CategoryDuplicateKey,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_already_exists",
		PublicMessage:   entity + " already exists",
		InternalMessage: fmt.Sprintf("%s: %s already exists", op, entity),
		Original:        original,
	}
}

func NewDatabaseError(op string, original error) error {
	return &DomainError{
		Category: CategoryDatabase, Op: op,
		Code:            "database_error",
		PublicMessage:   "an internal error occurred", // generic message for the client
		InternalMessage: original.Error(),
		Original:        original,
		Retryable:       true, // connection/timeout failures are usually worth retrying
	}
}

func NewForeignKeyViolation(op, entity string, original error) error {
	return &DomainError{
		Category:        CategoryForeignKey,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_foreign_key_violation",
		PublicMessage:   entity + " foreign key violation",
		InternalMessage: fmt.Sprintf("%s: %s foreign key violation", op, entity),
		Original:        original,
	}
}

func NewTransactionError(op string, original error) error {
	return &DomainError{
		Category:        CategoryTransaction,
		Code:            "transaction_error",
		PublicMessage:   "transaction error",
		InternalMessage: fmt.Sprintf("%s: transaction error", op),
		Op:              op,
		Original:        original,
	}
}

func NewValidationError(op, entity string, original error) error {
	return &DomainError{
		Category:        CategoryValidation,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_validation_error",
		PublicMessage:   entity + " validation error",
		InternalMessage: fmt.Sprintf("%s: %s validation error", op, entity),
		Original:        original,
	}
}

func NewInvalidInputError(op, entity, message string, original error) error {
	return &DomainError{
		Category:        CategoryValidation,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_invalid_input",
		PublicMessage:   message,
		InternalMessage: fmt.Sprintf("%s: %s", op, message),
		Original:        original,
	}
}

func NewEmptyKey(op string, original error) error {
	return &DomainError{
		Category: CategoryInvalidKey,
		Op:       op,
		Original: original,
	}
}

func NewKeyNotFound(op string, original error) error {
	return &DomainError{
		Category: CategoryKeyNotFound,
		Op:       op,
		Original: original,
	}
}

func NewNotImplemented(msg string) error {
	return &DomainError{
		Category:        CategoryNotImplemented,
		Code:            "not_implemented",
		PublicMessage:   "an internal error occurred", // generic message for the client
		InternalMessage: msg,
	}
}

func NewConfigurationError(op, detail string, original error) *DomainError {
	return &DomainError{
		Category: CategoryConfiguration, Op: op,
		Code:            "configuration_error",
		PublicMessage:   "service misconfigured",
		InternalMessage: fmt.Sprintf("%s: %s", op, detail),
		Original:        original,
	}
}

func NewSecurityError(op, code string, original error) *DomainError {
	return &DomainError{
		Category: CategorySecurity, Op: op,
		Code:            code,
		PublicMessage:   "invalid or expired credential", // generic message for the client
		InternalMessage: original.Error(),
		Original:        original,
		Retryable:       false, // a missing key version won't fix itself by retrying the same request
	}
}

func SerializableNotImplemented() error {
	return NewNotImplemented("model does not implement Serializable interface")
}

func IsNotFound(err error) bool { return Is(err, CategoryNotFound) }

func IsDuplicateKey(err error) bool { return Is(err, CategoryDuplicateKey) }

func IsValidationError(err error) bool { return Is(err, CategoryValidation) }

func IsRetryable(err error) bool {
	var de *DomainError
	return errors.As(err, &de) && de.Retryable
}

// WrapOp re-contextualizes an already-classified low level *DomainError at a higher
// call boundary: e.g. an adapter's generic "Count"/"sessions" becoming
// "SessionManager.Create"/"session" without losing Category, Original error, or
// Retryable flag, since the ErrorMapper and IsRetryable() checks depend on those
// surviving unchanged regardless of how many layers an error passes through.
//
// PublicMessage handling is deliberately asymmetric by category:
//   - Database / Transaction: PublicMessage is already generic and safe
//     ("an internal error occurred") and kept as-is. Rewriting Op/InternalMessage
//     only improves what a log sees.
//   - NotFound: PublicMessage is regenerated against the caller's entity name,
//     since the raw one ("sessions not found", from the adapter's
//     SchemaName()) is both an internal-detail leak and worse UX than
//     "session not found" from the manager that actually knows the concept.
//   - Everything else (validation, duplicate key, etc.) passes through
//     unchanged; already meaningful at the point it was raised.
func WrapOp(op, entity string, err error) error {
	if err == nil {
		return nil
	}
	var de *DomainError
	if !errors.As(err, &de) {
		return NewDatabaseError(op, err) // defensive; should never happen if handled in adapters correctly
	}
	switch de.Category {
	case CategoryDatabase, CategoryTransaction:
		return &DomainError{
			Category:        de.Category,
			Op:              op,
			Entity:          entity,
			Code:            de.Code,
			PublicMessage:   de.PublicMessage,
			InternalMessage: fmt.Sprintf("%s: %s", op, de.InternalMessage),
			Original:        de, // preserve error chain; errors.Is/As still reaches through Unwrap()
			Retryable:       de.Retryable,
		}
	case CategoryNotFound:
		return NewNotFound(op, entity, de)
	default:
		return de
	}
}
