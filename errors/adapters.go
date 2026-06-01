package behemotherr

import (
	"fmt"
)

type ErrorType string

var (
	ErrNotFound       = &DomainError{Type: NotFound}
	ErrDuplicateKey   = &DomainError{Type: DuplicateKey}
	ErrValidation     = &DomainError{Type: Validation}
	ErrDatabase       = &DomainError{Type: Database}
	ErrNotImplemented = &DomainError{Type: NotImplemented}

	// Add more: PermissionDenied, ConstraintViolation, etc.
)

const (
	NotFound            ErrorType = "NOT_FOUND"
	DuplicateKey        ErrorType = "DUPLICATE_KEY"
	ForeignKeyViolation ErrorType = "FOREIGN_KEY_VIOLATION"
	Validation          ErrorType = "VALIDATION_ERROR"
	TransactionError    ErrorType = "TRANSACTION_ERROR"
	NotImplemented      ErrorType = "NOT_IMPLEMENTED"
	Internal            ErrorType = "INTERNAL_ERROR"
	Database            ErrorType = "DATABASE_ERROR"
)

type DomainError struct {
	Type     ErrorType
	Message  string
	Op       string
	Entity   string
	Original error
}

func (e *DomainError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s failed", e.Type, e.Op)
}

func (e *DomainError) Unwrap() error {
	return e.Original
}

func NewNotFound(op, entity string, original error) error {
	return &DomainError{
		Type:     NotFound,
		Op:       op,
		Entity:   entity,
		Original: original,
	}
}

func NewDuplicateKey(op, entity string, original error) error {
	return &DomainError{
		Type:     DuplicateKey,
		Op:       op,
		Entity:   entity,
		Original: original,
	}
}

func NewDatabaseError(op string, original error) error {
	return &DomainError{
		Type:     Database,
		Op:       op,
		Original: original,
	}
}

func NewForeignKeyViolation(op, entity string, original error) error {
	return &DomainError{
		Type:     ForeignKeyViolation,
		Op:       op,
		Original: original,
	}
}

func NewTransactionError(op string, original error) error {
	return &DomainError{
		Type:     TransactionError,
		Op:       op,
		Original: original,
	}
}

func NewValidationError(op, entity string, original error) error {
	return &DomainError{
		Type:     Validation,
		Op:       op,
		Entity:   entity,
		Original: original,
	}
}

func NewNotImplemented(msg string) error {
	return &DomainError{
		Type:    NotImplemented,
		Message: msg,
	}
}

func SerializableNotImplemented() error {
	return NewNotImplemented("model does not implement Serializable interface")
}
