package errs

import (
	"errors"
	"fmt"
	"strings"
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

// NewUndefinedTable classifies a query against a table that doesn't exist.
// Deliberately distinct from NotFound: callers treating NotFound as "no such
// row" must not mistake a missing (e.g. not-yet-migrated) table for an empty
// one. Only a caller that knows a missing table is a legitimate state — like
// the migration runner reading its own bookkeeping tables before the first
// migration — should handle it.
func NewUndefinedTable(op, entity string, original error) error {
	return &DomainError{
		Category:        CategoryUndefinedTable,
		Op:              op,
		Entity:          entity,
		Code:            "undefined_table",
		PublicMessage:   "an internal error occurred", // a schema problem, never client-facing detail
		InternalMessage: fmt.Sprintf("%s: table for %s does not exist", op, entity),
		Original:        original,
	}
}

// NewDuplicateKey is the error of a write that broke a unique key of
// entity, when the adapter can't tell which one. NewDuplicateKeyOn names it.
func NewDuplicateKey(op, entity string, original error) error {
	return NewDuplicateKeyOn(op, entity, nil, original)
}

// NewDuplicateKeyOn is the error of a write that broke the unique key of
// entity made of columns (canonical names). The store turns one on a column
// declared unique into a conflict with the column's code; see
// [DuplicateKeyColumns].
func NewDuplicateKeyOn(op, entity string, columns []string, original error) error {
	internal := fmt.Sprintf("%s: %s already exists", op, entity)
	if len(columns) > 0 {
		internal = fmt.Sprintf("%s: %s already exists (unique key %s)", op, entity, strings.Join(columns, ", "))
	}
	return &DomainError{
		Category:        CategoryDuplicateKey,
		Op:              op,
		Entity:          entity,
		Code:            entity + "_already_exists",
		PublicMessage:   entity + " already exists",
		InternalMessage: internal,
		Original:        original,
		Columns:         columns,
	}
}

// NewTaken is the conflict (409) of a write whose value of column, a column
// of entity declared unique, another row holds. code is the column's
// (behemoth.UniqueKey.TakenCode), such as "username_taken". duplicate, the
// adapter's duplicate key error, stays in the chain, so [IsDuplicateKey]
// still holds. The store returns it whichever flow wrote the row.
func NewTaken(op, entity, column, code string, duplicate error) *DomainError {
	return &DomainError{
		Category:        CategoryConflict,
		Op:              op,
		Entity:          entity,
		Code:            code,
		PublicMessage:   strings.ReplaceAll(column, "_", " ") + " is already taken",
		InternalMessage: fmt.Sprintf("%s: %s.%s is already taken", op, entity, column),
		Original:        duplicate,
	}
}

// DuplicateKeyColumns returns the columns of the unique key a duplicate key
// error in err's chain names, or nil when it names none or there is no such
// error.
func DuplicateKeyColumns(err error) []string {
	if de := duplicateKey(err); de != nil {
		return de.Columns
	}
	return nil
}

// duplicateKey returns the first duplicate key error in err's chain. It looks
// past other DomainErrors, because the store wraps the duplicate key of a
// unique column in the column's conflict.
func duplicateKey(err error) *DomainError {
	for err != nil {
		if de, ok := err.(*DomainError); ok && de.Category == CategoryDuplicateKey {
			return de
		}
		switch e := err.(type) {
		case interface{ Unwrap() error }:
			err = e.Unwrap()
		case interface{ Unwrap() []error }:
			for _, inner := range e.Unwrap() {
				if de := duplicateKey(inner); de != nil {
					return de
				}
			}
			return nil
		default:
			return nil
		}
	}
	return nil
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

// NewSecurityError's original is optional: without one, the internal message
// is op and code.
func NewSecurityError(op, code string, original error) *DomainError {
	internal := fmt.Sprintf("%s: %s", op, code)
	if original != nil {
		internal = original.Error()
	}
	return &DomainError{
		Category: CategorySecurity, Op: op,
		Code:            code,
		PublicMessage:   "invalid or expired credential", // generic message for the client
		InternalMessage: internal,
		Original:        original,
		Retryable:       false, // a missing key version won't fix itself by retrying the same request
	}
}

func SerializableNotImplemented() error {
	return NewNotImplemented("model does not implement Serializable interface")
}

func IsNotFound(err error) bool { return IsCategory(err, CategoryNotFound) }

func IsUndefinedTable(err error) bool { return IsCategory(err, CategoryUndefinedTable) }

// IsDuplicateKey reports whether a write broke a unique key: err is a
// duplicate key error, or holds one, as the conflict the store returns for a
// column declared unique does.
func IsDuplicateKey(err error) bool { return duplicateKey(err) != nil }

func IsValidationError(err error) bool { return IsCategory(err, CategoryValidation) }

func IsRetryable(err error) bool {
	var de *DomainError
	return errors.As(err, &de) && de.Retryable
}

// WrapOp re-contextualizes an already-classified low level *DomainError at a higher
// call boundary: e.g. an adapter's generic "Count"/"sessions" becoming
// "SessionManager.Create"/"session" without losing Category, Original error, or
// Retryable flag, since the httpapi.ErrorMapper and IsRetryable() checks depend on those
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
