package behemotherr

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Category string

const (
	CategoryValidation     Category = "validation"
	CategoryNotFound       Category = "not_found"
	CategoryUndefinedTable Category = "undefined_table" // the table itself doesn't exist — a schema condition, never "no rows"
	CategoryDuplicateKey   Category = "duplicate_key"
	CategoryForeignKey     Category = "foreign_key_violation"
	CategoryConflict       Category = "conflict"     // optimistic-lock / concurrent-update collisions
	CategoryUnauthorized   Category = "unauthorized" // not authenticated
	CategoryForbidden      Category = "forbidden"    // authenticated, not permitted
	CategoryRateLimited    Category = "rate_limited"
	CategorySession        Category = "session"
	CategoryToken          Category = "token"
	CategoryTransaction    Category = "transaction"
	CategoryDatabase       Category = "database"        // infra failure, connection lost, timeout
	CategoryMigration      Category = "migration"       // migration errors
	CategoryInvalidKey     Category = "invalid_key"     // key is empty, malformed, or otherwise invalid for the operation
	CategoryKeyNotFound    Category = "key_not_found"   // key is valid but not present in the store
	CategoryNotImplemented Category = "not_implemented" // interface not implemented
	CategoryConfiguration  Category = "configuration"   // boot and initialization problems
	CategorySecurity       Category = "security"        // runtime crypto/key failures. unknown version, decode failure, etc.
	CategoryInternal       Category = "internal"        // catch-all, should shrink over time as gaps get classified
)

const (
	ErrorCodeUnknown = "unknown_error"
)

type DomainError struct {
	Category Category
	Op       string
	Entity   string // "user" | "session" | "password" | ...
	Code     string

	// PublicMessage is the message safe to return to the API caller.
	PublicMessage   string
	InternalMessage string
	Original        error
	Retryable       bool // whether the operation that produced this error is worth retrying (e.g. connection timeout)
	RetryAfter      time.Duration
}

func (e *DomainError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return e.PublicMessage
}

func (e *DomainError) Unwrap() error { return e.Original } // preserves errors.Is/As chains through Original

func Is(err error, category Category) bool {
	if de, ok := errors.AsType[*DomainError](err); ok {
		return de.Category == category
	}
	return false
}

func IsCode(err error, code string) bool {
	if de, ok := errors.AsType[*DomainError](err); ok {
		return de.Code == code
	}
	return false
}

func ClassifyCode(err error) string {
	if de, ok := errors.AsType[*DomainError](err); ok {
		return de.Code
	}
	return ErrorCodeUnknown
}

func NewRateLimited(op, ruleName string, retryAfter time.Duration) *DomainError {
	return &DomainError{
		Category:        CategoryRateLimited,
		Op:              op,
		Entity:          "rate_limit",
		Code:            "rate_limited",
		PublicMessage:   "too many requests, please try again later",
		InternalMessage: fmt.Sprintf("rule %q exceeded", ruleName),
		Retryable:       true,
		RetryAfter:      retryAfter,
	}
}

// NewUnauthorized reports that the caller could not be authenticated: wrong
// credentials at sign-in, for example. message is sent to the client, so it
// should not say which part was wrong. It maps to 401. A request that is
// authenticated but not allowed is CategoryForbidden instead.
func NewUnauthorized(op, code, message string) error {
	return &DomainError{
		Category:        CategoryUnauthorized,
		Op:              op,
		Code:            code,
		PublicMessage:   message,
		InternalMessage: fmt.Sprintf("%s: %s", op, message),
	}
}

// NewInternalError classifies an unexpected failure inside the system
func NewInternalError(op string, original error) *DomainError {
	return &DomainError{
		Category:        CategoryInternal,
		Op:              op,
		Code:            "internal_error",
		PublicMessage:   "an internal error occurred",
		InternalMessage: fmt.Sprintf("%s: %v", op, original),
		Original:        original,
	}
}

func NewMigrationError(op, code string, original error) *DomainError {
	return &DomainError{
		Category: CategoryMigration, Op: op, Code: code,
		PublicMessage:   "migration failed", // never client-facing anyway — this surfaces to an operator/CLI, not an HTTP response
		InternalMessage: fmt.Sprintf("%s: %v", op, original),
		Original:        original,
	}
}

var categoryToStatus = map[Category]int{
	CategoryValidation:     http.StatusBadRequest,
	CategoryNotFound:       http.StatusNotFound,
	CategoryDuplicateKey:   http.StatusConflict,
	CategoryForeignKey:     http.StatusConflict,
	CategoryConflict:       http.StatusConflict,
	CategoryUnauthorized:   http.StatusUnauthorized,
	CategoryForbidden:      http.StatusForbidden,
	CategoryRateLimited:    http.StatusTooManyRequests,
	CategorySession:        http.StatusUnauthorized,
	CategoryToken:          http.StatusUnauthorized,
	CategoryTransaction:    http.StatusInternalServerError,
	CategoryDatabase:       http.StatusInternalServerError,
	CategoryUndefinedTable: http.StatusInternalServerError,
}
