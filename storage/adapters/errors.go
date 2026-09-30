package adapters

import (
	"database/sql"
	"errors"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

// SentinelKind is an adapter-level failure kind; Classify turns it into the
// matching behemotherr category. Exported for adapters in their own modules.
type SentinelKind int

const (
	SentinelNotFound SentinelKind = iota
	SentinelDuplicateKey
	SentinelForeignKey
	SentinelConstraintViolation
	SentinelTxDone
	SentinelUndefinedTable
	SentinelUnknown
)

// Classify is the one place "what kind of failure is this" gets decided.
// All adapters should use this function to return classified errors, rather than returning behemotherr directly.
// The main reason for this is to maintain consistency across different adapters
func Classify(op, entity string, sentinel SentinelKind, cause error) error {
	switch sentinel {
	case SentinelNotFound:
		return behemotherr.NewNotFound(op, entity, cause)
	case SentinelDuplicateKey:
		return behemotherr.NewDuplicateKey(op, entity, cause)
	case SentinelForeignKey:
		return behemotherr.NewForeignKeyViolation(op, entity, cause)
	case SentinelTxDone:
		return behemotherr.NewTransactionError(op, cause)
	case SentinelUndefinedTable:
		return behemotherr.NewUndefinedTable(op, entity, cause)
	default:
		return behemotherr.NewDatabaseError(op, cause)
	}
}

// MapStdSQLErrors classifies the errors database/sql itself returns, the same
// for every SQL adapter. ok is false when err needs driver-specific mapping.
func MapStdSQLErrors(op, entity string, err error) (classified error, ok bool) {
	switch {
	case err == nil:
		return nil, true
	case errors.Is(err, sql.ErrNoRows):
		return Classify(op, entity, SentinelNotFound, err), true
	case errors.Is(err, sql.ErrTxDone):
		return Classify(op, entity, SentinelTxDone, err), true
	default:
		return nil, false
	}
}
