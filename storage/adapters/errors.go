package adapters

import (
	"database/sql"
	"errors"

	behemotherr "github.com/MastewalB/behemoth/errors"
)

type sentinelKind int

const (
	sentinelNotFound sentinelKind = iota
	sentinelDuplicateKey
	sentinelForeignKey
	sentinelConstraintViolation
	sentinelTxDone
	sentinelUndefinedTable
	sentinelUnknown
)

// classify is the one place "what kind of failure is this" gets decided.
// All adapters should use this function to return classified errors, rather than returning behemotherr directly.
// The main reason for this is to maintain consistency across different adapters
func classify(op, entity string, sentinel sentinelKind, cause error) error {
	switch sentinel {
	case sentinelNotFound:
		return behemotherr.NewNotFound(op, entity, cause)
	case sentinelDuplicateKey:
		return behemotherr.NewDuplicateKey(op, entity, cause)
	case sentinelForeignKey:
		return behemotherr.NewForeignKeyViolation(op, entity, cause)
	case sentinelTxDone:
		return behemotherr.NewTransactionError(op, cause)
	case sentinelUndefinedTable:
		return behemotherr.NewUndefinedTable(op, entity, cause)
	default:
		return behemotherr.NewDatabaseError(op, cause)
	}
}

// mapStdSQLErrors classifies the errors database/sql itself returns, the same
// for every SQL adapter. ok is false when err needs driver-specific mapping.
func mapStdSQLErrors(op, entity string, err error) (classified error, ok bool) {
	switch {
	case err == nil:
		return nil, true
	case errors.Is(err, sql.ErrNoRows):
		return classify(op, entity, sentinelNotFound, err), true
	case errors.Is(err, sql.ErrTxDone):
		return classify(op, entity, sentinelTxDone, err), true
	default:
		return nil, false
	}
}
