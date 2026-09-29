package adapters

import behemotherr "github.com/MastewalB/behemoth/errors"

type sentinelKind int

const (
	sentinelNotFound sentinelKind = iota
	sentinelDuplicateKey
	sentinelForeignKey
	sentinelConstraintViolation
	sentinelTxDone
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
	default:
		return behemotherr.NewDatabaseError(op, cause)
	}
}
