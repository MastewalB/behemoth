package adapters

import (
	"database/sql"
	"errors"
	"strings"

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

// ConstraintKind classifies a constraint violation without knowing the
// driver — for adapters over an application's connection (bun), whose driver
// is the application's choice. It reads the SQLSTATE where the driver exposes
// one (lib/pq, pgx, bun's pgdriver) and otherwise the engines' own codes in
// the message (SQLite, MySQL, SQL Server). SentinelUnknown: not a constraint
// violation it recognizes.
func ConstraintKind(err error) SentinelKind {
	if err == nil {
		return SentinelUnknown
	}
	var state string
	var withState interface{ SQLState() string }
	var withField interface{ Field(byte) string }
	switch {
	case errors.As(err, &withState):
		state = withState.SQLState()
	case errors.As(err, &withField):
		state = withField.Field('C')
	}
	switch state {
	case "23505":
		return SentinelDuplicateKey
	case "23503":
		return SentinelForeignKey
	}

	msg := err.Error()
	for _, m := range []struct {
		substr string
		kind   SentinelKind
	}{
		{"UNIQUE constraint failed", SentinelDuplicateKey},      // SQLite
		{"FOREIGN KEY constraint failed", SentinelForeignKey},   // SQLite
		{"Error 1062", SentinelDuplicateKey},                    // MySQL ER_DUP_ENTRY
		{"Error 1452", SentinelForeignKey},                      // MySQL ER_NO_REFERENCED_ROW_2
		{"Cannot insert duplicate key", SentinelDuplicateKey},   // SQL Server 2601 / 2627
		{"conflicted with the FOREIGN KEY", SentinelForeignKey}, // SQL Server 547
	} {
		if strings.Contains(msg, m.substr) {
			return m.kind
		}
	}
	return SentinelUnknown
}
