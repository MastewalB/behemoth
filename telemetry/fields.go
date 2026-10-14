package telemetry

import (
	"errors"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
)

// Field keys shared by every component's log lines. Call sites use these
// instead of string literals, so a key means the same thing in every line
// and in every backend. They are part of behemoth's public contract:
// dashboards and alerts are built on them.
const (
	FieldComponent = "component" // the behemoth component writing the line; set by Named
	FieldOp        = "op"        // the operation, in the form DomainError.Op uses
	FieldRequestID = "request_id"
	FieldTraceID   = "trace_id" // added by a tracing-aware backend
	FieldSpanID    = "span_id"  // added by a tracing-aware backend
	FieldUserID    = "user_id"
	FieldSessionID = "session_id"
	FieldPlugin    = "plugin"
	FieldPoint     = "point" // a hook point

	FieldMethod    = "method"    // HTTP method
	FieldRoute     = "route"     // a route's pattern ("/users/{id}"), never the request path
	FieldStatus    = "status"    // HTTP status code
	FieldStatement = "statement" // SQL text, with placeholders in place of values

	FieldError         = "error"          // the error's text
	FieldErrorCode     = "error_code"     // DomainError.Code, or "unknown_error"
	FieldErrorCategory = "error_category" // DomainError.Category
)

// ErrorFields returns the log fields that describe err, in a new map the
// caller may add to. It is how an error from the error taxonomy reaches a
// log line: a *DomainError anywhere in err's chain gives FieldErrorCode,
// FieldErrorCategory and FieldOp, and FieldError is its internal message.
// Any other error gives FieldError and the code "unknown_error". A nil err
// gives an empty map.
//
// The fields of extra are copied into the result, for a line that says more
// than the error does:
//
//	log.Warn(ctx, "rate limit store unavailable", telemetry.ErrorFields(err, behemoth.M{"rule": rule}))
//
// A key the error sets wins over the same key in extra.
func ErrorFields(err error, extra ...behemoth.M) behemoth.M {
	fields := behemoth.M{}
	for _, m := range extra {
		for k, v := range m {
			fields[k] = v
		}
	}
	if err == nil {
		return fields
	}
	fields[FieldError] = err.Error()
	fields[FieldErrorCode] = behemotherr.ErrorCodeUnknown
	if de, ok := errors.AsType[*behemotherr.DomainError](err); ok {
		if de.Code != "" {
			fields[FieldErrorCode] = de.Code
		}
		fields[FieldErrorCategory] = string(de.Category)
		if de.Op != "" {
			fields[FieldOp] = de.Op
		}
	}
	return fields
}
