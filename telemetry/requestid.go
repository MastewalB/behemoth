package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// DefaultRequestIDHeader is the header the router reads the request ID from
// and echoes it in, unless RouterConfig.RequestIDHeader names another.
const DefaultRequestIDHeader = "X-Request-ID"

// maxRequestIDLen bounds an ID taken from a request header.
const maxRequestIDLen = 128

type requestIDKey struct{}

// ContextWithRequestID returns ctx carrying id as the request ID. The router
// sets it once per request. An application whose own middleware already
// assigns request IDs can set it earlier, and the router keeps that value.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request ID on ctx, or "" when the call was not
// made while handling a request (a CLI command, a background job).
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID returns a random 32-character hexadecimal ID.
func NewRequestID() string {
	var b [16]byte
	rand.Read(b[:]) // never fails; see crypto/rand
	return hex.EncodeToString(b[:])
}

// ValidRequestID reports whether id can be used as it arrived in a request
// header: 1 to 128 visible ASCII characters. Anything else (empty, too long,
// spaces, control characters) is replaced by a generated ID, because the
// value is written to logs and audit rows.
func ValidRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}
