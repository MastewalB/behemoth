package types

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// RequestContext is the normalized, framework-agnostic context every plugin
// handler receives. It wraps the standard *http.Request (which every Go
// framework exposes) and a ResponseRecorder that buffers the response until
// the framework adapter flushes it to the real connection.
type RequestContext struct {
	Ctx context.Context

	Request *http.Request

	Response *ResponseRecorder

	Values M
}

// ResponseRecorder buffers status code, headers, and body so the plugin
// handler can write a complete response without ever touching a framework type.
// The framework adapter calls Flush() once the handler returns, copying
// everything onto the real http.ResponseWriter and sending it over the wire.
type ResponseRecorder struct {
	Code    int
	Headers http.Header
	body    *bytes.Buffer

	// Status(code int)
	// Header(key, value string)
	// Cookie(cookie *http.Cookie)

	// JSON(v any) error
	// Text(string) error

	// Redirect(url string, code int) error
}

func NewResponseRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		Code:    http.StatusOK,
		Headers: make(http.Header),
		body:    new(bytes.Buffer),
	}
}

// JSON serialises v, sets Content-Type, and writes into the buffer.
// Nothing is sent over the network until Flush() is called.
func (r *ResponseRecorder) JSON(code int, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Code = code
	r.Headers.Set("Content-Type", "application/json")
	r.body.Write(data)
	return nil
}

// Status sets only the status code (useful for 204 No Content, etc.).
func (r *ResponseRecorder) Status(code int) {
	r.Code = code
}
