package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GetJSON GETs rawURL with header and decodes the answer into into. It asks
// for JSON unless header names an Accept of its own. An answer whose status
// is not 2xx is an error, and so is one longer than DefaultMaxBody. It
// returns the status, so that a caller can tell a 404 from a failure.
func GetJSON(ctx context.Context, client *http.Client, rawURL string, header http.Header, into any) (status int, err error) {
	req, err := http.NewRequestWithContext(contextOrBackground(ctx), http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range header {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	status, body, err := Do(client, req, 0)
	if err != nil {
		return status, err
	}
	if status/100 != 2 {
		return status, fmt.Errorf("GET %s answered %d", describe(req), status)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return status, fmt.Errorf("GET %s: %w", describe(req), err)
	}
	return status, nil
}

// PostForm posts form, encoded as application/x-www-form-urlencoded, to
// rawURL with header, and returns the answer's status and body, read up to
// DefaultMaxBody. An answer with any status is returned without an error:
// OAuth 2.0, for one, describes a refusal in the body of a 400.
func PostForm(ctx context.Context, client *http.Client, rawURL string, form url.Values, header http.Header) (status int, body []byte, err error) {
	encoded := form.Encode()
	req, err := http.NewRequestWithContext(contextOrBackground(ctx), http.MethodPost, rawURL, strings.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	for k, v := range header {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return Do(client, req, 0)
}
