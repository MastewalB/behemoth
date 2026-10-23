package outbound_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-behemoth/behemoth/outbound"
	"github.com/go-behemoth/behemoth/telemetry"
	"github.com/go-behemoth/behemoth/telemetry/telemetrytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// server answers each path with a handler, and keeps what it received.
type server struct {
	*httptest.Server
	mu       sync.Mutex
	received []*http.Request
	bodies   []string
}

func newServer(t *testing.T, routes map[string]http.HandlerFunc) *server {
	t.Helper()
	s := &server{}
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.received = append(s.received, r.Clone(context.Background()))
			s.bodies = append(s.bodies, string(body))
			s.mu.Unlock()
			h(w, r)
		})
	}
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *server) last(t *testing.T) (*http.Request, string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.received, "the server received nothing")
	return s.received[len(s.received)-1], s.bodies[len(s.bodies)-1]
}

func (s *server) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.received {
		if r.URL.Path == path {
			n++
		}
	}
	return n
}

func json(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

// The defaults: a timeout, a user agent on a request that has none, and no
// redirect followed, so a credential reaches the URL it was sent to only.
func TestClientDefaults(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{
		"/moved": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		},
		"/elsewhere": json(`{}`),
		"/ok":        json(`{}`),
	})
	client := outbound.NewClient(outbound.Options{}, nil)
	assert.Equal(t, outbound.DefaultTimeout, client.Timeout)

	resp, err := client.Post(srv.URL+"/moved", "application/x-www-form-urlencoded", strings.NewReader("client_secret=s3cret"))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode, "the redirect is the answer")
	assert.Zero(t, srv.count("/elsewhere"), "the secret did not follow the redirect")

	_, err = outbound.GetJSON(context.Background(), client, srv.URL+"/ok", nil, &map[string]any{})
	require.NoError(t, err)
	got, _ := srv.last(t)
	assert.Equal(t, outbound.DefaultUserAgent, got.Header.Get("User-Agent"))
	assert.Equal(t, "application/json", got.Header.Get("Accept"))

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/ok", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "my-service/1.0")
	_, _, err = outbound.Do(client, req, 0)
	require.NoError(t, err)
	got, _ = srv.last(t)
	assert.Equal(t, "my-service/1.0", got.Header.Get("User-Agent"), "a user agent of the caller's own is kept")
	assert.Empty(t, req.Header.Get("Accept"), "the caller's request is not changed")
}

// Options change the defaults, and a negative timeout is refused.
func TestClientOptions(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{
		"/moved":     func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
		"/elsewhere": json(`{"followed":true}`),
		"/slow": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		},
	})

	var through []string
	client := outbound.NewClient(outbound.Options{
		FollowRedirects: true, UserAgent: "shop-auth", Timeout: 100 * time.Millisecond,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			through = append(through, req.URL.Path)
			return http.DefaultTransport.RoundTrip(req)
		}),
	}, nil)
	var answer map[string]any
	_, err := outbound.GetJSON(context.Background(), client, srv.URL+"/moved", nil, &answer)
	require.NoError(t, err)
	assert.Equal(t, true, answer["followed"], "redirects are followed when asked for")
	assert.Equal(t, []string{"/moved", "/elsewhere"}, through, "the requests go through the given transport")
	got, _ := srv.last(t)
	assert.Equal(t, "shop-auth", got.Header.Get("User-Agent"))

	start := time.Now()
	_, err = outbound.GetJSON(context.Background(), client, srv.URL+"/slow", nil, &answer)
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second, "the timeout ends the call")

	assert.Error(t, outbound.Options{Timeout: -time.Second}.Validate())
	assert.NoError(t, outbound.Options{}.Validate())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// An answer is read up to the limit, and one longer than it is refused.
func TestReadLimited(t *testing.T) {
	exact, err := outbound.ReadLimited(strings.NewReader("12345"), 5)
	require.NoError(t, err)
	assert.Equal(t, "12345", string(exact))

	_, err = outbound.ReadLimited(strings.NewReader("123456"), 5)
	assert.ErrorIs(t, err, outbound.ErrTooLarge)

	_, err = outbound.ReadLimited(strings.NewReader(strings.Repeat("a", int(outbound.DefaultMaxBody)+1)), 0)
	assert.ErrorIs(t, err, outbound.ErrTooLarge, "no limit given: DefaultMaxBody")
}

// GetJSON decodes a 2xx answer and refuses the rest. Its errors name the
// URL without its query, which may hold a secret.
func TestGetJSON(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{
		"/ok":       json(`{"issuer":"https://id.example.com"}`),
		"/missing":  func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusNotFound) },
		"/garbled":  json(`{"issuer":`),
		"/enormous": json(`{"keys":"` + strings.Repeat("a", int(outbound.DefaultMaxBody)) + `"}`),
	})
	client := outbound.NewClient(outbound.Options{}, nil)
	ctx := context.Background()

	var doc struct {
		Issuer string `json:"issuer"`
	}
	status, err := outbound.GetJSON(ctx, client, srv.URL+"/ok", http.Header{"authorization": {"Bearer at-1"}}, &doc)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "https://id.example.com", doc.Issuer)
	got, _ := srv.last(t)
	assert.Equal(t, "Bearer at-1", got.Header.Get("Authorization"), "the caller's headers are sent")

	status, err = outbound.GetJSON(ctx, client, srv.URL+"/missing?access_token=s3cret", nil, &doc)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, status, "the status tells a 404 from a failure")
	assert.NotContains(t, err.Error(), "s3cret", "the query is not in the error")
	assert.Contains(t, err.Error(), "/missing")

	_, err = outbound.GetJSON(ctx, client, srv.URL+"/garbled", nil, &doc)
	assert.Error(t, err)
	_, err = outbound.GetJSON(ctx, client, srv.URL+"/enormous", nil, &doc)
	assert.ErrorIs(t, err, outbound.ErrTooLarge)

	_, err = outbound.GetJSON(ctx, client, "http://127.0.0.1:1/unreachable", nil, &doc)
	assert.Error(t, err)
}

// PostForm sends a form and returns any status with its body, for the
// caller to read: OAuth 2.0 describes a refusal in the body of a 400.
func TestPostForm(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{
		"/token": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		},
	})
	status, body, err := outbound.PostForm(context.Background(), outbound.NewClient(outbound.Options{}, nil), srv.URL+"/token",
		url.Values{"grant_type": {"authorization_code"}, "code": {"c 1"}}, http.Header{"Accept": {"application/json"}})
	require.NoError(t, err, "a 400 is an answer, not a failure")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.JSONEq(t, `{"error":"invalid_grant"}`, string(body))

	got, sent := srv.last(t)
	assert.Equal(t, "application/x-www-form-urlencoded", got.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", got.Header.Get("Accept"))
	form, err := url.ParseQuery(sent)
	require.NoError(t, err)
	assert.Equal(t, "c 1", form.Get("code"))
}

// Every call is a span with the method, the host and the status, which
// ends when the body is closed. A call that fails marks it failed.
func TestClientSpans(t *testing.T) {
	srv := newServer(t, map[string]http.HandlerFunc{"/ok": json(`{}`)})
	tel, rec := telemetrytest.New()
	client := outbound.NewClient(outbound.Options{}, tel)

	_, err := outbound.GetJSON(context.Background(), client, srv.URL+"/ok?secret=1", nil, &map[string]any{})
	require.NoError(t, err)
	spans := rec.Tracer.Named(telemetry.SpanOutboundRequest)
	require.Len(t, spans, 1)
	host := strings.TrimPrefix(srv.URL, "http://")
	assert.Equal(t, http.MethodGet, spans[0].Attrs()[telemetry.AttrMethod])
	assert.Equal(t, host, spans[0].Attrs()[telemetry.AttrHost])
	assert.Equal(t, http.StatusOK, spans[0].Attrs()[telemetry.AttrStatus])
	assert.Equal(t, 1, spans[0].Ended(), "the span ended once, with the body")
	for k, v := range spans[0].Attrs() {
		if s, ok := v.(string); ok {
			assert.NotContains(t, s, "secret", "no URL with its query in the span (%s)", k)
		}
	}

	_, err = outbound.GetJSON(context.Background(), client, "http://127.0.0.1:1/unreachable", nil, &map[string]any{})
	require.Error(t, err)
	spans = rec.Tracer.Named(telemetry.SpanOutboundRequest)
	require.Len(t, spans, 2)
	assert.Error(t, spans[1].Err(), "a call that fails marks its span")
	assert.Equal(t, 1, spans[1].Ended())

	// Without telemetry, calls work the same.
	_, err = outbound.GetJSON(context.Background(), outbound.NewClient(outbound.Options{}, nil), srv.URL+"/ok", nil, &map[string]any{})
	assert.NoError(t, err)
}
