// Package outbound is how behemoth calls other services over HTTP. Every
// outbound call goes through a client NewClient builds, so that each gets
// the same defaults: a timeout, no redirects, a user agent, and a span. The
// helpers read an answer up to a limit.
//
// Boot builds one client from BootConfig.Outbound and puts it on the
// AuthContext as HTTPClient, and plugins call other services with it. The
// client is a plain *http.Client, so anything that takes one, such as a
// cloud SDK, works with it.
//
// It does not abstract over protocols. A call over another protocol, such
// as gRPC, belongs in a package or a module of its own.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/telemetry"
)

// Defaults of a client and of the helpers.
const (
	// DefaultTimeout bounds one call when Options.Timeout is zero, from
	// sending the request to reading the end of the answer.
	DefaultTimeout = 10 * time.Second
	// DefaultUserAgent is sent with a request that has no User-Agent of its
	// own when Options.UserAgent is empty. Some APIs, GitHub's among them,
	// refuse a request without one.
	DefaultUserAgent = "behemoth"
	// DefaultMaxBody is what the helpers read of an answer when they are
	// given no limit: 1 MiB, which a discovery document, a key set or a
	// token response stays far below.
	DefaultMaxBody int64 = 1 << 20
)

// ErrTooLarge is the error of a helper for an answer longer than its limit.
// The answer is not used: a hostile or broken service can't make behemoth
// read without end.
var ErrTooLarge = errors.New("outbound: the answer is longer than the limit")

// Options configures a client. The zero value gives the defaults.
type Options struct {
	// Timeout bounds one call, the answer's body included. Zero means
	// DefaultTimeout.
	Timeout time.Duration

	// FollowRedirects lets the client follow a redirect. False, the
	// default, returns the redirect as the answer: a request that carries a
	// credential, such as a client secret, reaches the URL it names and no
	// other.
	FollowRedirects bool

	// UserAgent is sent with every request that has none. Empty means
	// DefaultUserAgent.
	UserAgent string

	// Transport carries the requests, for an outbound proxy, a CA bundle of
	// the application's own, or a test server. Nil means a copy of
	// http.DefaultTransport, which takes the proxy from the environment
	// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY) and trusts the system's CAs, as
	// Go's own client does.
	Transport http.RoundTripper

	// Not built: an address guard that refuses private, loopback, and
	// link-local addresses, for URLs that come from a configuration file;
	// and a proxy URL and a CA bundle as plain values next to Transport.
}

// Validate reports an option that can't work: a negative timeout.
func (o Options) Validate() error {
	if o.Timeout < 0 {
		return fmt.Errorf("outbound.Options.Timeout is negative: %s", o.Timeout)
	}
	return nil
}

// NewClient returns a client with opts applied. Every call it makes is a
// span on tel (telemetry.SpanOutboundRequest), with the method, the host
// and the status; a nil tel records none. It never retries a request: a
// caller whose calls may be repeated writes the retry for its own calls. An
// authorization code, for one, works once.
func NewClient(opts Options, tel *telemetry.Telemetry) *http.Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	base := opts.Transport
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &roundTripper{base: base, userAgent: opts.UserAgent, tel: tel},
	}
	if !opts.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return client
}

// roundTripper adds the user agent and the span to every request.
type roundTripper struct {
	base      http.RoundTripper
	userAgent string
	tel       *telemetry.Telemetry
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, span := rt.tel.StartSpan(req.Context(), telemetry.SpanOutboundRequest, behemoth.M{
		telemetry.AttrMethod: req.Method,
		telemetry.AttrHost:   req.URL.Host,
	})
	// A RoundTripper must not change the request it was given.
	out := req.Clone(ctx)
	if out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", rt.userAgent)
	}
	resp, err := rt.base.RoundTrip(out)
	if err != nil {
		telemetry.FinishSpan(span, err)
		return nil, err
	}
	span.SetAttributes(behemoth.M{telemetry.AttrStatus: resp.StatusCode})
	// The span covers the body too: it ends when the caller closes it.
	resp.Body = &spanBody{ReadCloser: resp.Body, span: span}
	return resp, nil
}

type spanBody struct {
	io.ReadCloser
	span telemetry.Span
	once sync.Once
}

func (b *spanBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.span.End() })
	return err
}

// ReadLimited reads r to its end, and returns ErrTooLarge when it holds more
// than limit bytes. A limit of zero or less means DefaultMaxBody.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrTooLarge
	}
	return body, nil
}

// Do sends req with client and returns the answer's status and its body,
// read up to limit (zero means DefaultMaxBody). An answer with any status
// is returned without an error: the caller decides what a status means.
// The body is closed.
func Do(client *http.Client, req *http.Request, limit int64) (status int, body []byte, err error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", req.Method, describe(req), err)
	}
	defer resp.Body.Close()
	body, err = ReadLimited(resp.Body, limit)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s %s: %w", req.Method, describe(req), err)
	}
	return resp.StatusCode, body, nil
}

// describe names req's URL for an error: the scheme, the host and the path.
// The query and any credentials are left out, since they may hold a secret.
func describe(req *http.Request) string {
	u := *req.URL
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// contextOrBackground keeps a nil context from panicking a request.
func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
