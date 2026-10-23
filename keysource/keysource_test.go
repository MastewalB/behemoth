package keysource_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-behemoth/behemoth/keysource"
	"github.com/go-behemoth/behemoth/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuer serves a JWK set at /jwks, and keeps the requests it received.
type issuer struct {
	srv *httptest.Server

	mu       sync.Mutex
	status   int
	body     string
	requests []*http.Request
}

func newIssuer(t *testing.T, tls bool, body string) *issuer {
	t.Helper()
	iss := &issuer{status: http.StatusOK, body: body}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.mu.Lock()
		defer iss.mu.Unlock()
		iss.requests = append(iss.requests, r.Clone(context.Background()))
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(iss.status)
		_, _ = w.Write([]byte(iss.body))
	})
	if tls {
		iss.srv = httptest.NewTLSServer(handler)
	} else {
		iss.srv = httptest.NewServer(handler)
	}
	t.Cleanup(iss.srv.Close)
	return iss
}

func (iss *issuer) answer(status int, body string) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.status, iss.body = status, body
}

func (iss *issuer) received() []*http.Request {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return append([]*http.Request(nil), iss.requests...)
}

func rsaSet(t *testing.T, extra ...map[string]any) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	keys := append([]map[string]any{{
		"kty": "RSA", "kid": "k1", "alg": "RS256",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}, extra...)
	data, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	return string(data), &key.PublicKey
}

// The source fetches the set on every call, asks for a JWK set, and
// returns the keys that can verify a signature.
func TestJWKSetFetchesTheKeys(t *testing.T) {
	body, public := rsaSet(t, map[string]any{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"})
	iss := newIssuer(t, true, body)
	client := outbound.NewClient(outbound.Options{Transport: iss.srv.Client().Transport, UserAgent: "shop-auth"}, nil)
	source, err := keysource.NewJWKSet(client, iss.srv.URL+"/jwks?tenant=7")
	require.NoError(t, err)

	keys, err := source.Keys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1, "the symmetric key is left out")
	assert.Equal(t, "k1", keys[0].KID)
	assert.Equal(t, "RS256", keys[0].Algorithm)
	assert.True(t, public.Equal(keys[0].Key))

	_, err = source.Keys(context.Background())
	require.NoError(t, err)
	requests := iss.received()
	require.Len(t, requests, 2, "nothing is cached")
	assert.Equal(t, "/jwks", requests[0].URL.Path)
	assert.Equal(t, "7", requests[0].URL.Query().Get("tenant"))
	assert.Equal(t, "application/jwk-set+json, application/json", requests[0].Header.Get("Accept"))
	assert.Equal(t, "shop-auth", requests[0].Header.Get("User-Agent"), "the given client makes the calls")
}

// A failed fetch, an answer that is not a JWK set, and a set without a key
// that can verify a signature are errors. None of them names the query.
func TestJWKSetErrors(t *testing.T) {
	body, _ := rsaSet(t)
	iss := newIssuer(t, false, body)
	source, err := keysource.NewJWKSet(nil, iss.srv.URL+"/jwks?token=s3cret")
	require.NoError(t, err)
	_, err = source.Keys(context.Background())
	require.NoError(t, err, "a nil client is a client with the defaults")

	cases := map[string]struct {
		status int
		body   string
		is     error
	}{
		"a server error":         {status: http.StatusInternalServerError, body: `{}`},
		"not found":              {status: http.StatusNotFound, body: `{}`},
		"not JSON":               {status: http.StatusOK, body: `<html></html>`},
		"not a set":              {status: http.StatusOK, body: `{"issuer":"https://id.example.com"}`},
		"an empty set":           {status: http.StatusOK, body: `{"keys":[]}`, is: keysource.ErrNoUsableKey},
		"no key that can verify": {status: http.StatusOK, body: `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`, is: keysource.ErrNoUsableKey},
		"a set too large":        {status: http.StatusOK, body: `{"keys":[],"x":"` + strings.Repeat("a", int(outbound.DefaultMaxBody)) + `"}`, is: outbound.ErrTooLarge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			iss.answer(c.status, c.body)
			_, err := source.Keys(context.Background())
			require.Error(t, err)
			if c.is != nil {
				assert.ErrorIs(t, err, c.is)
			}
			assert.NotContains(t, err.Error(), "s3cret")
			assert.Contains(t, err.Error(), "/jwks")
		})
	}

	unreachable, err := keysource.NewJWKSet(nil, "http://127.0.0.1:1/jwks")
	require.NoError(t, err)
	_, err = unreachable.Keys(context.Background())
	assert.Error(t, err)
}

// Keys come over https, or over http from a loopback address.
func TestNewJWKSetChecksTheURL(t *testing.T) {
	for _, raw := range []string{
		"https://id.example.com/.well-known/jwks.json",
		"http://localhost:8080/jwks", "http://127.0.0.1/jwks", "http://[::1]:9000/jwks",
	} {
		_, err := keysource.NewJWKSet(nil, raw)
		assert.NoError(t, err, raw)
	}
	for _, raw := range []string{
		"http://id.example.com/jwks", "/jwks", "id.example.com/jwks", "ftp://id.example.com/jwks",
		"https://user:pw@id.example.com/jwks", "https://id.example.com/jwks#keys", "https://[::1/jwks",
	} {
		_, err := keysource.NewJWKSet(nil, raw)
		assert.Error(t, err, raw)
	}
}
