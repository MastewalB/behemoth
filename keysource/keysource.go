// Package keysource holds key sources: what gives a key set the public keys
// it verifies tokens with. A source returns the keys as they are when it is
// called. It caches nothing, and each call fetches or reads the keys again,
// so its caller decides how long to keep them: crypto.NewCachedKeySet keeps
// them for a TTL, and fetches them again for a kid they lack.
//
// JWKSet fetches a JWK set over HTTPS, such as an OpenID Connect provider's
// or the one behemoth publishes at /.well-known/jwks.json, through a client
// of package outbound, and reads it with crypto.ParseJWKSet.
//
// Package crypto makes no outbound call. A key set that lives elsewhere
// reaches it through a source.
package keysource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/outbound"
	"github.com/MastewalB/behemoth/types"
)

// JWKSet is the source of the JWK set at a URL: a crypto.KeySource, whose
// keys crypto.NewCachedKeySet keeps. It is safe for concurrent use.
//
// Not built: the answer's Cache-Control, which would tell a caller how long
// the keys may be kept.
type JWKSet struct {
	client *http.Client
	url    string
	// name is the URL without its query, for errors.
	name string
}

var _ crypto.KeySource = (*JWKSet)(nil)

// NewJWKSet returns the source of the JWK set at rawURL, fetched with client.
// rawURL has to pass outbound.CheckURL: whoever can change the keys can sign
// tokens, so they come over https, or over http from a loopback address in
// development. A nil client means outbound.NewClient with no options and no
// telemetry.
func NewJWKSet(client *http.Client, rawURL string) (*JWKSet, error) {
	if err := outbound.CheckURL(rawURL); err != nil {
		return nil, fmt.Errorf("JWK set URL: %w", err)
	}
	if client == nil {
		client = outbound.NewClient(outbound.Options{}, nil)
	}
	u, _ := url.Parse(rawURL) // CheckURL parsed it
	u.RawQuery = ""
	return &JWKSet{client: client, url: rawURL, name: u.String()}, nil
}

// Keys fetches the set and returns its keys that can verify a signature, as
// crypto.ParseJWKSet reads them. An answer that is not 2xx, that is longer
// than outbound.DefaultMaxBody, or that is not a JWK set is an error. So is
// a set without a key that can verify a signature: no token could be
// checked with it.
func (s *JWKSet) Keys(ctx context.Context) ([]types.PublishedKey, error) {
	var raw json.RawMessage
	header := http.Header{"Accept": {"application/jwk-set+json, application/json"}}
	if _, err := outbound.GetJSON(ctx, s.client, s.url, header, &raw); err != nil {
		return nil, fmt.Errorf("JWK set: %w", err)
	}
	keys, err := crypto.ParseJWKSet(raw)
	if err != nil {
		return nil, fmt.Errorf("JWK set at %s: %w", s.name, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWK set at %s: %w", s.name, ErrNoUsableKey)
	}
	return keys, nil
}

// ErrNoUsableKey is the error of a JWK set that has no key that can verify a
// signature: an empty set, or one whose keys are all left out by
// crypto.ParseJWKSet.
var ErrNoUsableKey = errors.New("the set has no key that can verify a signature")
