package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticKeySet is a crypto.KeySet over a fixed list of keys.
type staticKeySet []crypto.PublishedKey

func (s staticKeySet) PublicKey(_ context.Context, kid string) (crypto.PublishedKey, error) {
	for _, k := range s {
		if k.KID == kid {
			return k, nil
		}
	}
	return crypto.PublishedKey{}, errs.NewNotFound("staticKeySet", kid, nil)
}

func (s staticKeySet) PublicKeys(context.Context) ([]crypto.PublishedKey, error) { return s, nil }

// serve runs the one route of routes and returns what it answered.
func serve(t *testing.T, routes []types.Route) (*httptest.ResponseRecorder, error) {
	t.Helper()
	require.Len(t, routes, 1)
	rctx := &types.RequestContext{Ctx: context.Background(), Response: types.NewResponseRecorder()}
	err := routes[0].Handler(rctx)
	w := httptest.NewRecorder()
	rctx.Response.Flush(w)
	return w, err
}

// The route publishes the key set as a JWK set at the configured path, and
// lets a verifier cache it for a while.
func TestKeySetRoutesPublishTheKeys(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keys := staticKeySet{{KID: "1", Algorithm: "EdDSA", Key: public}}

	routes := KeySetRoutes(keys, "")
	require.Len(t, routes, 1)
	assert.Equal(t, http.MethodGet, routes[0].Method)
	assert.Equal(t, crypto.DefaultJWKSPath, routes[0].Path, "an empty path means the default")
	assert.Equal(t, "/keys.json", KeySetRoutes(keys, "/keys.json")[0].Path)

	w, err := serve(t, routes)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

	want, err := crypto.MarshalJWKSet(keys)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), w.Body.String())
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "1", set.Keys[0]["kid"])
}

// Without a key set, external JWTs are off and there is no route.
func TestKeySetRoutesWithoutKeys(t *testing.T) {
	assert.Nil(t, KeySetRoutes(nil, ""))
}

// A key the JWK set can't hold, such as a private key, publishes nothing.
func TestKeySetRoutesRefuseAPrivateKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	w, err := serve(t, KeySetRoutes(staticKeySet{{KID: "1", Algorithm: "EdDSA", Key: private}}, ""))
	require.Error(t, err)
	assert.True(t, errs.IsCode(err, errs.CodeJWKSReadFailed))
	assert.Empty(t, w.Body.String())
}
