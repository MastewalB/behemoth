package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/errs"
)

// keySetMaxAge is how long a verifier may cache the key set. A key published
// for a new secret version is found within it.
const keySetMaxAge = 5 * time.Minute

// KeySetRoutes returns the key set route: GET path, which answers with the
// public keys of keys as a JWK set (RFC 7517). Another service checks
// Behemoth's external JWTs, such as session tokens, against it. path is
// absolute, and empty means crypto.DefaultJWKSPath. It returns nil when keys
// is nil: external JWTs are off, and there is nothing to publish.
func KeySetRoutes(keys crypto.KeySet, path string) []Route {
	if keys == nil {
		return nil
	}
	if path == "" {
		path = crypto.DefaultJWKSPath
	}
	return []Route{{Method: http.MethodGet, Path: path, Handler: keySetHandler(keys)}}
}

// keySetHandler answers with the public halves of keys. A key that
// MarshalJWKSet can't write, such as a private key, is a security error, and
// nothing is published.
func keySetHandler(keys crypto.KeySet) HandlerFunc {
	return func(rctx *RequestContext) error {
		published, err := keys.PublicKeys(rctx.Ctx)
		if err != nil {
			return err
		}
		set, err := crypto.MarshalJWKSet(published)
		if err != nil {
			return errs.NewSecurityError("auth.KeySet", errs.CodeJWKSReadFailed, err)
		}
		rctx.Response.SetHeader("Cache-Control", fmt.Sprintf("public, max-age=%d", int(keySetMaxAge/time.Second)))
		return rctx.Response.JSON(http.StatusOK, json.RawMessage(set))
	}
}
