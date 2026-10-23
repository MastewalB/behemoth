package plugins_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/crypto"
	"github.com/go-behemoth/behemoth/engine"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/httpapi"
	"github.com/go-behemoth/behemoth/plugins/emailpassword"
	sqliteAdapter "github.com/go-behemoth/behemoth/storage/adapters/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bootWithRouter boots the email/password plugin alone with a token
// delivery and a router configuration.
func bootWithRouter(t *testing.T, delivery httpapi.TokenDelivery, router httpapi.RouterConfig) (*core.AuthContext, mountedRoutes, error) {
	t.Helper()
	router.Carrier.Delivery = delivery
	return bootRouter(t, router)
}

// bootRouter boots the email/password plugin alone with a router
// configuration.
func bootRouter(t *testing.T, router httpapi.RouterConfig) (*core.AuthContext, mountedRoutes, error) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "origin.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	mounted := mountedRoutes{}
	app, err := engine.Prepare([]core.Plugin{emailpassword.New(emailpassword.Options{})}, engine.PrepareConfig{})
	require.NoError(t, err)
	ac, err := engine.Boot(context.Background(), app, sqliteAdapter.NewSQLiteAdapter(db, nil), engine.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Router: router,
		HTTP:   mounted,
	})
	return ac, mounted, err
}

// Boot puts the origin check in front of every route when the session token
// travels in a cookie, and leaves it out for the bearer deliveries, whose
// token a browser never sends by itself.
func TestBootInstallsTheOriginCheckForCookieDeliveries(t *testing.T) {
	const body = `{"email":"nobody@example.com","password":"correct horse battery"}`
	router := httpapi.RouterConfig{BaseURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"}}

	for delivery, checked := range map[httpapi.TokenDelivery]bool{
		"":                     true, // the default is the cookie
		httpapi.DeliveryCookie: true,
		httpapi.DeliveryBoth:   true,
		httpapi.DeliveryHeader: false,
		httpapi.DeliveryBody:   false,
	} {
		t.Run("delivery "+string(delivery), func(t *testing.T) {
			ac, mounted, err := bootWithRouter(t, delivery, router)
			require.NoError(t, err)
			signIn := mounted["/api/auth/sign-in/email"]

			// A sign-in carries no cookie, and is refused all the same.
			w := callHeaders(t, ac, signIn, body, map[string]string{"Origin": "https://evil.example"})
			if checked {
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.Contains(t, w.Body.String(), errs.CodeUntrustedOrigin)
			} else {
				assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
			}

			// A form's content type is refused behind the origin check,
			// under the same deliveries.
			w = callHeaders(t, ac, signIn, body, map[string]string{"Origin": "https://auth.example.com", "Content-Type": "text/plain"})
			if checked {
				assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
				assert.Contains(t, w.Body.String(), errs.CodeUnsupportedContentType)
			} else {
				assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
			}

			for name, headers := range map[string]map[string]string{
				"JSON":             {"Origin": "https://auth.example.com", "Content-Type": "application/json"},
				"its own origin":   {"Origin": "https://auth.example.com"},
				"a trusted origin": {"Origin": "https://app.example.com"},
				"not a browser":    {},
			} {
				w := callHeaders(t, ac, signIn, body, headers)
				assert.Equal(t, http.StatusUnauthorized, w.Code, "%s: %s", name, w.Body.String())
			}
		})
	}
}

// A base URL that is not an origin fails Boot whatever the delivery, and
// not the first request.
func TestBootRefusesAMalformedBaseURL(t *testing.T) {
	for _, delivery := range []httpapi.TokenDelivery{httpapi.DeliveryCookie, httpapi.DeliveryHeader} {
		_, _, err := bootWithRouter(t, delivery, httpapi.RouterConfig{BaseURL: "auth.example.com/api"})
		require.Error(t, err)
		assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "got %v", err)
	}
}

// Boot refuses a session cookie that can't work with the base URL: one
// that is sent cross-site without a base URL for the origin check to
// compare with, and one whose domain does not cover behemoth's host.
func TestBootChecksTheSessionCookieAgainstTheBaseURL(t *testing.T) {
	for name, tc := range map[string]struct {
		carrier httpapi.TokenCarrierConfig
		baseURL string
		refused string // "" = Boot succeeds
	}{
		"SameSite none without a base URL":      {httpapi.TokenCarrierConfig{CookieSameSite: httpapi.SameSiteNone}, "", "BaseURL"},
		"SameSite none with a base URL":         {httpapi.TokenCarrierConfig{CookieSameSite: httpapi.SameSiteNone}, "https://auth.example.com", ""},
		"SameSite none under a bearer delivery": {httpapi.TokenCarrierConfig{CookieSameSite: httpapi.SameSiteNone, Delivery: httpapi.DeliveryHeader}, "", ""},
		"a domain that is the host":             {httpapi.TokenCarrierConfig{CookieDomain: "auth.example.com"}, "https://auth.example.com", ""},
		"a domain that is a parent of the host": {httpapi.TokenCarrierConfig{CookieDomain: ".Example.com"}, "https://auth.example.com:8443", ""},
		"a domain of another site":              {httpapi.TokenCarrierConfig{CookieDomain: "example.org"}, "https://auth.example.com", "CookieDomain"},
		"a domain that only ends alike":         {httpapi.TokenCarrierConfig{CookieDomain: "ample.com"}, "https://auth.example.com", "CookieDomain"},
		"a domain without a base URL":           {httpapi.TokenCarrierConfig{CookieDomain: "example.com"}, "", ""},
	} {
		_, _, err := bootRouter(t, httpapi.RouterConfig{BaseURL: tc.baseURL, Carrier: tc.carrier})
		if tc.refused == "" {
			assert.NoError(t, err, name)
			continue
		}
		require.Error(t, err, name)
		assert.True(t, errs.IsCategory(err, errs.CategoryConfiguration), "%s: %v", name, err)
		assert.Contains(t, err.Error(), tc.refused, name)
	}
}
