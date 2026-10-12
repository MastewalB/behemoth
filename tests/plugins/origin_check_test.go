package plugins_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/plugins/emailpassword"
	sqliteAdapter "github.com/MastewalB/behemoth/storage/adapters/sqlite"
	"github.com/MastewalB/behemoth/types"
	bmth "github.com/MastewalB/behemoth/types/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bootWithRouter boots the email/password plugin alone with a session
// transport and a router configuration.
func bootWithRouter(t *testing.T, transport types.TokenTransport, router types.RouterConfig) (*types.AuthContext, mountedRoutes, error) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "origin.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(magicLinkSchema)
	require.NoError(t, err)

	mounted := mountedRoutes{}
	app, err := bmth.Prepare([]types.Plugin{emailpassword.New(emailpassword.Options{})}, bmth.PrepareConfig{})
	require.NoError(t, err)
	ac, err := bmth.Boot(context.Background(), app, sqliteAdapter.NewSQLiteAdapter(db, nil), bmth.BootConfig{
		Crypto: crypto.Config{
			Secrets: crypto.StaticSecretSource{Secrets: map[int]string{1: strings.Repeat("ef", 32)}, Current: 1},
		},
		Session: types.SessionConfig{Transport: transport},
		Router:  router,
		HTTP:    mounted,
	})
	return ac, mounted, err
}

// Boot puts the origin check in front of every route when the session token
// travels in a cookie, and leaves it out for the bearer transports, whose
// token a browser never sends by itself.
func TestBootInstallsTheOriginCheckForCookieTransports(t *testing.T) {
	const body = `{"email":"nobody@example.com","password":"correct horse battery"}`
	router := types.RouterConfig{BaseURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"}}

	for transport, checked := range map[types.TokenTransport]bool{
		"":                    true, // the default is the cookie
		types.TransportCookie: true,
		types.TransportBoth:   true,
		types.TransportHeader: false,
		types.TransportBody:   false,
	} {
		t.Run("transport "+string(transport), func(t *testing.T) {
			ac, mounted, err := bootWithRouter(t, transport, router)
			require.NoError(t, err)
			signIn := mounted["/api/auth/sign-in/email"]

			// A sign-in carries no cookie, and is refused all the same.
			w := callHeaders(t, ac, signIn, body, map[string]string{"Origin": "https://evil.example"})
			if checked {
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.Contains(t, w.Body.String(), behemotherr.ErrorCodeUntrustedOrigin)
			} else {
				assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
			}

			for name, headers := range map[string]map[string]string{
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

// A base URL that is not an origin fails Boot whatever the transport, and
// not the first request.
func TestBootRefusesAMalformedBaseURL(t *testing.T) {
	for _, transport := range []types.TokenTransport{types.TransportCookie, types.TransportHeader} {
		_, _, err := bootWithRouter(t, transport, types.RouterConfig{BaseURL: "auth.example.com/api"})
		require.Error(t, err)
		assert.True(t, behemotherr.Is(err, behemotherr.CategoryConfiguration), "got %v", err)
	}
}
