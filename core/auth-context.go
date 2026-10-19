package core

import (
	"net/http"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/schema"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
)

type AuthContext struct {
	// DB is the root database adapter, for a plugin's or the application's
	// own tables. By convention behemoth's tables are written through Store
	// (and sessions and tokens through their managers): the adapter skips
	// the hooks, ids, timestamps, normalization and token sealing they add.
	// See Store.DB and docs/api/core-tables.md.
	DB behemoth.Database
	KV behemoth.KeyValueStorage
	// Store is the data layer plugins use instead of DB. It is a concrete
	// type: store never imports core, so no interface is needed to break
	// an import cycle.
	Store          *store.Store
	Crypto         crypto.Services
	SessionManager SessionManager
	// SessionConfig is BootConfig.Session with its defaults applied: the
	// settings the session manager runs with. It is a copy: changing it
	// changes nothing.
	SessionConfig SessionConfig
	// TokenCarrier carries the session token over HTTP, the way
	// RouterConfig.Carrier says: a sign-in route hands the token to the
	// client through it (WriteSignIn), and a route that ends its caller's
	// session takes the token back (Clear). A route that hands the client a
	// value of its own reads TokenCarrier.Config to deliver it the same way.
	// Never nil on an AuthContext Boot returns.
	TokenCarrier *TokenCarrier
	TokenManager TokenManager
	// JWT signs and verifies JWTs: internal ones with the key manager's
	// HMAC key, external ones with keys derived from the master secret
	// (ADR-0002). Never nil on an AuthContext Boot returns. External tokens
	// are on when BootConfig.JWT names an external audience.
	JWT crypto.JWTProvider
	// SessionTokens exchanges a session for a session token, a short-lived
	// external JWT for other services. Never nil on an AuthContext Boot
	// returns; with external tokens off, Issue is a configuration error.
	SessionTokens SessionTokens
	Dispatcher    Dispatcher
	RateLimiter   RateLimiter
	// Origins answers whether an origin is one of RouterConfig.TrustedOrigins.
	// A plugin that takes a redirect URL from a request checks it with
	// TrustedRedirect(Origins, url) before it stores or returns it. Never
	// nil on an AuthContext Boot returns; with no origins configured it
	// trusts none, and only paths on the application's own site pass.
	Origins OriginValidator
	// Public builds what a client is sent of a row: the columns its table
	// declares Public, and no others. A route that returns a user answers
	// with Public.Of(user) and not with the model, which as JSON carries
	// every column a plugin contributed to users. Never nil on an
	// AuthContext Boot returns.
	Public schema.PublicView
	// Mailer sends the messages plugins produce (a sign-in link, an email
	// verification) through the application's MailSender. Never nil on an
	// AuthContext Boot returns; Mailer.Configured says whether a sender was
	// given. The application calls Mailer.Close at shutdown to let
	// background sends finish.
	Mailer Mailer
	// SMS sends the text messages plugins produce (a one-time code) through
	// the application's SMSSender. Never nil on an AuthContext Boot returns;
	// SMS.Configured says whether a sender was given. The application calls
	// SMS.Close at shutdown, as for Mailer.
	SMS SMS
	// Codes issues and checks one-time codes: short numeric secrets sent by
	// text message. See CodeManager for how they differ from tokens.
	Codes CodeManager
	// Access answers whether the caller on a context may run a flow: a
	// self-service flow requires a user and a permission, and an admin
	// operation a privileged caller. Never nil on an AuthContext Boot returns.
	Access Access
	// Authenticator turns the credential of a call into its caller. The router
	// authenticates every request through it, and an application's own
	// transport authenticates through it too, so that its calls get the same
	// caller. Never nil on an AuthContext Boot returns.
	Authenticator Authenticator
	// Telemetry is never nil on an AuthContext Boot returns, and neither are
	// its fields. Plugins take their logger from here, usually through
	// telemetry.Named.
	Telemetry *telemetry.Telemetry
	// HTTPClient is the client plugins call other services with, built by
	// outbound.NewClient from BootConfig.Outbound: a timeout, no redirect
	// unless the options say so, a user agent, and a span per call. A
	// plugin uses it unless an option of the plugin names another client.
	// Never nil on an AuthContext Boot returns.
	HTTPClient *http.Client
}
