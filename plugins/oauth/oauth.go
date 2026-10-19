// Package oauth is the OAuth sign-in plugin: a user signs in through an
// OAuth 2.0 or OpenID Connect provider, such as Google or GitHub.
//
// A sign-in has two flows. Begin starts it: it creates the state, the PKCE
// verifier, the nonce and the binding value of one sign-in, keeps them as a
// single-use token of kind core.TokenKindOAuthState, and returns the URL at
// the provider to send the browser to. The provider sends the browser back
// to a page of the application (Options.CallbackURL) with an authorization
// code and the state. Complete takes both with the binding value, redeems
// the code at the provider, finds or creates the user, and creates a
// session. It fires core's auth.signIn.* points, and auth.signUp.* for a
// user it creates, so a handler written for another plugin's sign-ins sees
// these too.
//
// The two routes, POST /sign-in/oauth and POST /oauth/complete, are JSON
// calls of the application's own pages. The binding value travels the way
// the session token does: in an HttpOnly cookie under the cookie
// transports, and in the response body for a client that keeps the session
// token itself.
//
// Three kinds of provider ship with the plugin and are configured as data
// (ProviderConfig): any OpenID Connect provider, Google, and GitHub. An
// application can add a Provider of its own.
//
// Experimental: the plugin is not complete. There is no linking of a
// provider account to an existing user, and no stored provider token.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/outbound"
	"github.com/MastewalB/behemoth/telemetry"
)

// PluginName is the name the plugin registers under (PluginMeta.Name). It
// owns the plugin's hook points and its token kind, and is the Method of the
// sign-ins it makes.
const PluginName = "oauth"

// pluginVersion is what Version reports.
const pluginVersion = "0.1.0"

// DefaultStateTTL is how long a started sign-in can be finished when
// Options.StateTTL is zero.
const DefaultStateTTL = 10 * time.Minute

// The points the plugin declares and fires around Begin.
const (
	// HookBeginBefore runs on Begin's input: "provider", "redirect_url" and
	// the keys of BeginRequest.Extra. A handler may rewrite them or stop the
	// sign-in.
	HookBeginBefore core.HookPoint = "auth.oauth.beforeBegin"
	// HookBeginAfter runs once a sign-in has started, with a *BeginResult
	// whose AuthorizationURL and Binding are empty.
	HookBeginAfter core.HookPoint = "auth.oauth.afterBegin"
	// HookBeginFailed fires for a sign-in that a handler or a rate limit
	// refused to start: code "rejected_by_hook".
	HookBeginFailed core.HookPoint = "auth.oauth.beginFailed"
)

// providerID is the form of a provider's id. The length is that of the
// accounts table's provider_id column.
var providerID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Options configures the plugin. CallbackURL is required, and so is at
// least one provider, in Providers or CustomProviders. Every provider has
// an id of its own.
type Options struct {
	// Providers are the providers that ship with the plugin, configured as
	// data: any OpenID Connect provider, Google, and GitHub.
	Providers []ProviderConfig

	// CustomProviders are providers the application implements.
	CustomProviders []Provider

	// HTTPClient makes the calls of the built-in providers: discovery, keys,
	// the code exchange, and GitHub's API. Nil means AuthContext.HTTPClient,
	// the client Boot builds from BootConfig.Outbound for every plugin. Set
	// it to give the providers a client of their own, such as one that
	// sends them to a test server. Build it with outbound.NewClient, or make
	// sure it follows no redirect: the code exchange sends the client
	// secret.
	HTTPClient *http.Client

	// CallbackURL is the page of the application a provider sends the
	// browser back to, such as "https://app.example.com/auth/callback".
	// Required, absolute, http or https, without a query or a fragment.
	//
	// Each provider has a redirect URI of its own under it, CallbackURL
	// followed by "/" and the provider's id (RedirectURI):
	// "https://app.example.com/auth/callback/google". That is the URI to
	// register at the provider, and the page the application serves.
	CallbackURL string

	// StateTTL is how long a started sign-in can be finished: the time a
	// user has to sign in at the provider. Zero means DefaultStateTTL.
	// TokenConfig.TTLOverrides for core.TokenKindOAuthState takes
	// precedence.
	StateTTL time.Duration
}

// Plugin is the OAuth sign-in plugin. It declares the oauth_state token
// kind and the auth.oauth.* points around Begin, and fires core's
// auth.signIn.* and auth.signUp.* points when a sign-in is completed. It
// needs no table of its own: a started sign-in is a row in core's tokens
// table, and a provider account is a row in accounts.
type Plugin struct {
	opts        Options
	providers   map[string]Provider
	authContext *core.AuthContext
	log         telemetry.Logger
	complete    func(hctx *core.HookContext, in completeInput) (*core.SignInResult, error)
	signUp      func(hctx *core.HookContext, in signUpInput) (*models.User, error)
}

// New returns the plugin configured with opts. Values left at zero take
// their defaults. Missing or invalid options are reported by Init, as a
// configuration error from Boot.
func New(opts Options) *Plugin {
	if opts.StateTTL == 0 {
		opts.StateTTL = DefaultStateTTL
	}
	return &Plugin{opts: opts}
}

// RedirectURI returns the redirect URI of the provider with the id
// providerID, for an application whose Options.CallbackURL is callbackURL:
// callbackURL followed by "/" and the id. It is the URI the application
// registers at the provider, and the one Begin hands to the provider.
func RedirectURI(callbackURL, providerID string) string {
	return strings.TrimRight(callbackURL, "/") + "/" + providerID
}

// Meta implements [core.Plugin]. The plugin depends on no other plugin and
// has no mount path.
func (p *Plugin) Meta() core.PluginMeta {
	return core.PluginMeta{Name: PluginName}
}

// Version implements [core.Plugin].
func (p *Plugin) Version() string {
	return pluginVersion
}

// Declare implements [core.Plugin]. The plugin declares:
//   - the token kind core.TokenKindOAuthState: single use, and kept in the
//     database, so that the plugin works without a key-value storage;
//   - the auth.oauth.* points around Begin. None is audited: Begin needs no
//     session and is not about an account;
//   - two rate-limit rules: starts and completions of a sign-in per client
//     address.
//
// It declares no sign-in points: core declares auth.signIn.* and
// auth.signUp.*.
func (p *Plugin) Declare(ic *core.PluginInitContext) error {
	if err := ic.Tokens.Declare(core.TokenKindDef{
		Kind: core.TokenKindOAuthState, SingleUse: true, DefaultTTL: p.opts.StateTTL, Backend: core.TokenBackendDB,
	}); err != nil {
		return err
	}
	for _, def := range []core.HookPointDef{
		{Point: HookBeginBefore, Phase: core.BeforeHookPhase},
		{Point: HookBeginAfter, Phase: core.AfterHookPhase},
		{Point: HookBeginFailed, Phase: core.FailedHookPhase},
	} {
		if err := ic.Hooks.Declare(def); err != nil {
			return err
		}
	}

	// Per address on the routes, like the magic link plugin's: it slows one
	// client down and can't be used to keep another one out. Begin needs no
	// session and writes a token for every call.
	byAddress := func(_ *http.Request, ip string) string { return ip }
	for _, rule := range []core.RouteRateLimitRule{
		{Name: RuleBeginRoute, Method: http.MethodPost, Path: PathBegin, KeyFunc: byAddress, Limit: core.Limit{Max: 10, Window: time.Minute}},
		{Name: RuleCompleteRoute, Method: http.MethodPost, Path: PathComplete, KeyFunc: byAddress, Limit: core.Limit{Max: 10, Window: time.Minute}},
	} {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// Register implements [core.Plugin]. The plugin attaches no handlers to
// other points.
func (p *Plugin) Register(reg core.HookRegistry) error {
	return nil
}

// Middlewares implements [core.Plugin]. The plugin has no middleware.
func (p *Plugin) Middlewares() []core.Middleware {
	return nil
}

// Init implements [core.Plugin]. It checks the options, builds the
// built-in providers, keeps the AuthContext and wraps the flows with their
// hook points. A missing provider, a ProviderConfig that is incomplete or
// whose client secret can't be read, a provider id that is malformed,
// reserved or used twice, and a CallbackURL that is not usable are
// configuration errors. Init calls no provider: a provider that is down
// fails the sign-ins, not the boot.
func (p *Plugin) Init(ac *core.AuthContext) error {
	const op = "oauth.Init"
	if p.opts.StateTTL < 0 {
		return errs.NewConfigurationError(op, fmt.Sprintf("Options.StateTTL is negative: %s", p.opts.StateTTL), nil)
	}
	callbackURL, err := url.Parse(p.opts.CallbackURL)
	if err != nil || (callbackURL.Scheme != "http" && callbackURL.Scheme != "https") || callbackURL.Host == "" ||
		callbackURL.User != nil || callbackURL.RawQuery != "" || callbackURL.ForceQuery || callbackURL.Fragment != "" {
		return errs.NewConfigurationError(op,
			fmt.Sprintf("Options.CallbackURL %q is not an absolute http or https URL without a query or a fragment", p.opts.CallbackURL), err)
	}

	if len(p.opts.Providers)+len(p.opts.CustomProviders) == 0 {
		return errs.NewConfigurationError(op, "Options.Providers and Options.CustomProviders are empty; the plugin needs at least one provider", nil)
	}
	client := providerHTTP{client: p.opts.HTTPClient}
	if client.client == nil {
		client.client = ac.HTTPClient
	}
	if client.client == nil { // an AuthContext Boot did not build
		client.client = outbound.NewClient(outbound.Options{}, ac.Telemetry)
	}
	type placed struct {
		at       string
		provider Provider
	}
	all := make([]placed, 0, len(p.opts.Providers)+len(p.opts.CustomProviders))
	for i, cfg := range p.opts.Providers {
		at := fmt.Sprintf("Options.Providers[%d]", i)
		provider, err := newBuiltinProvider(at, cfg, client, time.Now)
		if err != nil {
			return errs.NewConfigurationError(op, err.Error(), nil)
		}
		all = append(all, placed{at, provider})
	}
	for i, provider := range p.opts.CustomProviders {
		all = append(all, placed{fmt.Sprintf("Options.CustomProviders[%d]", i), provider})
	}
	providers := make(map[string]Provider, len(all))
	for _, entry := range all {
		if entry.provider == nil {
			return errs.NewConfigurationError(op, entry.at+" is nil", nil)
		}
		id := entry.provider.ID()
		switch {
		case !providerID.MatchString(id):
			return errs.NewConfigurationError(op, fmt.Sprintf(
				"%s has the id %q; an id is 1 to 64 lowercase letters, digits, \"-\" and \"_\", and starts with a letter or a digit", entry.at, id), nil)
		case id == models.ProviderCredential:
			// The provider_id of the account that holds a user's password.
			return errs.NewConfigurationError(op, fmt.Sprintf("%s has the reserved id %q", entry.at, id), nil)
		case providers[id] != nil:
			return errs.NewConfigurationError(op, fmt.Sprintf("two providers have the id %q", id), nil)
		}
		providers[id] = entry.provider
	}

	p.providers = providers
	p.authContext = ac
	p.log = telemetry.NoOpLogger{}
	if ac.Telemetry != nil {
		p.log = telemetry.Named(ac.Telemetry.Logger, PluginName)
	}
	p.complete = core.WithLifecycle(ac.Dispatcher, hooks.HookSignInBefore, hooks.HookSignInAfter, hooks.HookSignInFailed, p.completeBody)
	p.signUp = core.WithLifecycle(ac.Dispatcher, hooks.HookSignUpBefore, hooks.HookSignUpAfter, hooks.HookSignUpFailed, p.signUpBody)
	return nil
}

// operation builds the HookContext one flow call runs with. Its Values start
// as a copy of the operation ctx already belongs to, if any, and Request is
// the request ctx carries, or nil.
func (p *Plugin) operation(ctx context.Context, op string) (*core.HookContext, error) {
	if p.authContext == nil {
		return nil, errs.NewConfigurationError(op, "the plugin is not initialized; pass it to Prepare and Boot first", nil)
	}
	return &core.HookContext{
		Ctx:     ctx,
		Auth:    p.authContext,
		Values:  core.NestedHookValues(ctx),
		Request: core.RequestFrom(ctx),
	}, nil
}

// Routes implements [core.Plugin].
func (p *Plugin) Routes() []core.Route {
	return []core.Route{
		{Method: http.MethodPost, Path: PathBegin, Handler: p.handleBegin},
		{Method: http.MethodPost, Path: PathComplete, Handler: p.handleComplete},
	}
}

var _ core.Plugin = (*Plugin)(nil)
