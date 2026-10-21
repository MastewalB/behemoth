// Package engine assembles Behemoth. Prepare collects what the plugins declare:
// hook points, token kinds, rate-limit rules, and tables. Boot builds the
// services over a database and returns the AuthContext the application and
// the plugins use.
package engine

import (
	"context"
	"fmt"
	"github.com/MastewalB/behemoth/dispatch"
	"github.com/MastewalB/behemoth/messaging"
	"net/url"
	"strings"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/auth"
	"github.com/MastewalB/behemoth/core"
	"github.com/MastewalB/behemoth/core/hooks"
	"github.com/MastewalB/behemoth/crypto"
	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/migration"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/outbound"
	"github.com/MastewalB/behemoth/ratelimit"
	"github.com/MastewalB/behemoth/schema"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/utils"
)

// PrepareConfig is everything Prepare needs beyond the plugin list. None of
// it touches a live connection: Prepare must stay runnable from a migration
// CLI that never boots the application.
type PrepareConfig struct {
	Migration migration.MigrationConfig

	// AppName is the owner name of everything the application itself
	// declares or registers: its tables (Schema) and its hook handlers
	// (BootConfig.Hooks). It is what HookOptions.Before/After and error
	// messages call the application. Empty = "app". It can't be "core" or a
	// plugin's name.
	AppName string

	// Schema declares the application's own tables under owner AppName. It
	// runs after every plugin has declared, so it can also extend plugin
	// tables (e.g. a column on "users"). nil = no application tables.
	Schema func(reg schema.Registry) error

	// Migrations are hand-authored migrations, ordered among generated
	// operations by their DependsOn. Each is emitted into exactly one
	// generated migration, recorded there by Name; names are therefore
	// permanent and must never be reused.
	Migrations []migration.CustomMigration
}

// Owner names that are not plugins. coreOwner owns what behemoth itself
// declares. defaultAppOwner owns what the application declares or registers
// when PrepareConfig.AppName is empty.
const (
	coreOwner       = "core"
	defaultAppOwner = "app"
)

// PreparedApp is the connection-free result of Prepare: every catalog and
// the schema registry, frozen, plus the SchemaResolver derived from them.
// Build storage adapters and migration drivers with Resolver, then hand the
// adapter to Boot.
type PreparedApp struct {
	Order []string
	// AppName is the application's owner name: PrepareConfig.AppName, or
	// "app" when that was empty.
	AppName    string
	Hooks      core.HookCatalog
	Tokens     core.TokenCatalog
	RateLimits core.RateLimitCatalog
	// Permissions holds the permissions core and the plugins declared, which
	// Boot gives to AuthContext.Access.
	Permissions core.PermissionCatalog
	Schemas     schema.Registry
	Resolver    behemoth.SchemaResolver
	Migration   migration.MigrationConfig
	Custom      []migration.CustomMigration

	plugins []core.Plugin // kept so Boot runs exactly the set that was prepared
}

// Prepare runs every declaration step of initialization — plugin ordering,
// hook/token/rate-limit catalogs and the schema registry — and freezes them.
// It is the whole of Boot that needs no database, so migration tooling calls
// it alone, and Boot calls nothing else to get there.
func Prepare(plugins []core.Plugin, cfg PrepareConfig) (*PreparedApp, error) {
	if err := DetectPluginNameConflicts(plugins); err != nil {
		return nil, err
	}
	appName := cfg.AppName
	if appName == "" {
		appName = defaultAppOwner
	}
	if err := checkOwnerNames(plugins, appName); err != nil {
		return nil, err
	}
	if err := migration.ValidateCustomMigrations(cfg.Migrations); err != nil {
		return nil, err
	}

	order, err := ResolvePluginOrder(plugins)
	if err != nil {
		return nil, err
	}

	// Initialize Catalogs
	hookCatalog := dispatch.NewDefaultHookCatalog()
	tokenCatalog := auth.NewDefaultTokenCatalog()
	rateLimitCatalog := ratelimit.NewRateLimitCatalog(hookCatalog)
	permissionCatalog := auth.NewDefaultPermissionCatalog()
	schemaRegistry := schema.NewRegistry()

	// Core declares first, under owner "core" via the scoped
	// wrappers all plugins get, to enforce uniform validation process
	coreIC := newScopedInitContext(hookCatalog, tokenCatalog, rateLimitCatalog, permissionCatalog, schemaRegistry, coreOwner)
	if err := CoreDeclareHookPoints(coreIC); err != nil {
		return nil, err
	}
	if err := CoreDeclareRateLimitRules(coreIC); err != nil {
		return nil, err
	}
	if err := CoreDeclarePermissions(coreIC); err != nil {
		return nil, err
	}
	if err := CoreDeclareSchema(coreIC); err != nil {
		return nil, err
	}

	// Declare phase: every plugin, in dependency order
	for _, name := range order {
		p := lookup(plugins, name)
		if p == nil {
			return nil, errs.NewConfigurationError("Prepare", fmt.Sprintf("internal error: resolved plugin name %q not found", name), nil)
		}
		ic := newScopedInitContext(hookCatalog, tokenCatalog, rateLimitCatalog, permissionCatalog, schemaRegistry, name)
		if err := p.Declare(ic); err != nil {
			return nil, fmt.Errorf("plugin %q Declare failed: %w", name, err)
		}
	}

	// Application tables last, so they can extend anything declared above
	if cfg.Schema != nil {
		if err := cfg.Schema(&scopedSchemaRegistry{inner: schemaRegistry, owner: appName}); err != nil {
			return nil, fmt.Errorf("application schema declaration failed: %w", err)
		}
	}

	// Freeze all catalogs and the schema registry
	hookCatalog.Freeze()
	tokenCatalog.Freeze()
	rateLimitCatalog.Freeze()
	permissionCatalog.Freeze()
	if err := schemaRegistry.Freeze(); err != nil {
		return nil, err
	}

	// The resolver is derived from the frozen registry, never authored
	// separately, so it is complete before any adapter or driver exists.
	migrationCfg := migration.NewMigrationConfig(cfg.Migration)
	resolver := migration.NewSchemaResolver()
	resolver.Freeze(migration.BuildSchemaResolverTable(schemaRegistry, migrationCfg))

	return &PreparedApp{
		Order:       order,
		AppName:     appName,
		Hooks:       hookCatalog,
		Tokens:      tokenCatalog,
		RateLimits:  rateLimitCatalog,
		Permissions: permissionCatalog,
		Schemas:     schemaRegistry,
		Resolver:    resolver,
		Migration:   migrationCfg,
		Custom:      cfg.Migrations,
		plugins:     plugins,
	}, nil
}

// Declared is what migration tooling converges the database on: every
// declared table plus the application's custom migrations.
func (a *PreparedApp) Declared() migration.Declared {
	return migration.Declared{Schemas: a.Schemas, Custom: a.Custom}
}

// BootConfig is everything Boot needs beyond the prepared app and the
// database. Only Crypto.Secrets is required; every other zero value means
// the documented default.
type BootConfig struct {
	Crypto crypto.Config

	// KV is optional. nil = sessions and rate-limit counters use the database.
	KV behemoth.KeyValueStorage

	// Telemetry is optional. nil = no-op logger, audit recorder and metrics.
	// Build it with telemetry.New; a nil field of a struct literal also
	// becomes a no-op.
	Telemetry *telemetry.Telemetry

	// Hooks registers the application's own hook handlers, under the owner
	// name PreparedApp.AppName ("app" by default). It runs after every
	// plugin's Register, so the application can hook any declared point
	// without writing a plugin. Among handlers of equal priority with no
	// Before/After constraint between them, the application's run last.
	// HookOptions.Before/After may name the application like a plugin. Like
	// a plugin, it may register one handler per point. nil = the application
	// registers no handlers.
	Hooks func(reg core.HookRegistry) error

	RateLimit core.RateLimitConfig
	Session   core.SessionConfig
	Token     core.TokenConfig

	// Audit says what the audit events behemoth records hold. Zero value =
	// every event in full, the client's IP address and user agent included.
	// Where events go is Telemetry's audit recorder.
	Audit core.AuditConfig

	// JWT configures the JWTs behemoth issues. Naming an external audience
	// (Audiences[JWTExternal]) turns session tokens on: POST /session/token
	// and the key set route at JWKSPath are mounted. An empty Issuer is
	// RouterConfig.BaseURL. Zero value = session tokens off.
	JWT crypto.JWTConfig

	// Mail gives behemoth the application's mail sender, which plugins
	// that send messages need (magic link, email verification). Zero value
	// = no sender; such a plugin then fails Boot.
	Mail core.MailConfig

	// SMS gives behemoth the application's SMS sender, which plugins that
	// send text messages need (phone number). Zero value = no sender; such
	// a plugin then fails Boot.
	SMS core.SMSConfig

	// Outbound configures the client behemoth calls other services with,
	// AuthContext.HTTPClient: a timeout, whether redirects are followed, a
	// user agent, and a transport for a proxy of the application's own.
	// Every call is a span on Telemetry. Zero value = outbound's defaults:
	// a 10-second timeout, no redirects, and the proxy from the
	// environment.
	Outbound outbound.Options

	// Router configures behemoth's routes: base path, error mapping,
	// client-IP resolution, and how the session token travels over HTTP
	// (Carrier). Zero value = documented defaults.
	Router core.RouterConfig

	// HTTP mounts behemoth's routes onto the application's framework
	// instance, e.g. ginadapter.New(engine). nil = routes are built and
	// checked but not served (workers, CLIs).
	HTTP core.FrameworkDriver
}

// IndexChecker is an optional interface of a Database on which a missing
// index goes unnoticed. Boot calls CheckIndexes once with every declared
// table, before anything is written, and fails when it returns an error.
//
// The MongoDB adapter implements it. MongoDB has no migration driver, so
// nothing creates the indexes a schema declares unless the application calls
// the adapter's EnsureIndexes, and without a unique index MongoDB stores the
// duplicates it was declared to refuse. The SQL adapters don't implement it:
// their indexes come with the tables their migration drivers create, and a
// missing table fails the first query.
//
// It is declared here and not next to behemoth.TransactionChecker because it
// names schema.Table, and the schema package imports behemoth.
type IndexChecker interface {
	// CheckIndexes returns an error when an index that enforces uniqueness
	// is missing. A missing index that only speeds reads up is returned as
	// a warning, one line per index, which Boot logs.
	CheckIndexes(ctx context.Context, tables []schema.Table) (warnings []string, err error)
}

// Boot turns a PreparedApp into a running AuthContext. db must have been
// built with app.Resolver, otherwise application queries and migrations
// disagree on physical table and column names.
//
// ctx bounds long-lived background work Boot starts (e.g. the KeyManager's
// secret watch), so it should live as long as the application.
func Boot(ctx context.Context, app *PreparedApp, db behemoth.Database, cfg BootConfig) (*core.AuthContext, error) {
	if app == nil {
		return nil, errs.NewConfigurationError("Boot", "Boot requires the result of Prepare", nil)
	}
	if db == nil {
		return nil, errs.NewConfigurationError("Boot", "a Database is required", nil)
	}
	// Fail here instead of on the first hooked write (a sign-up) when the
	// database is deployed without transactions, e.g. a standalone MongoDB.
	if checker, ok := db.(behemoth.TransactionChecker); ok {
		if err := checker.CheckTransactions(ctx); err != nil {
			return nil, fmt.Errorf("database transaction check failed: %w", err)
		}
	}
	plugins, order := app.plugins, app.Order
	kv := cfg.KV

	tel := telemetry.OrDefault(cfg.Telemetry)
	// Fail here instead of storing duplicates when the database has no way
	// to refuse them: on MongoDB a missing unique index is silent.
	if checker, ok := db.(IndexChecker); ok {
		warnings, err := checker.CheckIndexes(ctx, app.Schemas.All())
		if err != nil {
			return nil, fmt.Errorf("database index check failed: %w", err)
		}
		for _, w := range warnings {
			tel.Named("boot").Logger.Warn(ctx, "a declared index is missing; reads that use it scan the collection", behemoth.M{"index": w})
		}
	}
	if !tel.AuditConfigured() {
		// Auditing is on unless the application says otherwise: events go
		// to the audit_log table. The recorder gets a store of its own,
		// without data hooks or an encryptor, because it is needed before
		// either exists and the table uses neither.
		tel.Audit = store.NewAuditRecorder(store.New(db, store.WithSchema(app.Resolver), store.WithTelemetry(tel)))
	}

	cryptoSuite, err := crypto.New(ctx, cfg.Crypto, tel)
	if err != nil {
		return nil, err
	}

	// Registration phase
	hookRegistry := dispatch.NewHookRegistry(app.Hooks)
	for _, name := range order {
		p := lookup(plugins, name)
		if p == nil {
			return nil, errs.NewConfigurationError("Boot", fmt.Sprintf("internal error: resolved plugin name %q not found", name), nil)
		}
		scoped := hookRegistry.For(name)
		if err := p.Register(scoped); err != nil {
			return nil, fmt.Errorf("plugin %q Register failed: %w", name, err)
		}
	}

	// The application registers last, like its schema is declared last. Its
	// handlers are ordered as if it were the last plugin to boot.
	hookOrder := order
	if cfg.Hooks != nil {
		if err := cfg.Hooks(hookRegistry.For(app.AppName)); err != nil {
			return nil, fmt.Errorf("application hook registration failed: %w", err)
		}
		hookOrder = append(append([]string{}, order...), app.AppName)
	}

	frozenChains, err := dispatch.FreezeChains(app.Hooks, hookRegistry, hookOrder)
	if err != nil {
		return nil, err
	}

	// Counters fire no data hooks, so they get a store of their own: the
	// one plugins use is built later, from the dispatcher this feeds.
	rateLimiter, err := ratelimit.NewDefaultRateLimiter(app.RateLimits, kv, store.New(db, store.WithSchema(app.Resolver), store.WithTelemetry(tel)), cfg.RateLimit, cfg.Audit, tel)
	if err != nil {
		return nil, err
	}
	// One client-IP configuration for sessions, route rate limiting, and audit
	// events, so that all of them see the same address for a request.
	ipCfg, err := core.NewClientConfig(cfg.Router.TrustedProxies, cfg.Router.ClientIPHeader)
	if err != nil {
		return nil, err
	}
	dispatcher := dispatch.NewDefaultDispatcher(app.Hooks, frozenChains, rateLimiter, cfg.Audit, tel)

	origins, err := core.NewTrustedOrigins(cfg.Router.TrustedOrigins)
	if err != nil {
		return nil, errs.NewConfigurationError("Boot", "RouterConfig.TrustedOrigins", err)
	}
	// Built whatever the delivery, so a malformed BaseURL fails here.
	originCheck, err := core.NewOriginCheck(cfg.Router.BaseURL, origins)
	if err != nil {
		return nil, errs.NewConfigurationError("Boot", "RouterConfig.BaseURL", err)
	}
	if err := cfg.Outbound.Validate(); err != nil {
		return nil, errs.NewConfigurationError("Boot", err.Error(), err)
	}
	if err := cfg.Router.Carrier.Validate(); err != nil {
		return nil, errs.NewConfigurationError("Boot", err.Error(), err)
	}
	if err := checkCookieAgainstBaseURL(cfg.Router.Carrier.WithDefaults(), cfg.Router.BaseURL); err != nil {
		return nil, errs.NewConfigurationError("Boot", err.Error(), err)
	}
	ac := &core.AuthContext{
		DB:          db,
		KV:          kv,
		Dispatcher:  dispatcher,
		RateLimiter: rateLimiter,
		Crypto:      cryptoSuite,
		Telemetry:   tel,
		Origins:     origins,
		// One client for every outbound call, so each gets the same rules
		// (ADR-0003).
		HTTPClient: outbound.NewClient(cfg.Outbound, tel),
		// The session manager applies the same defaults to the same value.
		SessionConfig: cfg.Session.WithDefaults(),
		Mailer:        messaging.NewMailer(cfg.Mail, tel),
		SMS:           messaging.NewSMS(cfg.SMS, tel),
		Public:        schema.NewPublicView(app.Schemas.All()), // the registry was frozen by Prepare
	}
	if err := dispatch.CheckDataHookPoints(app.Hooks); err != nil {
		return nil, err
	}
	// The store's data hooks dispatch with ac, and the managers persist
	// through the store, so they are built in that order.
	ac.Store = store.New(db, store.WithHooks(dispatch.NewDataHooks(ac)), store.WithSchema(app.Resolver),
		store.WithEncryptor(cryptoSuite.AtRest), store.WithTelemetry(tel))
	ac.Codes = auth.NewCodeManager(ac.Store, cryptoSuite)
	ac.TokenManager = auth.NewDefaultTokenManager(ac.Store, kv, app.Tokens, cryptoSuite, dispatcher, cfg.Token, ac)
	if err := cfg.Session.Validate(); err != nil {
		return nil, errs.NewConfigurationError("Boot", err.Error(), err)
	}
	ac.SessionManager = auth.NewSessionManager(ac.Store, kv, cryptoSuite, cfg.Session, dispatcher, tel, ac)
	ac.Access = auth.NewAccess(app.Permissions, ac.SessionManager.IsFresh)
	ac.Authenticator = auth.NewAuthenticator(ac.SessionManager, tel)

	// JWTs: internal ones always, external ones and session tokens when an
	// external audience is named. The external keys are derived from the
	// master secret, so there is nothing to create first (ADR-0002).
	jwtCfg := cfg.JWT.WithDefaults()
	if jwtCfg.Issuer == "" {
		jwtCfg.Issuer = cfg.Router.BaseURL
	}
	if err := jwtCfg.Validate(); err != nil {
		return nil, errs.NewConfigurationError("Boot", err.Error(), err)
	}
	var externalKeys crypto.ExternalKeySet
	if jwtCfg.ExternalEnabled() {
		externalKeys = crypto.NewDerivedKeySet(cryptoSuite.Keys)
	}
	jwtProvider := crypto.NewJWTProvider(cryptoSuite.JWTSign, externalKeys, jwtCfg)
	ac.JWT = jwtProvider
	sessionTokens := auth.NewSessionTokens(jwtProvider, dispatcher, ac, ac.SessionManager, jwtCfg)
	ac.SessionTokens = sessionTokens

	// Init before routing, so Routes() and Middlewares() may rely on
	// anything a plugin sets up in Init.
	for _, name := range order {
		p := lookup(plugins, name)
		if err := p.Init(ac); err != nil {
			return nil, fmt.Errorf("plugin %q Init failed: %w", name, err)
		}
	}

	// The route table is built and conflict-checked even without an HTTP
	// driver, so a misconfiguration surfaces the same way in every process.
	router := core.NewRouter(cfg.Router, ac)
	var globalMiddleware []core.Middleware
	// A bearer token is never sent by the browser on its own, so only the
	// cookie deliveries need the origin check and the refusal of form
	// bodies behind it. Both run before the plugins' middleware.
	if router.TokenCarrier().Config().Delivery.ReadsCookie() {
		globalMiddleware = append(globalMiddleware, originCheck.Middleware(), core.RefuseFormContentTypes())
	}
	for _, name := range order {
		p := lookup(plugins, name)
		if err := router.Mount(name, p.Meta().MountPath, p.Routes()); err != nil {
			return nil, err
		}
		globalMiddleware = append(globalMiddleware, p.Middlewares()...)
	}

	// Session tokens, when on: the exchange below the base path, and the
	// key set at its well-known path outside it.
	if err := router.Mount(coreOwner, "", sessionTokens.Routes()); err != nil {
		return nil, err
	}
	if err := router.MountAbsolute(coreOwner, auth.KeySetRoutes(externalKeys, jwtCfg.JWKSPath)...); err != nil {
		return nil, err
	}

	// Route-scoped rate limiting is baked in once, before any driver sees the routes.
	// Authentication wraps each route inside its rate limit, so that a refused
	// request costs no session lookup.
	router.ApplyAuthentication(ac.Authenticator, ipCfg)
	router.ApplyRateLimiting(rateLimiter, app.RateLimits, ipCfg)

	if cfg.HTTP != nil {
		if err := router.Build(cfg.HTTP, globalMiddleware...); err != nil {
			return nil, err
		}
	}
	logBootSummary(ctx, tel.Named("boot").Logger, order, len(router.Routes()), cfg)
	return ac, nil
}

// checkCookieAgainstBaseURL reports a session cookie that can't work with
// the base URL, under the deliveries that set one. carrier has its defaults
// applied, and baseURL has been parsed by NewOriginCheck already.
//
//   - SameSiteNone needs a base URL. The browser then sends the cookie with
//     cross-site requests, the origin check is all that refuses a forged
//     one, and without a base URL the check compares with the Host header.
//   - CookieDomain has to be the base URL's host or a parent of it. A
//     browser drops a cookie whose Domain does not cover the host that set
//     it, and every sign-in would then seem to succeed and leave no session.
func checkCookieAgainstBaseURL(carrier core.TokenCarrierConfig, baseURL string) error {
	if !carrier.Delivery.ReadsCookie() {
		return nil
	}
	if baseURL == "" {
		if carrier.CookieSameSite == core.SameSiteNone {
			return fmt.Errorf("RouterConfig.Carrier.CookieSameSite %q needs RouterConfig.BaseURL, which the origin check compares requests with", carrier.CookieSameSite)
		}
		return nil
	}
	domain := strings.ToLower(strings.TrimPrefix(carrier.CookieDomain, "."))
	if domain == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return fmt.Errorf("RouterConfig.BaseURL %q: %w", baseURL, err)
	}
	if host := strings.ToLower(u.Hostname()); host != domain && !strings.HasSuffix(host, "."+domain) {
		return fmt.Errorf("RouterConfig.Carrier.CookieDomain %q does not cover the host of RouterConfig.BaseURL %q, so a browser would drop the session cookie", carrier.CookieDomain, baseURL)
	}
	return nil
}

// logBootSummary writes one Info line describing what Boot built, and one
// Warn line per configuration that is valid but probably not intended. It
// runs last, so a line means Boot succeeded.
func logBootSummary(ctx context.Context, log telemetry.Logger, order []string, routes int, cfg BootConfig) {
	log.Info(ctx, "behemoth booted", behemoth.M{
		"plugins":        order,
		"routes":         routes,
		"routes_mounted": cfg.HTTP != nil, // false: built and checked, not served (a worker, a CLI)
		"kv":             cfg.KV != nil,   // false: sessions and rate-limit counters use the database only
	})
	if cfg.Router.ClientIPHeader != "" && len(cfg.Router.TrustedProxies) == 0 {
		log.Warn(ctx, "RouterConfig.ClientIPHeader is set but TrustedProxies is empty; the header is ignored and every request is attributed to its direct peer",
			behemoth.M{"header": cfg.Router.ClientIPHeader})
	}
	// Only where routes are served: a worker or a CLI answers no request.
	if cfg.HTTP != nil && cfg.Router.BaseURL == "" && cfg.Router.Carrier.WithDefaults().Delivery.ReadsCookie() {
		log.Warn(ctx, "RouterConfig.BaseURL is not set; the origin check compares each request's Origin with its Host header, which refuses browser requests behind a proxy that rewrites Host", nil)
	}
}

// ResolvePluginOrder builds a dependency DAG from every plugin's declared
// PluginMeta.Dependencies, resolves it via utils.KahnSort, and returns
// plugins in an order where every hard dependency precedes its dependant.
func ResolvePluginOrder(plugins []core.Plugin) ([]string, error) {
	byName := make(map[string]core.Plugin, len(plugins))
	metas := make(map[string]core.PluginMeta, len(plugins))

	// Step 1: collect each plugin's declared metadata, reject duplicate names up front
	for _, p := range plugins {
		meta := p.Meta()
		if meta.Name == "" {
			return nil, errs.NewConfigurationError("ResolvePluginOrder", "a plugin returned an empty Meta().Name", nil)
		}
		if _, dup := byName[meta.Name]; dup {
			return nil, errs.NewConfigurationError("ResolvePluginOrder", fmt.Sprintf("plugin name %q registered more than once", meta.Name), nil)
		}
		byName[meta.Name] = p
		metas[meta.Name] = meta
	}

	// Step 2: validate hard dependencies exist before building the graph.
	// A missing optional dependency is skipped (simply no edge).
	for name, meta := range metas {
		for _, dep := range meta.Dependencies {
			if _, exists := metas[dep.Name]; !exists && !dep.Optional {
				return nil, errs.NewConfigurationError("ResolvePluginOrder",
					fmt.Sprintf("plugin %q requires %q, which is not registered", name, dep.Name), nil)
			}
		}
	}

	// Step 3: build the graph in KahnSort's expected dependant direction.
	// PluginMeta expresses dependencies the natural way (A lists that it
	// depends on B) and this loop inverts that into graph[B] = [A, ...]..
	// Getting this backwards would make KahnSort silently produce a valid-looking but wrong order
	// (dependants before their dependencies)
	graphMap := make(map[string][]string, len(metas))
	for name := range metas {
		if _, ok := graphMap[name]; !ok {
			graphMap[name] = nil // ensure every plugin appears as a key even with zero dependants, so KahnSort's allNodes collection sees it
		}
	}
	for name, meta := range metas {
		for _, dep := range meta.Dependencies {
			if _, exists := metas[dep.Name]; !exists {
				continue // optional and absent
			}
			graphMap[dep.Name] = append(graphMap[dep.Name], name) // dep.Name's dependants include name
		}
	}

	// Step 4: sort, and report a cycle if one exists
	alphabetical := func(a, b string) bool { return a < b }
	order, cyclePath, ok := utils.KahnSort(graphMap, alphabetical)
	if !ok {
		return nil, errs.NewConfigurationError("ResolvePluginOrder",
			fmt.Sprintf("circular plugin dependency: %s", strings.Join(cyclePath, " -> ")), nil)
	}

	// Step 5: translate the []string order back into []Plugin
	// resolved := make([]Plugin, len(order))
	// for i, name := range order {
	// 	resolved[i] = byName[name]
	// }
	return order, nil
}

// Owner-injection wrappers - Declare phase scoping
type scopedHookCatalog struct {
	inner core.HookCatalog
	owner string
}

func (s *scopedHookCatalog) Declare(def core.HookPointDef) error {
	def.Owner = s.owner // overwritten unconditionally — a plugin cannot misattribute a declaration
	return s.inner.Declare(def)
}
func (s *scopedHookCatalog) Lookup(point core.HookPoint) (core.HookPointDef, bool) {
	return s.inner.Lookup(point)
}

func (s *scopedHookCatalog) All() []core.HookPointDef {
	return s.inner.All()
}

type scopedTokenCatalog struct {
	inner core.TokenCatalog
	owner string
}

func (s *scopedTokenCatalog) Declare(def core.TokenKindDef) error {
	def.Owner = s.owner
	return s.inner.Declare(def)
}
func (s *scopedTokenCatalog) Lookup(kind models.TokenKind) (core.TokenKindDef, bool) {
	return s.inner.Lookup(kind)
}

type scopedRateLimitCatalog struct {
	inner core.RateLimitCatalog
	owner string
}

func (s *scopedRateLimitCatalog) DeclareHookRateLimitRule(rule core.HookRateLimitRule) error {
	rule.Owner = s.owner
	return s.inner.DeclareHookRateLimitRule(rule)
}
func (s *scopedRateLimitCatalog) RulesForHook(point core.HookPoint) []core.HookRateLimitRule {
	return s.inner.RulesForHook(point)
}
func (s *scopedRateLimitCatalog) DeclareRouteRateLimitRule(rule core.RouteRateLimitRule) error {
	rule.Owner = s.owner
	return s.inner.DeclareRouteRateLimitRule(rule)
}
func (s *scopedRateLimitCatalog) RulesForRoute() []core.RouteRateLimitRule {
	return s.inner.RulesForRoute()
}
func (s *scopedRateLimitCatalog) DeclareRule(rule core.RateLimitRule) error {
	rule.Owner = s.owner
	return s.inner.DeclareRule(rule)
}
func (s *scopedRateLimitCatalog) Rule(name string) (core.RateLimitRule, bool) {
	return s.inner.Rule(name)
}
func (s *scopedRateLimitCatalog) HasRule(name string) bool { return s.inner.HasRule(name) }

// scopedSchemaRegistry injects the declaring owner into every table and
// contribution, the same way the catalog wrappers above do.
// scopedPermissionCatalog is the PermissionCatalog a declarer receives: it
// records the declarer as the owner of what it declares.
type scopedPermissionCatalog struct {
	inner core.PermissionCatalog
	owner string
}

func (s *scopedPermissionCatalog) Declare(def core.PermissionDef) error {
	def.Owner = s.owner
	return s.inner.Declare(def)
}
func (s *scopedPermissionCatalog) Lookup(p core.Permission) (core.PermissionDef, bool) {
	return s.inner.Lookup(p)
}
func (s *scopedPermissionCatalog) All() []core.PermissionDef { return s.inner.All() }

type scopedSchemaRegistry struct {
	inner schema.Registry
	owner string
}

func (s *scopedSchemaRegistry) Declare(model behemoth.Model, table schema.Table) error {
	table.Owner = s.owner
	return s.inner.Declare(model, table)
}
func (s *scopedSchemaRegistry) ExtendColumn(c schema.ColumnContribution) error {
	c.Owner = s.owner
	return s.inner.ExtendColumn(c)
}
func (s *scopedSchemaRegistry) ExtendIndex(c schema.IndexContribution) error {
	c.Owner = s.owner
	return s.inner.ExtendIndex(c)
}
func (s *scopedSchemaRegistry) ExtendForeignKey(c schema.ForeignKeyContribution) error {
	c.Owner = s.owner
	return s.inner.ExtendForeignKey(c)
}
func (s *scopedSchemaRegistry) Lookup(name string) (schema.Table, bool) {
	return s.inner.Lookup(name)
}
func (s *scopedSchemaRegistry) LookupModel(name string) (behemoth.Model, bool) {
	return s.inner.LookupModel(name)
}
func (s *scopedSchemaRegistry) All() []schema.Table { return s.inner.All() }

// Freeze is Prepare's alone; a declarer freezing the registry early would
// lock out every declarer after it.
func (s *scopedSchemaRegistry) Freeze() error {
	return errs.NewConfigurationError("SchemaRegistry.Freeze", fmt.Sprintf("%q cannot freeze the schema registry", s.owner), nil)
}

func newScopedInitContext(
	hooks *dispatch.DefaultHookCatalog,
	tokens *auth.DefaultTokenCatalog,
	rl *ratelimit.DefaultRateLimitCatalog,
	permissions *auth.DefaultPermissionCatalog,
	schemas schema.Registry,
	owner string,
) *core.PluginInitContext {
	return &core.PluginInitContext{
		Hooks:       &scopedHookCatalog{inner: hooks, owner: owner},
		Tokens:      &scopedTokenCatalog{inner: tokens, owner: owner},
		RateLimits:  &scopedRateLimitCatalog{inner: rl, owner: owner},
		Permissions: &scopedPermissionCatalog{inner: permissions, owner: owner},
		Schemas:     &scopedSchemaRegistry{inner: schemas, owner: owner},
	}
}

func DetectPluginNameConflicts(plugins []core.Plugin) error {
	var conflicts strings.Builder
	var conflictDetected bool

	seen := make(map[string]int, len(plugins))
	for _, p := range plugins {
		if _, exists := seen[p.Meta().Name]; exists {
			conflictDetected = true
		}
		seen[p.Meta().Name] += 1
	}

	if conflictDetected {
		conflicts.WriteString("\nConflicting plugin names: \n")
		for k, v := range seen {
			if v > 1 {
				fmt.Fprintf(&conflicts, "\t %s - used %d times.\n", k, v)
			}
		}
		return errs.NewConfigurationError("Router.Mount", conflicts.String(), nil)
	}

	return nil
}

// checkOwnerNames rejects names that would make two owners indistinguishable:
// an application named like core, or a plugin named like core or the
// application. Owner names attribute tables and hook points and order hook
// handlers, so each must mean one thing.
func checkOwnerNames(plugins []core.Plugin, appName string) error {
	if appName == coreOwner {
		return errs.NewConfigurationError("Prepare",
			fmt.Sprintf("AppName %q is reserved for behemoth's own declarations", coreOwner), nil)
	}
	for _, p := range plugins {
		switch name := p.Meta().Name; name {
		case coreOwner:
			return errs.NewConfigurationError("Prepare",
				fmt.Sprintf("plugin name %q is reserved for behemoth's own declarations", name), nil)
		case appName:
			return errs.NewConfigurationError("Prepare",
				fmt.Sprintf("plugin name %q is the application's name (PrepareConfig.AppName); rename one of them", name), nil)
		}
	}
	return nil
}

// lookup finds the Plugin matching name. O(n) scan at boot-time plugin
// counts (dozens at most), called a handful of times total, not per-request.
// A nil return should never happen for a name that came out of
// ResolvePluginOrder's own output; Boot treats a nil result as an internal
// invariant violation, not a recoverable condition.
func lookup(plugins []core.Plugin, name string) core.Plugin {
	for _, p := range plugins {
		if p.Meta().Name == name {
			return p
		}
	}
	return nil
}

// CoreDeclareHookPoints declares every hook point behemoth's own code fires:
// the flow points of sign-up, sign-in and sign-out, the session and token
// manager points, and the data points the store fires (dispatch.NewDataHooks).
// A point has one phase, so an operation with a before and an after side is
// two points. Dispatching a point missing from this list is a configuration
// error.
func CoreDeclareHookPoints(ic *core.PluginInitContext) error {
	points := []core.HookPointDef{
		{Point: hooks.HookSignUpBefore, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSignUpAfter, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: hooks.HookSignUpFailed, Owner: coreOwner, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},

		{Point: hooks.HookSignInBefore, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSignInCredentialsVerified, Owner: coreOwner, Phase: core.BeforeHookPhase}, // also Before; a distinct checkpoint, not signIn's "after"
		{Point: hooks.HookSignInAfter, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: hooks.HookSignInFailed, Owner: coreOwner, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},

		{Point: hooks.HookSignOutBefore, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSignOutAfter, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},

		// fired by the session manager
		{Point: hooks.HookSessionBeforeCreate, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSessionAfterCreate, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: hooks.HookSessionBeforeRevoke, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSessionAfterRevoke, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},

		// fired by the session token flow; not audited: a client asks for a
		// token every few minutes, and its session is audited when created
		{Point: hooks.HookSessionTokenBeforeIssue, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookSessionTokenAfterIssue, Owner: coreOwner, Phase: core.AfterHookPhase},
		{Point: hooks.HookSessionTokenIssueFailed, Owner: coreOwner, Phase: core.FailedHookPhase},

		// fired by the token manager
		{Point: hooks.HookTokenBeforeIssue, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookTokenAfterIssue, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: hooks.HookTokenConsumed, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{}},
		{Point: hooks.HookTokenFailed, Owner: coreOwner, Phase: core.FailedHookPhase, Audit: &core.AuditSpec{}},

		// data hooks the store fires (see dispatch.NewDataHooks)
		{Point: hooks.HookUserBeforeCreate, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookUserAfterCreate, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{Type: telemetry.AuditUserCreated}}, // written in the write's transaction
		{Point: hooks.HookUserBeforeUpdate, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookUserAfterUpdate, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{Type: telemetry.AuditUserUpdated}}, // written in the write's transaction
		// fired once the write's transaction has committed
		{Point: hooks.HookUserCreated, Owner: coreOwner, Phase: core.AfterHookPhase},
		{Point: hooks.HookUserUpdated, Owner: coreOwner, Phase: core.AfterHookPhase},
		// a delete: Store.DeleteUser, with the user's sessions, accounts and tokens
		{Point: hooks.HookUserBeforeDelete, Owner: coreOwner, Phase: core.BeforeHookPhase},
		{Point: hooks.HookUserAfterDelete, Owner: coreOwner, Phase: core.AfterHookPhase, Audit: &core.AuditSpec{Type: telemetry.AuditUserDeleted}}, // written in the delete's transaction
		{Point: hooks.HookUserDeleted, Owner: coreOwner, Phase: core.AfterHookPhase},
	}
	for _, p := range points {
		if err := ic.Hooks.Declare(p); err != nil {
			return err
		}
	}
	return nil
}

// CoreDeclareSchema declares the tables core itself owns. Plugins and the
// application may extend them (ExtendColumn); the models carry those
// columns in their Extension.
//
// A table added here or removed changes the name of an application's first
// migration, which TestLauncherRunsAnApplication checks: update it too.
func CoreDeclareSchema(ic *core.PluginInitContext) error {
	for _, d := range []struct {
		model behemoth.Model
		table schema.Table
	}{
		{&models.User{}, models.UserTableSchema()},
		{&models.Session{}, models.SessionTableSchema()},
		{&models.Token{}, models.TokenTableSchema()},
		{&models.Account{}, models.AccountTableSchema()},
		{&models.RateLimit{}, models.RateLimitTableSchema()},
		{&models.AuditLog{}, models.AuditLogTableSchema()},
		{&models.VerificationCode{}, models.VerificationCodeTableSchema()},
	} {
		if err := ic.Schemas.Declare(d.model, d.table); err != nil {
			return err
		}
	}
	return nil
}

// CoreDeclarePermissions declares the permissions core's own flows require:
// core.PermissionSessionTokenIssue, for SessionTokens.Issue. It is declared
// whether or not session tokens are on, so that the catalog does not depend
// on BootConfig.
func CoreDeclarePermissions(ic *core.PluginInitContext) error {
	return ic.Permissions.Declare(core.PermissionDef{
		Name: core.PermissionSessionTokenIssue, Kind: core.PermissionSelf,
		Description: "Get a short-lived token that proves your session to another service",
	})
}

// The names of core's limits per client address. Each is a hook rule on its
// flow's before point, keyed by core.KeyByClientIP, so it counts every call
// of the flow, over HTTP or another transport, and not the requests to one
// path. A call whose caller has no address, such as code in the process, is
// not counted. RateLimitConfig.Limits and Disabled change them by name.
const (
	// RuleSignInAddress limits sign-ins per client address and sign-in
	// method (hooks.HookValueMethod): each method, such as emailpassword or
	// magiclink, keeps a count of its own.
	RuleSignInAddress = "core.signin.address"
	// RuleSignUpAddress limits sign-ups per client address and method, as
	// RuleSignInAddress does.
	RuleSignUpAddress = "core.signup.address"
	// RuleSessionTokenAddress limits session token issues per client
	// address. A client asks again every few minutes, and a page with
	// several tabs asks once per tab, so the limit is higher than sign-in's.
	RuleSessionTokenAddress = "core.session_token.address"
)

// CoreDeclareRateLimitRules declares the limits core applies without being
// asked: ten attempts a minute per client address and method on sign-in,
// the same on sign-up, and thirty session token issues a minute per client
// address. Sign-in and sign-up count separately.
//
// The limits are per address and not per account. On sign-in that slows one
// client guessing passwords and does not let anyone lock a user out by
// failing on purpose. On sign-up it bounds how fast one client can create
// accounts and make the server hash passwords.
func CoreDeclareRateLimitRules(ic *core.PluginInitContext) error {
	perMinute := func(max int64) core.Limit { return core.Limit{Max: max, Window: time.Minute} }
	for _, rule := range []core.HookRateLimitRule{
		{Name: RuleSignInAddress, Point: hooks.HookSignInBefore, KeyFunc: core.KeyByClientIP(hooks.HookValueMethod), Limit: perMinute(10)},
		{Name: RuleSignUpAddress, Point: hooks.HookSignUpBefore, KeyFunc: core.KeyByClientIP(hooks.HookValueMethod), Limit: perMinute(10)},
		{Name: RuleSessionTokenAddress, Point: hooks.HookSessionTokenBeforeIssue, KeyFunc: core.KeyByClientIP(), Limit: perMinute(30)},
	} {
		if err := ic.RateLimits.DeclareHookRateLimitRule(rule); err != nil {
			return err
		}
	}
	return nil
}
