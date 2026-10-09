package types

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/crypto"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/migration/core"
	"github.com/MastewalB/behemoth/models"
	"github.com/MastewalB/behemoth/store"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/transport"
	"github.com/MastewalB/behemoth/types"
	"github.com/MastewalB/behemoth/types/hooks"
	"github.com/MastewalB/behemoth/types/ratelimit"
	"github.com/MastewalB/behemoth/types/schema"
)

// PrepareConfig is everything Prepare needs beyond the plugin list. None of
// it touches a live connection: Prepare must stay runnable from a migration
// CLI that never boots the application.
type PrepareConfig struct {
	Migration core.MigrationConfig

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
	Migrations []core.CustomMigration
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
	Hooks      types.HookCatalog
	Tokens     types.TokenCatalog
	RateLimits types.RateLimitCatalog
	Schemas    schema.Registry
	Resolver   behemoth.SchemaResolver
	Migration  core.MigrationConfig
	Custom     []core.CustomMigration

	plugins []types.Plugin // kept so Boot runs exactly the set that was prepared
}

// Prepare runs every declaration step of initialization — plugin ordering,
// hook/token/rate-limit catalogs and the schema registry — and freezes them.
// It is the whole of Boot that needs no database, so migration tooling calls
// it alone, and Boot calls nothing else to get there.
func Prepare(plugins []types.Plugin, cfg PrepareConfig) (*PreparedApp, error) {
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
	if err := core.ValidateCustomMigrations(cfg.Migrations); err != nil {
		return nil, err
	}

	order, err := ResolvePluginOrder(plugins)
	if err != nil {
		return nil, err
	}

	// Initialize Catalogs
	hookCatalog := NewDefaultHookCatalog()
	tokenCatalog := NewDefaultTokenCatalog()
	rateLimitCatalog := NewRateLimitCatalog(hookCatalog)
	schemaRegistry := schema.NewRegistry()

	// Core declares first, under owner "core" via the scoped
	// wrappers all plugins get, to enforce uniform validation process
	coreIC := newScopedInitContext(hookCatalog, tokenCatalog, rateLimitCatalog, schemaRegistry, coreOwner)
	if err := CoreDeclareHookPoints(coreIC); err != nil {
		return nil, err
	}
	if err := CoreDeclareRateLimitRules(coreIC); err != nil {
		return nil, err
	}
	if err := CoreDeclareSchema(coreIC); err != nil {
		return nil, err
	}

	// Declare phase: every plugin, in dependency order
	for _, name := range order {
		p := lookup(plugins, name)
		if p == nil {
			return nil, behemotherr.NewConfigurationError("Prepare", fmt.Sprintf("internal error: resolved plugin name %q not found", name), nil)
		}
		ic := newScopedInitContext(hookCatalog, tokenCatalog, rateLimitCatalog, schemaRegistry, name)
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
	if err := schemaRegistry.Freeze(); err != nil {
		return nil, err
	}

	// The resolver is derived from the frozen registry, never authored
	// separately, so it is complete before any adapter or driver exists.
	migrationCfg := core.NewMigrationConfig(cfg.Migration)
	resolver := core.NewSchemaResolver()
	resolver.Freeze(core.BuildSchemaResolverTable(schemaRegistry, migrationCfg))

	return &PreparedApp{
		Order:      order,
		AppName:    appName,
		Hooks:      hookCatalog,
		Tokens:     tokenCatalog,
		RateLimits: rateLimitCatalog,
		Schemas:    schemaRegistry,
		Resolver:   resolver,
		Migration:  migrationCfg,
		Custom:     cfg.Migrations,
		plugins:    plugins,
	}, nil
}

// Declared is what migration tooling converges the database on: every
// declared table plus the application's custom migrations.
func (a *PreparedApp) Declared() core.Declared {
	return core.Declared{Schemas: a.Schemas, Custom: a.Custom}
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
	Hooks func(reg types.HookRegistry) error

	RateLimit types.RateLimitConfig
	Session   types.SessionConfig
	Token     types.TokenConfig

	// Mail gives behemoth the application's mail sender, which plugins
	// that send messages need (magic link, email verification). Zero value
	// = no sender; such a plugin then fails Boot.
	Mail types.MailConfig

	// Router configures behemoth's routes: base path, error mapping and
	// client-IP resolution. Zero value = documented defaults.
	Router types.RouterConfig

	// HTTP mounts behemoth's routes onto the application's framework
	// instance, e.g. ginadapter.New(engine). nil = routes are built and
	// checked but not served (workers, CLIs).
	HTTP types.FrameworkDriver
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
func Boot(ctx context.Context, app *PreparedApp, db behemoth.Database, cfg BootConfig) (*types.AuthContext, error) {
	if app == nil {
		return nil, behemotherr.NewConfigurationError("Boot", "Boot requires the result of Prepare", nil)
	}
	if db == nil {
		return nil, behemotherr.NewConfigurationError("Boot", "a Database is required", nil)
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
	hookRegistry := NewHookRegistry(app.Hooks)
	for _, name := range order {
		p := lookup(plugins, name)
		if p == nil {
			return nil, behemotherr.NewConfigurationError("Boot", fmt.Sprintf("internal error: resolved plugin name %q not found", name), nil)
		}
		scoped := &scopedHookRegistry{inner: hookRegistry, owner: name}
		if err := p.Register(scoped); err != nil {
			return nil, fmt.Errorf("plugin %q Register failed: %w", name, err)
		}
	}

	// The application registers last, like its schema is declared last. Its
	// handlers are ordered as if it were the last plugin to boot.
	hookOrder := order
	if cfg.Hooks != nil {
		if err := cfg.Hooks(&scopedHookRegistry{inner: hookRegistry, owner: app.AppName}); err != nil {
			return nil, fmt.Errorf("application hook registration failed: %w", err)
		}
		hookOrder = append(append([]string{}, order...), app.AppName)
	}

	frozenChains, err := freezeAllHookChains(app.Hooks, hookRegistry, hookOrder)
	if err != nil {
		return nil, err
	}

	// Counters fire no data hooks, so they get a store of their own: the
	// one plugins use is built later, from the dispatcher this feeds.
	counterStore, err := resolveRateLimitStore(kv, store.New(db, store.WithSchema(app.Resolver), store.WithTelemetry(tel))) // backend selection, below
	if err != nil {
		return nil, err
	}
	rateLimiter := &DefaultRateLimiter{catalog: app.RateLimits, limiters: newLimiters(counterStore), cfg: cfg.RateLimit, tel: tel.Named("ratelimit")}
	dispatcher := NewDefaultDispatcher(app.Hooks, frozenChains, rateLimiter, tel)

	origins, err := types.NewTrustedOrigins(cfg.Router.TrustedOrigins)
	if err != nil {
		return nil, behemotherr.NewConfigurationError("Boot", "RouterConfig.TrustedOrigins", err)
	}
	ac := &types.AuthContext{
		DB:          db,
		KV:          kv,
		Dispatcher:  dispatcher,
		RateLimiter: rateLimiter,
		Crypto:      cryptoSuite,
		Telemetry:   tel,
		Origins:     origins,
		Mailer:      NewMailer(cfg.Mail, tel),
		Public:      types.NewPublicView(app.Schemas.All()), // the registry was frozen by Prepare
	}
	if err := checkDataHookPoints(app.Hooks, coreDataHookPoints); err != nil {
		return nil, err
	}
	// The store's data hooks dispatch with ac, and the managers persist
	// through the store, so they are built in that order.
	ac.Store = store.New(db, store.WithHooks(dataHooks{ac: ac, points: coreDataHookPoints}), store.WithSchema(app.Resolver),
		store.WithEncryptor(cryptoSuite.AtRest), store.WithTelemetry(tel))
	ac.TokenManager = transport.NewDefaultTokenManager(ac.Store, kv, app.Tokens, cryptoSuite, dispatcher, cfg.Token, ac)
	// One client-IP configuration for sessions and route rate limiting, so
	// both see the same address for a request.
	ipCfg, err := types.NewClientConfig(cfg.Router.TrustedProxies, cfg.Router.ClientIPHeader)
	if err != nil {
		return nil, err
	}
	dispatcher.ipCfg = ipCfg // audit events record the same client address
	if err := cfg.Session.Validate(); err != nil {
		return nil, behemotherr.NewConfigurationError("Boot", err.Error(), err)
	}
	ac.SessionManager = transport.NewSessionManager(ac.Store, kv, cryptoSuite, cfg.Session, dispatcher, tel, ac, ipCfg)

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
	router := types.NewRouter(cfg.Router, ac)
	var globalMiddleware []types.Middleware
	for _, name := range order {
		p := lookup(plugins, name)
		if err := router.Mount(name, p.Meta().MountPath, p.Routes()); err != nil {
			return nil, err
		}
		globalMiddleware = append(globalMiddleware, p.Middlewares()...)
	}

	// // --- JWKS, if external JWT is configured (Crypto round) ---
	// if jwks := crypto.JWTRoutes(); jwks != nil {
	// 	router.MountAbsolute("core", jwks...)
	// }

	// Route-scoped rate limiting is baked in once, before any driver sees the routes.
	router.ApplyRateLimiting(rateLimiter, app.RateLimits, ipCfg)

	if cfg.HTTP != nil {
		if err := router.Build(cfg.HTTP, globalMiddleware...); err != nil {
			return nil, err
		}
	}
	logBootSummary(ctx, tel.Named("boot").Logger, order, len(router.Routes()), cfg)
	return ac, nil
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
}

// ResolvePluginOrder builds a dependency DAG from every plugin's declared
// PluginMeta.Dependencies, resolves it via graph.KahnSort, and returns
// plugins in an order where every hard dependency precedes its dependant.
func ResolvePluginOrder(plugins []types.Plugin) ([]string, error) {
	byName := make(map[string]types.Plugin, len(plugins))
	metas := make(map[string]types.PluginMeta, len(plugins))

	// Step 1: collect each plugin's declared metadata, reject duplicate names up front
	for _, p := range plugins {
		meta := p.Meta()
		if meta.Name == "" {
			return nil, behemotherr.NewConfigurationError("ResolvePluginOrder", "a plugin returned an empty Meta().Name", nil)
		}
		if _, dup := byName[meta.Name]; dup {
			return nil, behemotherr.NewConfigurationError("ResolvePluginOrder", fmt.Sprintf("plugin name %q registered more than once", meta.Name), nil)
		}
		byName[meta.Name] = p
		metas[meta.Name] = meta
	}

	// Step 2: validate hard dependencies exist before building the graph.
	// A missing optional dependency is skipped (simply no edge).
	for name, meta := range metas {
		for _, dep := range meta.Dependencies {
			if _, exists := metas[dep.Name]; !exists && !dep.Optional {
				return nil, behemotherr.NewConfigurationError("ResolvePluginOrder",
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
	order, cyclePath, ok := types.KahnSort(graphMap, alphabetical)
	if !ok {
		return nil, behemotherr.NewConfigurationError("ResolvePluginOrder",
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
	inner types.HookCatalog
	owner string
}

func (s *scopedHookCatalog) Declare(def types.HookPointDef) error {
	def.Owner = s.owner // overwritten unconditionally — a plugin cannot misattribute a declaration
	return s.inner.Declare(def)
}
func (s *scopedHookCatalog) Lookup(point types.HookPoint) (types.HookPointDef, bool) {
	return s.inner.Lookup(point)
}

func (s *scopedHookCatalog) All() []types.HookPointDef {
	return s.inner.All()
}

type scopedTokenCatalog struct {
	inner types.TokenCatalog
	owner string
}

func (s *scopedTokenCatalog) Declare(def types.TokenKindDef) error {
	def.Owner = s.owner
	return s.inner.Declare(def)
}
func (s *scopedTokenCatalog) Lookup(kind types.TokenKind) (types.TokenKindDef, bool) {
	return s.inner.Lookup(kind)
}

type scopedRateLimitCatalog struct {
	inner types.RateLimitCatalog
	owner string
}

func (s *scopedRateLimitCatalog) DeclareHookRateLimitRule(rule types.HookRateLimitRule) error {
	rule.Owner = s.owner
	return s.inner.DeclareHookRateLimitRule(rule)
}
func (s *scopedRateLimitCatalog) RulesForHook(point types.HookPoint) []types.HookRateLimitRule {
	return s.inner.RulesForHook(point)
}
func (s *scopedRateLimitCatalog) DeclareRouteRateLimitRule(rule types.RouteRateLimitRule) error {
	rule.Owner = s.owner
	return s.inner.DeclareRouteRateLimitRule(rule)
}
func (s *scopedRateLimitCatalog) RulesForRoute() []types.RouteRateLimitRule {
	return s.inner.RulesForRoute()
}

// scopedSchemaRegistry injects the declaring owner into every table and
// contribution, the same way the catalog wrappers above do.
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
	return behemotherr.NewConfigurationError("SchemaRegistry.Freeze", fmt.Sprintf("%q cannot freeze the schema registry", s.owner), nil)
}

func newScopedInitContext(
	hooks *DefaultHookCatalog,
	tokens *DefaultTokenCatalog,
	rl *DefaultRateLimitCatalog,
	schemas schema.Registry,
	owner string,
) *types.PluginInitContext {
	return &types.PluginInitContext{
		Hooks:      &scopedHookCatalog{inner: hooks, owner: owner},
		Tokens:     &scopedTokenCatalog{inner: tokens, owner: owner},
		RateLimits: &scopedRateLimitCatalog{inner: rl, owner: owner},
		Schemas:    &scopedSchemaRegistry{inner: schemas, owner: owner},
	}
}

type DefaultHookRegistry struct {
	mu      sync.Mutex
	catalog types.HookCatalog
	pending map[types.HookPoint][]registeredHandler // unordered until freezeAllHookChains resolves it
	frozen  bool
}

func NewHookRegistry(catalog types.HookCatalog) *DefaultHookRegistry {
	return &DefaultHookRegistry{catalog: catalog, pending: map[types.HookPoint][]registeredHandler{}}
}

func (r *DefaultHookRegistry) register(point types.HookPoint, phase types.HookPhase, plugin string, fn any, opts *types.HookOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return behemotherr.NewConfigurationError("HookRegistry.register", "cannot register after chains have been frozen", nil)
	}
	def, ok := r.catalog.Lookup(point)
	if !ok {
		return behemotherr.NewConfigurationError("HookRegistry.register", fmt.Sprintf("point %q was never declared", point), nil)
	}
	if def.Phase != phase {
		return behemotherr.NewConfigurationError("HookRegistry.register",
			fmt.Sprintf("point %q is phase %q, cannot register a %q handler on it", point, def.Phase, phase), nil)
	}

	// One handler per owner on a point: chain ordering (Before/After,
	// tie-breaks) identifies a handler by its owner's name, so a second one
	// could not be placed. An owner that needs two steps combines them in
	// one handler.
	for _, existing := range r.pending[point] {
		if existing.plugin == plugin {
			return behemotherr.NewConfigurationError("HookRegistry.register",
				fmt.Sprintf("%q already registered a handler on point %q; an owner may register one handler per point", plugin, point), nil)
		}
	}

	rh := registeredHandler{plugin: plugin, handler: fn, priority: types.PriorityNormal}
	if opts != nil {
		rh.priority, rh.before, rh.after = opts.Priority, opts.Before, opts.After
	}
	r.pending[point] = append(r.pending[point], rh)
	return nil
}

// scopedHookRegistry is the types.HookRegistry an owner registers through. It
// injects the owner's name: a plugin's Register(reg HookRegistry) call
// receives one of these, typed as the interface, and can't override `owner`.
// DefaultHookRegistry has no registering methods of its own, so a handler
// can't be registered without an owner.
type scopedHookRegistry struct {
	inner *DefaultHookRegistry
	owner string
}

func (s *scopedHookRegistry) OnBefore(point types.HookPoint, fn types.BeforeHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.BeforeHookPhase, s.owner, fn, opts)
}
func (s *scopedHookRegistry) OnAfter(point types.HookPoint, fn types.AfterHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.AfterHookPhase, s.owner, fn, opts)
}
func (s *scopedHookRegistry) OnFailed(point types.HookPoint, fn types.FailedHookFunc, opts *types.HookOptions) error {
	return s.inner.register(point, types.FailedHookPhase, s.owner, fn, opts)
}

func freezeAllHookChains(catalog types.HookCatalog, registry *DefaultHookRegistry, pluginOrder []string) (map[types.HookPoint][]registeredHandler, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	frozen := make(map[types.HookPoint][]registeredHandler)
	for _, def := range catalog.All() {
		resolved, err := resolvePointOrder(def.Point, registry.pending[def.Point], pluginOrder)
		if err != nil {
			return nil, err
		}
		frozen[def.Point] = resolved
	}

	registry.frozen = true
	return frozen, nil
}

func resolvePointOrder(point types.HookPoint, handlers []registeredHandler, pluginOrder []string) ([]registeredHandler, error) {
	if len(handlers) <= 1 {
		return handlers, nil
	}

	buckets := map[types.HookPriority][]registeredHandler{}
	priorityOf := map[string]types.HookPriority{}

	for _, h := range handlers {
		buckets[h.priority] = append(buckets[h.priority], h)
		priorityOf[h.plugin] = h.priority
	}

	priorities := make([]types.HookPriority, 0, len(buckets))
	for p := range buckets {
		priorities = append(priorities, p)
	}
	sort.Slice(priorities, func(i, j int) bool { return priorities[i] < priorities[j] }) // Highest(-100) first, ascending numeric order

	var result []registeredHandler
	for _, p := range priorities {
		bucket := buckets[p]

		// contradiction check: a Before/After constraint that contradicting bucket ordering is a boot error
		for _, h := range bucket {
			for _, mustBeBefore := range h.before {
				if otherP, ok := priorityOf[mustBeBefore]; ok && otherP < p {
					return nil, behemotherr.NewConfigurationError("HookRegistry.Freeze",
						fmt.Sprintf("point %q: %q wants to run before %q, but %q sits in a higher-priority bucket", point, h.plugin, mustBeBefore, mustBeBefore), nil)
				}
			}
			for _, mustBeAfter := range h.after {
				if otherP, ok := priorityOf[mustBeAfter]; ok && otherP > p {
					return nil, behemotherr.NewConfigurationError("HookRegistry.Freeze",
						fmt.Sprintf("point %q: %q wants to run after %q, but %q sits in a lower-priority bucket", point, h.plugin, mustBeAfter, mustBeAfter), nil)
				}
			}
		}

		if len(bucket) == 1 {
			result = append(result, bucket[0])
			continue
		}
		ordered, err := topoSortBucket(point, bucket, pluginOrder)
		if err != nil {
			return nil, err
		}
		result = append(result, ordered...)
	}
	return result, nil

}

// topoSortBucket resolves handler order within one priority bucket with
// KahnSort, the sort plugin ordering uses. An edge comes from a Before or
// After that names an owner with a handler in the same bucket; a constraint
// naming any other owner adds none. Handlers the edges leave unordered run
// in plugin boot order (pluginOrder, the application last), so a plugin's
// handler runs after those of the plugins it depends on. A cycle is a
// configuration error.
func topoSortBucket(point types.HookPoint, bucket []registeredHandler, pluginOrder []string) ([]registeredHandler, error) {
	byPlugin := make(map[string]registeredHandler, len(bucket))
	for _, h := range bucket {
		byPlugin[h.plugin] = h
	}

	// indexOf gives O(1) lookup into the finalized plugin boot order
	indexOf := make(map[string]int, len(pluginOrder))
	for i, name := range pluginOrder {
		indexOf[name] = i
	}
	registrationOrder := func(a, b string) bool { return indexOf[a] < indexOf[b] }

	graphMap := map[string][]string{}
	for name := range byPlugin {
		graphMap[name] = nil // ensure every handler-plugin appears even with zero constraints
	}

	for _, h := range bucket {
		for _, mustBeBefore := range h.before {
			if _, exists := byPlugin[mustBeBefore]; exists { // constraint naming a plugin outside this bucket/point is a no-op, per the ordering round
				graphMap[h.plugin] = append(graphMap[h.plugin], mustBeBefore)
			}
		}
		for _, mustBeAfter := range h.after {
			if _, exists := byPlugin[mustBeAfter]; exists {
				graphMap[mustBeAfter] = append(graphMap[mustBeAfter], h.plugin)
			}
		}
	}

	sortedNames, cyclePath, ok := types.KahnSort(graphMap, registrationOrder)
	if !ok {
		return nil, behemotherr.NewConfigurationError("HookRegistry.Freeze",
			fmt.Sprintf("point %q: circular handler ordering: %s", point, strings.Join(cyclePath, " -> ")), nil)
	}

	ordered := make([]registeredHandler, len(sortedNames))
	for i, name := range sortedNames {
		ordered[i] = byPlugin[name]
	}
	return ordered, nil
}

func DetectPluginNameConflicts(plugins []types.Plugin) error {
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
		return behemotherr.NewConfigurationError("Router.Mount", conflicts.String(), nil)
	}

	return nil
}

// checkOwnerNames rejects names that would make two owners indistinguishable:
// an application named like core, or a plugin named like core or the
// application. Owner names attribute tables and hook points and order hook
// handlers, so each must mean one thing.
func checkOwnerNames(plugins []types.Plugin, appName string) error {
	if appName == coreOwner {
		return behemotherr.NewConfigurationError("Prepare",
			fmt.Sprintf("AppName %q is reserved for behemoth's own declarations", coreOwner), nil)
	}
	for _, p := range plugins {
		switch name := p.Meta().Name; name {
		case coreOwner:
			return behemotherr.NewConfigurationError("Prepare",
				fmt.Sprintf("plugin name %q is reserved for behemoth's own declarations", name), nil)
		case appName:
			return behemotherr.NewConfigurationError("Prepare",
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
func lookup(plugins []types.Plugin, name string) types.Plugin {
	for _, p := range plugins {
		if p.Meta().Name == name {
			return p
		}
	}
	return nil
}

// dbCounterStore counts in the rate_limits table: the AtomicIncrementer used
// when no KeyValueStorage provides one.
type dbCounterStore struct{ store *store.Store }

func (s *dbCounterStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, time.Time, error) {
	return s.store.IncrementRateLimit(ctx, key, ttl)
}

// DefaultRateLimiter evaluates the declared rules. limiters holds the Limiter
// Boot built for each algorithm, over the counter storage it resolved
// (newLimiters); a rule's own Limiter takes its place.
type DefaultRateLimiter struct {
	catalog  types.RateLimitCatalog
	limiters map[types.RateLimitAlgorithm]types.Limiter
	cfg      types.RateLimitConfig
	tel      *telemetry.Telemetry
}

// knownAlgorithms are the algorithms a rule may name; newLimiters builds a
// Limiter for each. The catalog rejects any other name at Prepare.
var knownAlgorithms = map[types.RateLimitAlgorithm]bool{types.AlgorithmFixedWindow: true}

// newLimiters builds the Limiter of every known algorithm over counter.
func newLimiters(counter types.AtomicIncrementer) map[types.RateLimitAlgorithm]types.Limiter {
	return map[types.RateLimitAlgorithm]types.Limiter{
		types.AlgorithmFixedWindow: ratelimit.NewFixedWindow(counter),
	}
}

// limiterFor returns the Limiter a rule is evaluated with: its own, or the
// one built for its algorithm, where an empty name means the fixed window.
func (rl *DefaultRateLimiter) limiterFor(rule string, algorithm types.RateLimitAlgorithm, own types.Limiter) (types.Limiter, error) {
	if own != nil {
		return own, nil
	}
	if algorithm == "" {
		algorithm = types.AlgorithmFixedWindow
	}
	if l, ok := rl.limiters[algorithm]; ok {
		return l, nil
	}
	return nil, behemotherr.NewConfigurationError("RateLimiter", fmt.Sprintf("rule %q names the algorithm %q, which has no limiter", rule, algorithm), nil)
}

// checkRateLimitRule is what the catalog requires of a rule's strategy: an
// action that is built, and a known algorithm with a limit that can be
// counted, or a Limiter of its own, whose limit is its own business.
//
// ActionLockout is refused here, at Prepare, and not at request time: a rule
// that asked for a lockout would otherwise get an ordinary rejection and its
// author would not find out. The check comes before the rule's own Limiter
// is accepted, because the lockout is the rate limiter's to enforce, not the
// Limiter's.
func checkRateLimitRule(name string, action types.RateLimitAction, algorithm types.RateLimitAlgorithm, own types.Limiter, limit types.Limit) error {
	switch action {
	case "", types.ActionReject:
	case types.ActionLockout:
		return fmt.Errorf("ratelimit: rule %q uses ActionLockout, which is not built; use ActionReject", name)
	default:
		return fmt.Errorf("ratelimit: rule %q names an unknown Action %q", name, action)
	}
	if own != nil {
		return nil
	}
	if algorithm != "" && !knownAlgorithms[algorithm] {
		return fmt.Errorf("ratelimit: rule %q names an unknown Algorithm %q", name, algorithm)
	}
	if limit.Max <= 0 || limit.Window <= 0 {
		return fmt.Errorf("ratelimit: rule %q needs a Limit with a positive Max and Window", name)
	}
	return nil
}

func (rl *DefaultRateLimiter) CheckHookLimit(ctx context.Context, point types.HookPoint, hctx *types.HookContext) error {
	// UNLIKE RouteRule (single most-specific match wins), every declared
	// HookPointRule for a point is evaluated and must ALL pass — this is
	// deliberate, not an inconsistency: two independent plugins might each
	// have a legitimate, unrelated reason to bound the same point (core's
	// blunt sign-in lockout AND a plugin's separate suspicious-activity
	// counter), and both should apply simultaneously. Routes get
	// override/specificity semantics because a path is normally ONE
	// deliberately-configured policy; hook points get cumulative semantics
	// because multiple concerns legitimately compose there.

	rules := rl.catalog.RulesForHook(point)
	for _, rule := range rules {
		// A rule that has nothing to count this call per (no request for a
		// rule per address, no email on the sign-in) is skipped, not counted
		// under an empty key that every such caller would share.
		ruleKey, ok := rule.KeyFunc(hctx)
		if !ok {
			rl.countCheck(ctx, rule.Name, "skipped")
			continue
		}
		key := rule.Name + ":" + ruleKey
		limiter, err := rl.limiterFor(rule.Name, rule.Algorithm, rule.Limiter)
		if err != nil {
			return err
		}
		if err := rl.evaluate(ctx, rule.Name, key, "", limiter, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
			return err
		}
	}

	return nil
}

func (rl *DefaultRateLimiter) CheckRouteLimit(ctx context.Context, rule types.RouteRateLimitRule, r *http.Request, ipCfg *types.ClientIPConfig) error {
	ip := types.ClientIP(r, ipCfg)
	key := rule.Name + ":" + rule.KeyFunc(r, ip)
	limiter, err := rl.limiterFor(rule.Name, rule.Algorithm, rule.Limiter)
	if err != nil {
		return err
	}
	if err := rl.evaluate(ctx, rule.Name, key, ip, limiter, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
		return err // *behemotherr.DomainError, CategoryRateLimited; ErrorMapper already maps this to 429 + Retry-After, no body parsing or session lookup ever ran
	}

	return nil
}

func (rl *DefaultRateLimiter) GetBestMatchforRoute(ctx context.Context, method, path string) (types.RouteRateLimitRule, bool) {
	rules := rl.catalog.RulesForRoute()
	return types.BestRouteMatch(rules, method, path)
}

// evaluate is the shared core: it asks the rule's limiter and turns a
// refusal into an audit event and a rate-limited error. Both the
// point-scoped path and route-scoped path call through here, so there is
// exactly one place that handles a refusal and a failing counter.
//
// Deferred: ActionLockout. No rule reaches here with it, because the catalog
// rejects it at declaration. When it is built it belongs here, around the
// call to the limiter: check a lockout key before counting and set it on the
// first refusal. action and lockoutFor are passed for that and not read.
func (rl *DefaultRateLimiter) evaluate(
	ctx context.Context,
	name, key string,
	ip string, // the client address, when the caller resolved one; recorded in the audit event
	algo types.Limiter,
	limit types.Limit,
	action types.RateLimitAction,
	lockoutFor time.Duration,
) error {
	var spanAttrs behemoth.M
	if rl.tel.TracingEnabled() {
		spanAttrs = behemoth.M{telemetry.AttrRule: name}
	}
	spanCtx, span := rl.tel.StartSpan(ctx, telemetry.SpanRateLimitCheck, spanAttrs)
	allowed, retryAfter, err := algo.Allow(spanCtx, key, limit)
	result := "allowed"
	switch {
	case err != nil:
		result = "error"
	case !allowed:
		result = "limited"
	}
	if rl.tel.TracingEnabled() {
		span.SetAttributes(behemoth.M{telemetry.AttrResult: result})
	}
	telemetry.FinishSpan(span, err)
	rl.countCheck(ctx, name, result)
	if err != nil {
		return rl.handleStoreFailure(ctx, name, err)
	}

	if !allowed {
		if rl.tel != nil {
			rl.tel.RecordAudit(ctx, telemetry.AuditEvent{
				Type: telemetry.AuditRateLimitExceeded, Outcome: telemetry.OutcomeDenied,
				IPAddress: ip, Metadata: behemoth.M{"rule": name, "key": key},
			})
		}
		return behemotherr.NewRateLimited(name, name, retryAfter)
	}

	return nil
}

// countCheck counts one evaluation of rule: "allowed", "limited", "error"
// when the counter store could not be reached (what happens to the request
// then is RateLimitConfig.FailureMode's decision), or "skipped" when a hook
// rule's KeyFunc said the rule does not apply to the call.
func (rl *DefaultRateLimiter) countCheck(ctx context.Context, rule, result string) {
	if rl.tel.MetricsEnabled() {
		rl.tel.Count(ctx, telemetry.MetricRateLimitChecks, behemoth.M{telemetry.AttrRule: rule, telemetry.AttrResult: result})
	}
}

func (rl *DefaultRateLimiter) handleStoreFailure(ctx context.Context, rule string, err error) error {
	if rl.tel != nil {
		rl.tel.Logger.Warn(ctx, "rate limit store unavailable", telemetry.ErrorFields(err, behemoth.M{"rule": rule}))
	}
	if rl.cfg.FailureMode == types.FailClosed {
		return behemotherr.NewRateLimited(rule, rule, 0)
	}
	return nil // FailOpen request proceeds
}

// CoreDeclareHookPoints declares every hook point behemoth's own code fires:
// the flow points of sign-up, sign-in and sign-out, the session and token
// manager points, and the data points the store fires (coreDataHookPoints).
// A point has one phase, so an operation with a before and an after side is
// two points. Dispatching a point missing from this list is a configuration
// error (DefaultDispatcher.checkPhase).
func CoreDeclareHookPoints(ic *types.PluginInitContext) error {
	points := []types.HookPointDef{
		{Point: hooks.HookSignUpBefore, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookSignUpAfter, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: hooks.HookSignUpFailed, Owner: coreOwner, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},

		{Point: hooks.HookSignInBefore, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookSignInCredentialsVerified, Owner: coreOwner, Phase: types.BeforeHookPhase}, // also Before; a distinct checkpoint, not signIn's "after"
		{Point: hooks.HookSignInAfter, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: hooks.HookSignInFailed, Owner: coreOwner, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},

		{Point: hooks.HookSignOutBefore, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookSignOutAfter, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},

		// fired by the session manager
		{Point: hooks.HookSessionBeforeCreate, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookSessionAfterCreate, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: hooks.HookSessionBeforeRevoke, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookSessionAfterRevoke, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},

		// fired by the token manager
		{Point: hooks.HookTokenBeforeIssue, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookTokenAfterIssue, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: hooks.HookTokenConsumed, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{}},
		{Point: hooks.HookTokenFailed, Owner: coreOwner, Phase: types.FailedHookPhase, Audit: &types.AuditSpec{}},

		// data hooks the store fires (see coreDataHookPoints)
		{Point: hooks.HookUserBeforeCreate, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookUserAfterCreate, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{Type: telemetry.AuditUserCreated}}, // written in the write's transaction
		{Point: hooks.HookUserBeforeUpdate, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookUserAfterUpdate, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{Type: telemetry.AuditUserUpdated}}, // written in the write's transaction
		// fired once the write's transaction has committed
		{Point: hooks.HookUserCreated, Owner: coreOwner, Phase: types.AfterHookPhase},
		{Point: hooks.HookUserUpdated, Owner: coreOwner, Phase: types.AfterHookPhase},
		// a delete: Store.DeleteUser, with the user's sessions, accounts and tokens
		{Point: hooks.HookUserBeforeDelete, Owner: coreOwner, Phase: types.BeforeHookPhase},
		{Point: hooks.HookUserAfterDelete, Owner: coreOwner, Phase: types.AfterHookPhase, Audit: &types.AuditSpec{Type: telemetry.AuditUserDeleted}}, // written in the delete's transaction
		{Point: hooks.HookUserDeleted, Owner: coreOwner, Phase: types.AfterHookPhase},
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
func CoreDeclareSchema(ic *types.PluginInitContext) error {
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
	} {
		if err := ic.Schemas.Declare(d.model, d.table); err != nil {
			return err
		}
	}
	return nil
}

// RuleSignInRoute and RuleSignUpRoute are the names of core's rate-limit
// rules on the email sign-in and sign-up routes. An application or plugin
// that wants another limit on one of them declares a rule for the same method
// and path with a more specific match, or the same one with Disabled set.
const (
	RuleSignInRoute = "core.signin.route"
	RuleSignUpRoute = "core.signup.route"
)

// CoreDeclareRateLimitRules declares the limits core applies without being
// asked: ten attempts a minute per client address on sign-in, and the same
// on sign-up. The two count separately.
//
// The limits are per address and not per account. On sign-in that slows one
// client guessing passwords and does not let anyone lock a user out by
// failing on purpose. On sign-up it bounds how fast one client can create
// accounts and make the server hash passwords.
//
// There is no password-reset route yet, and so no rule for one.
func CoreDeclareRateLimitRules(ic *types.PluginInitContext) error {
	byAddress := func(r *http.Request, ip string) string { return ip }
	coreRules := []types.RouteRateLimitRule{
		{
			Name:      RuleSignInRoute,
			Method:    http.MethodPost,
			Path:      "/sign-in/email",
			KeyFunc:   byAddress,
			Limit:     types.Limit{Max: 10, Window: time.Minute},
			Algorithm: types.AlgorithmFixedWindow,
			Action:    types.ActionReject,
			Owner:     "core",
		},
		{
			Name:      RuleSignUpRoute,
			Method:    http.MethodPost,
			Path:      "/sign-up/email",
			KeyFunc:   byAddress,
			Limit:     types.Limit{Max: 10, Window: time.Minute},
			Algorithm: types.AlgorithmFixedWindow,
			Action:    types.ActionReject,
			Owner:     "core",
		},
	}
	for _, r := range coreRules {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(r); err != nil {
			return err
		}
	}
	return nil
}

// resolveRateLimitStore picks where counters are kept: the key-value storage
// when it can count atomically (the Redis adapter), otherwise the
// rate_limits table.
func resolveRateLimitStore(kv behemoth.KeyValueStorage, st *store.Store) (types.AtomicIncrementer, error) {
	if kv != nil {
		if inc, ok := kv.(types.AtomicIncrementer); ok {
			return inc, nil
		}
	}
	return &dbCounterStore{store: st}, nil
}

type DefaultRateLimitCatalog struct {
	frozen      bool
	mu          sync.RWMutex
	hookCatalog types.HookCatalog // read-only reference, for cross-validating Point at Declare time

	rules      map[types.HookPoint][]types.HookRateLimitRule
	routeRules []types.RouteRateLimitRule
	names      map[string]bool
}

func NewRateLimitCatalog(hooks types.HookCatalog) *DefaultRateLimitCatalog {
	return &DefaultRateLimitCatalog{
		hookCatalog: hooks,
		rules:       map[types.HookPoint][]types.HookRateLimitRule{},
		names:       map[string]bool{},
	}
}

func (c *DefaultRateLimitCatalog) DeclareHookRateLimitRule(rule types.HookRateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.frozen {
		return errors.New("ratelimitcatalog: cannot Declare after boot has completed")
	}

	if rule.Name == "" {
		return errors.New("ratelimit: rule must have a Name")
	}
	if rule.Owner == "" {
		return fmt.Errorf("ratelimit: rule %q missing Owner", rule.Name)
	}
	if c.names[rule.Name] {
		return fmt.Errorf("ratelimit: rule %q already declared", rule.Name)
	}
	if err := checkRateLimitRule(rule.Name, rule.Action, rule.Algorithm, rule.Limiter, rule.Limit); err != nil {
		return err
	}

	// cross-validation: the point must already exist (declared by core, or by an earlier-in-dependency-order plugin, or by
	// this plugin earlier in its own Declare() call), and it must specifically be a Before-phase point, since
	// RunBefore is the only place this rule will ever be consulted.
	def, ok := c.hookCatalog.Lookup(rule.Point)
	if !ok {
		return fmt.Errorf("ratelimitcatalog: rule %q targets undeclared hook point %q", rule.Name, rule.Point)
	}
	if def.Phase != types.BeforeHookPhase {
		return fmt.Errorf("ratelimitcatalog: rule %q targets point %q (phase %q) - rate-limit rules may only target Before-phase points", rule.Name, rule.Point, def.Phase)
	}

	c.names[rule.Name] = true
	c.rules[rule.Point] = append(c.rules[rule.Point], rule)
	return nil
}

func (c *DefaultRateLimitCatalog) RulesForHook(point types.HookPoint) []types.HookRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[point] // safe to return directly post-boot
}

func (c *DefaultRateLimitCatalog) DeclareRouteRateLimitRule(rule types.RouteRateLimitRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.frozen {
		return errors.New("ratelimitcatalog: cannot DeclareRouteRateLimitRule after boot has completed")
	}

	if rule.Name == "" {
		return errors.New("ratelimitcatalog: route rule must have a Name")
	}
	if rule.Owner == "" {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Owner", rule.Name)
	}
	if c.names[rule.Name] {
		return fmt.Errorf("ratelimitcatalog: rule name %q already declared", rule.Name)
	}
	if !rule.Disabled {
		if err := checkRateLimitRule(rule.Name, rule.Action, rule.Algorithm, rule.Limiter, rule.Limit); err != nil {
			return err
		}
	}
	if rule.Path == "" {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Path", rule.Name)
	}
	if rule.Method == "" {
		rule.Method = "*"
	}

	c.names[rule.Name] = true
	c.routeRules = append(c.routeRules, rule)
	return nil
}

func (c *DefaultRateLimitCatalog) RulesForRoute() []types.RouteRateLimitRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.routeRules // safe to hand out directly post-freeze
}

func (c *DefaultRateLimitCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

type DefaultHookCatalog struct {
	mu     sync.RWMutex
	points map[types.HookPoint]types.HookPointDef
	frozen bool
}

func NewDefaultHookCatalog() *DefaultHookCatalog {
	return &DefaultHookCatalog{points: map[types.HookPoint]types.HookPointDef{}}
}

func (c *DefaultHookCatalog) Declare(def types.HookPointDef) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return behemotherr.NewConfigurationError("HookCatalog.Declare", "cannot Declare after boot has completed", nil)
	}
	if def.Point == "" {
		return behemotherr.NewConfigurationError("HookCatalog.Declare", "HookPointDef.Point must not be empty", nil)
	}
	if def.Owner == "" {
		return behemotherr.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q missing Owner", def.Point), nil)
	}
	if def.Phase != types.BeforeHookPhase && def.Phase != types.AfterHookPhase && def.Phase != types.FailedHookPhase {
		return behemotherr.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q declared with invalid or missing Phase %q", def.Point, def.Phase), nil)
	}
	if existing, dup := c.points[def.Point]; dup {
		return behemotherr.NewConfigurationError("HookCatalog.Declare", fmt.Sprintf("point %q already declared by %q, cannot redeclare from %q", def.Point, existing.Owner, def.Owner), nil)
	}
	c.points[def.Point] = def
	return nil
}

func (c *DefaultHookCatalog) Lookup(point types.HookPoint) (types.HookPointDef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	def, ok := c.points[point]
	return def, ok
}

func (c *DefaultHookCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

// All is consumed only by freezeAllHookChains, to know the full universe of
// declared points, including ones with zero registered handlers, which
// still need an empty (not missing) entry in frozenChains.
func (c *DefaultHookCatalog) All() []types.HookPointDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]types.HookPointDef, 0, len(c.points))
	for _, def := range c.points {
		out = append(out, def)
	}
	return out
}

type registeredHandler struct {
	plugin   string
	priority types.HookPriority
	before   []string
	after    []string
	handler  any // BeforeHookFunc | AfterHookFunc | FailedHookFunc, resolved by the point's declared Phase
}

type DefaultDispatcher struct {
	catalog      types.HookCatalog
	frozenChains map[types.HookPoint][]registeredHandler
	rateLimiter  types.RateLimiter // nil-safe; a deployment with no declared point rules simply skips this
	tel          *telemetry.Telemetry
	// ipCfg resolves the client address recorded in audit events, the same
	// way sessions and route rate limits resolve it. Boot sets it.
	ipCfg *types.ClientIPConfig
}

func NewDefaultDispatcher(
	catalog types.HookCatalog,
	frozenChains map[types.HookPoint][]registeredHandler,
	rateLimiter types.RateLimiter,
	tel *telemetry.Telemetry,
) *DefaultDispatcher {
	return &DefaultDispatcher{catalog: catalog, frozenChains: frozenChains, rateLimiter: rateLimiter, tel: telemetry.OrDefault(tel).Named("hooks")}
}

// checkPhase is the single check that point exists and is declared with the
// expected phase. Either failure is a mistake in the code that fires the
// point, not in a handler, and is returned as a configuration error like the
// ones Prepare and Boot return. op names the dispatching method.
func (d *DefaultDispatcher) checkPhase(op string, point types.HookPoint, expected types.HookPhase) (types.HookPointDef, error) {
	def, ok := d.catalog.Lookup(point)
	if !ok {
		return types.HookPointDef{}, behemotherr.NewConfigurationError(op, fmt.Sprintf("point %q was never declared", point), nil)
	}
	if def.Phase != expected {
		return types.HookPointDef{}, behemotherr.NewConfigurationError(op,
			fmt.Sprintf("point %q is phase %q, cannot dispatch as %q", point, def.Phase, expected), nil)
	}
	return def, nil
}

// forPoint returns the context the handlers of point receive: a shallow copy
// of the firing site's with Point and Phase set, so a site can't dispatch one
// point with a context that names another, and a site that leaves them empty
// (a flow reusing one context for all its points) still gives handlers the
// right ones. The copy shares the Values map. A nil map is replaced, so a
// handler's write can't panic; such notes last for this dispatch only.
func forPoint(hctx *types.HookContext, point types.HookPoint, phase types.HookPhase) *types.HookContext {
	c := *hctx
	c.Point, c.Phase = point, phase
	if c.Values == nil {
		c.Values = behemoth.M{}
	}
	return &c
}

func (d *DefaultDispatcher) safeInvokeBefore(hctx *types.HookContext, fn types.BeforeHookFunc, payload behemoth.M, point types.HookPoint, plugin string) (m behemoth.M, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Dispatcher.RunBefore", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
			d.logError(hctx.Ctx, "before-hook panicked", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: plugin})
		}
	}()
	return fn(hctx, payload)
}

// safeInvokeAfter calls an after handler and turns a panic into an internal
// error. It does not log: the caller decides what an error means. RunAfter
// logs it and goes on, RunAfterTx returns it. op names the calling method.
func (d *DefaultDispatcher) safeInvokeAfter(op string, hctx *types.HookContext, fn types.AfterHookFunc, result any, point types.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError(op, fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, result)
}

// RunBefore implements [Dispatcher]. A handler never receives a nil payload
// and the caller never gets one back: a nil input starts the chain as an empty
// map, and a handler that returns a nil map leaves the payload as it was.
func (d *DefaultDispatcher) RunBefore(hctx *types.HookContext, point types.HookPoint, payload behemoth.M) (behemoth.M, error) {
	if _, err := d.checkPhase("Dispatcher.RunBefore", point, types.BeforeHookPhase); err != nil {
		return nil, err
	}
	hctx = forPoint(hctx, point, types.BeforeHookPhase)
	defer d.chainSpan(hctx, point, types.BeforeHookPhase).End()

	// rate-limiting, evaluated before any registered before-hook handler runs
	// rate limiter will handle auditing
	if d.rateLimiter != nil {
		if err := d.rateLimiter.CheckHookLimit(hctx.Ctx, point, hctx); err != nil {
			return nil, err // CategoryRateLimited: indistinguishable, to every existing caller, from a before-hook abort
		}
	}

	mutated := payload
	if mutated == nil {
		mutated = behemoth.M{}
	}
	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.BeforeHookFunc)
		if !ok {
			// Should be structurally impossible. HookRegistry.OnBefore only
			// ever stores a BeforeHookFunc under a Before-phase point. If this
			// fires, it's a bug in the registry itself
			err := behemotherr.NewInternalError("Dispatcher.RunBefore",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Before", point, h.plugin))

			d.logError(hctx.Ctx, "before-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			return nil, err
		}

		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		result, err := d.safeInvokeBefore(handlerCtx, fn, mutated, point, h.plugin)
		d.observeHandler(hctx, point, types.BeforeHookPhase, h.plugin, start, span, err)
		if err != nil {
			return nil, err // abort and propagate error (caller decides whether/how to Fail)
		}
		// A nil map means "no change", so a handler that only validates can
		// return nil, nil. Changes it made to the map in place are kept.
		if result != nil {
			mutated = result
		}
	}
	return mutated, nil
}

// RunAfter implements [Dispatcher]. The only error it returns is checkPhase's;
// handler errors are logged.
func (d *DefaultDispatcher) RunAfter(hctx *types.HookContext, point types.HookPoint, result any) error {
	def, err := d.checkPhase("Dispatcher.RunAfter", point, types.AfterHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, types.AfterHookPhase)
	defer d.chainSpan(hctx, point, types.AfterHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.AfterHookFunc)
		if !ok {
			err := behemotherr.NewInternalError("Dispatcher.RunAfter",
				fmt.Errorf("point %q: handler from %q has wrong type for phase After", point, h.plugin))
			d.logError(hctx.Ctx, "after-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			continue // execution continues since one bad registration must not stop the rest
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeAfter("Dispatcher.RunAfter", handlerCtx, fn, result, point, h.plugin)
		d.observeHandler(hctx, point, types.AfterHookPhase, h.plugin, start, span, err)
		if err != nil {
			// Errors in AfterHookPhase are not propagated
			d.logError(hctx.Ctx, "after-hook failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
		}
	}

	d.countPoint(hctx, point, result, nil)
	d.recordAudit(hctx, point, def, result, nil)
	return nil
}

// RunAfterTx implements [Dispatcher]. It mirrors RunBefore rather than
// RunAfter: the first failing handler ends the chain and its error is
// returned as-is, because the caller (the store) rolls the write back on it.
func (d *DefaultDispatcher) RunAfterTx(hctx *types.HookContext, point types.HookPoint, result any) error {
	def, err := d.checkPhase("Dispatcher.RunAfterTx", point, types.AfterHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, types.AfterHookPhase)
	defer d.chainSpan(hctx, point, types.AfterHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.AfterHookFunc)
		if !ok {
			err := behemotherr.NewInternalError("Dispatcher.RunAfterTx",
				fmt.Errorf("point %q: handler from %q has wrong type for phase After", point, h.plugin))
			d.logError(hctx.Ctx, "after-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			return err
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeAfter("Dispatcher.RunAfterTx", handlerCtx, fn, result, point, h.plugin)
		d.observeHandler(hctx, point, types.AfterHookPhase, h.plugin, start, span, err)
		if err != nil {
			return err // abort and propagate; the write is rolled back
		}
	}
	// The event is written through the write's transaction, so it can't
	// describe a row that was rolled back.
	return d.recordAuditTx(hctx, point, def, result)
}

// Fail implements [Dispatcher]. The only error it returns is checkPhase's;
// handler errors are logged.
func (d *DefaultDispatcher) Fail(hctx *types.HookContext, point types.HookPoint, reason types.FailureReason) error {
	if point == "" {
		return nil // Tier 1 CRUD paths have no Failed-phase point to cascade to (hook taxonomy round)
	}
	def, err := d.checkPhase("Dispatcher.Fail", point, types.FailedHookPhase)
	if err != nil {
		return err
	}
	hctx = forPoint(hctx, point, types.FailedHookPhase)
	defer d.chainSpan(hctx, point, types.FailedHookPhase).End()

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.FailedHookFunc)
		if !ok {
			err := behemotherr.NewInternalError("Dispatcher.Fail",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Failed", point, h.plugin))
			d.logError(hctx.Ctx, "failed-hook type assertion failed", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
			continue
		}
		start := time.Now()
		handlerCtx, span := d.handlerSpan(hctx, point, h.plugin)
		err := d.safeInvokeFailed(handlerCtx, fn, reason, point, h.plugin)
		d.observeHandler(hctx, point, types.FailedHookPhase, h.plugin, start, span, err)
		if err != nil {
			d.logError(hctx.Ctx, "failed-hook handler errored", err, behemoth.M{telemetry.FieldPoint: string(point), telemetry.FieldPlugin: h.plugin})
		}
	}

	d.countPoint(hctx, point, nil, &reason)
	d.recordAudit(hctx, point, def, nil, &reason)
	return nil
}

func (d *DefaultDispatcher) safeInvokeFailed(hctx *types.HookContext, fn types.FailedHookFunc, reason types.FailureReason, point types.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Dispatcher.Fail", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, reason)
}

// chainSpan starts the span of one dispatch and makes hctx, the dispatch's
// own copy of the hook context (forPoint), carry it, so that the handlers,
// the rate-limit check and the audit record nest under it. A point without
// handlers gets no span: most dispatches have none, and an empty span per
// point would bury a trace. The caller ends the span.
func (d *DefaultDispatcher) chainSpan(hctx *types.HookContext, point types.HookPoint, phase types.HookPhase) telemetry.Span {
	if len(d.frozenChains[point]) == 0 || !d.tel.TracingEnabled() {
		return telemetry.SpanFrom(context.Background()) // records nothing
	}
	ctx, span := d.tel.StartSpan(hctx.Ctx, telemetry.SpanHookChain,
		behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPhase: string(phase)})
	hctx.Ctx = ctx
	return span
}

// handlerSpan starts the span of one handler call and returns the hook
// context the handler receives: a copy of hctx carrying the span, so what
// the handler does with HookContext.Ctx nests under it. The copy shares
// hctx's Values. observeHandler ends the span.
func (d *DefaultDispatcher) handlerSpan(hctx *types.HookContext, point types.HookPoint, plugin string) (*types.HookContext, telemetry.Span) {
	if !d.tel.TracingEnabled() {
		return hctx, telemetry.SpanFrom(context.Background())
	}
	ctx, span := d.tel.StartSpan(hctx.Ctx, telemetry.SpanHookHandler,
		behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPlugin: plugin})
	c := *hctx
	c.Ctx = ctx
	return &c, span
}

// observeHandler measures one handler call: its duration, and an error
// count when it returned an error or panicked. On a before point a returned
// error is a veto, which is how a handler refuses an operation; the phase
// attribute tells those apart from the failures of after and failed
// handlers.
func (d *DefaultDispatcher) observeHandler(hctx *types.HookContext, point types.HookPoint, phase types.HookPhase, plugin string, start time.Time, span telemetry.Span, err error) {
	telemetry.FinishSpan(span, err) // a veto is not marked as a failed span; see FinishSpan
	if !d.tel.MetricsEnabled() {
		return
	}
	attrs := behemoth.M{telemetry.AttrPoint: string(point), telemetry.AttrPhase: string(phase), telemetry.AttrPlugin: plugin}
	d.tel.ObserveSince(hctx.Ctx, telemetry.MetricHookDuration, start, attrs)
	if err != nil {
		d.tel.Count(hctx.Ctx, telemetry.MetricHookErrors, attrs)
	}
}

// pointMetric is the counter a core point increments when it is dispatched,
// with the outcome it stands for.
type pointMetric struct {
	name    string
	outcome telemetry.AuditOutcome // "" for a counter that has no outcome attribute
}

// corePointMetrics maps core's after and failed points to the counters of
// the metric catalog, so that the flows and managers firing them are counted
// without reporting anything themselves. A point declared by a plugin has no
// entry: the plugin counts what it needs through AuthContext.Telemetry.
var corePointMetrics = map[types.HookPoint]pointMetric{
	hooks.HookSignInAfter:  {telemetry.MetricSignIn, telemetry.OutcomeSuccess},
	hooks.HookSignInFailed: {telemetry.MetricSignIn, telemetry.OutcomeFailure},
	hooks.HookSignUpAfter:  {telemetry.MetricSignUp, telemetry.OutcomeSuccess},
	hooks.HookSignUpFailed: {telemetry.MetricSignUp, telemetry.OutcomeFailure},

	hooks.HookSessionAfterCreate: {name: telemetry.MetricSessionCreated},
	hooks.HookSessionAfterRevoke: {name: telemetry.MetricSessionRevoked},

	hooks.HookTokenAfterIssue: {name: telemetry.MetricTokenIssued},
	hooks.HookTokenConsumed:   {name: telemetry.MetricTokenConsumed},
	hooks.HookTokenFailed:     {name: telemetry.MetricTokenFailed},
}

// countPoint increments the counter of a core point, if it has one. A
// failure adds its code as the reason, and a token result its kind.
func (d *DefaultDispatcher) countPoint(hctx *types.HookContext, point types.HookPoint, result any, reason *types.FailureReason) {
	metric, ok := corePointMetrics[point]
	if !ok || !d.tel.MetricsEnabled() {
		return
	}
	attrs := behemoth.M{}
	if metric.outcome != "" {
		attrs[telemetry.AttrOutcome] = string(metric.outcome)
	}
	if reason != nil {
		attrs[telemetry.AttrReason] = reason.Code
	}
	if tok, ok := result.(*models.Token); ok {
		attrs[telemetry.AttrKind] = string(tok.Kind)
	}
	d.tel.Count(hctx.Ctx, metric.name, attrs)
}

func (d *DefaultDispatcher) logError(ctx context.Context, msg string, err error, fields behemoth.M) {
	d.tel.Logger.Error(ctx, msg, telemetry.ErrorFields(err, fields))
}

// recordAudit records the audit event of a point dispatched with RunAfter or
// Fail, best effort: the operation is over, so a failed write is logged
// (Telemetry.RecordAudit) and changes nothing.
func (d *DefaultDispatcher) recordAudit(hctx *types.HookContext, point types.HookPoint, def types.HookPointDef, result any, reason *types.FailureReason) {
	if def.Audit == nil {
		return
	}
	d.tel.RecordAudit(hctx.Ctx, d.auditEvent(hctx, point, def, result, reason))
}

// recordAuditTx records the audit event of a data point dispatched with
// RunAfterTx. A recorder that can write through a transaction
// (telemetry.TxAuditRecorder, the database recorder) gets the write's own,
// so the event commits or rolls back with the row, and its error is
// returned to fail the write. Any other recorder can't take part in the
// transaction: it is called once the transaction has committed, best
// effort.
func (d *DefaultDispatcher) recordAuditTx(hctx *types.HookContext, point types.HookPoint, def types.HookPointDef, result any) error {
	if def.Audit == nil {
		return nil
	}
	event := d.auditEvent(hctx, point, def, result, nil)
	if hctx.Tx == nil {
		// Not fired by the store: there is no transaction to join.
		d.tel.RecordAudit(hctx.Ctx, event)
		return nil
	}
	event = telemetry.NormalizeAuditEvent(hctx.Ctx, event)
	inTx, rest := telemetry.SplitAuditRecorders(d.tel.Audit)
	for _, rec := range inTx {
		if err := rec.RecordTx(hctx.Ctx, hctx.Tx.DB(), event); err != nil {
			d.tel.AuditFailed(hctx.Ctx, event.Type, err)
			return fmt.Errorf("audit event %q could not be recorded with the write: %w", event.Type, err)
		}
	}
	if len(rest) > 0 {
		hctx.Tx.AfterCommit(hctx.Ctx, func(ctx context.Context) {
			for _, rec := range rest {
				if err := rec.Record(ctx, event); err != nil {
					d.tel.AuditFailed(ctx, event.Type, err)
				}
			}
		})
	}
	return nil
}

// auditEvent builds the event of one dispatch from what the dispatcher can
// see: the point, its result or failure reason, the operation's Values and
// the request.
//
// Subject, first match: the failure reason's, the result's (auditSubject),
// the operation's user (Values[HookValueUserID]).
//
// Actor, first match: the user of the session the request was authenticated
// with (RequireSession); for a successful operation inside a request, the
// user the subject belongs to, which covers sign-up and sign-in, where no
// session exists yet. Otherwise the actor is anonymous inside a request and
// the system outside one. A failed operation is never attributed to its
// subject: a wrong password for an account was not typed by its owner as far
// as behemoth knows.
func (d *DefaultDispatcher) auditEvent(hctx *types.HookContext, point types.HookPoint, def types.HookPointDef, result any, reason *types.FailureReason) telemetry.AuditEvent {
	event := telemetry.AuditEvent{Type: coalesce(def.Audit.Type, string(point)), Metadata: behemoth.M{}}

	subjectType, subjectID, subjectUser, sessionID := auditSubject(result)
	if reason != nil {
		event.Outcome = telemetry.OutcomeFailure
		maps.Copy(event.Metadata, reason.Metadata)
		event.Metadata["code"] = reason.Code
		if reason.Cause != nil {
			event.Metadata["cause"] = reason.Cause.Error()
		}
		if reason.SubjectID != "" {
			subjectType, subjectID, subjectUser = reason.SubjectType, reason.SubjectID, ""
			if subjectType == models.UserTable {
				subjectUser = subjectID
			}
		}
	}
	if subjectID == "" {
		if id := valueString(hctx.Values, hooks.HookValueUserID); id != "" {
			subjectType, subjectID, subjectUser = models.UserTable, id, id
		}
	}
	event.SubjectType, event.SubjectID = subjectType, subjectID

	if tok, ok := result.(*models.Token); ok {
		event.Metadata[hooks.HookValueTokenKind] = string(tok.Kind)
	}

	if req := hctx.Request; req != nil {
		if req.Request != nil {
			event.IPAddress = types.ClientIP(req.Request, d.clientIPConfig())
			event.UserAgent = req.Request.UserAgent()
		}
		if sess, ok := req.Values["session"].(*models.Session); ok && sess != nil {
			event.ActorID, event.SessionID = sess.UserID, sess.ID
		}
	}
	if event.SessionID == "" {
		event.SessionID = coalesce(sessionID, valueString(hctx.Values, hooks.HookValueSessionID))
	}
	if event.ActorID == "" && reason == nil && hctx.Request != nil {
		event.ActorID = subjectUser
	}
	switch {
	case event.ActorID != "":
		event.ActorType = telemetry.ActorUser
	case hctx.Request != nil:
		event.ActorType = telemetry.ActorAnonymous
	default:
		event.ActorType = telemetry.ActorSystem
	}
	return event
}

// clientIPConfig returns how the client address is resolved. Boot sets the
// router's configuration; a dispatcher built without one trusts no proxy.
func (d *DefaultDispatcher) clientIPConfig() *types.ClientIPConfig {
	if d.ipCfg == nil {
		return &types.ClientIPConfig{}
	}
	return d.ipCfg
}

func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// valueString reads a string from an operation's Values. Ids are stored as
// strings; any other non-nil value is formatted.
func valueString(values behemoth.M, key string) string {
	switch v := values[key].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

// auditSubject reads the subject of an audit event from a hook result:
// its type and id, the user it belongs to (userID, "" when unknown), and
// the session it is or carries (sessionID).
//
// A result that is not a Model says what it is about by implementing
// types.AuditSubject, as the email/password plugin's SignInResult does.
func auditSubject(result any) (subjectType, subjectID, userID, sessionID string) {
	switch r := result.(type) {
	case nil:
		return "", "", "", ""
	case *models.Session:
		return models.SessionTable, r.ID, r.UserID, r.ID
	case types.AuditSubject:
		subjectType, subjectID = r.AuditSubject()
	case behemoth.Model:
		subjectType, subjectID = r.SchemaName(), fmt.Sprint(r.PrimaryKeyField())
	}
	if subjectType == models.UserTable {
		userID = subjectID
	}
	return subjectType, subjectID, userID, ""
}

type DefaultTokenCatalog struct {
	mu     sync.RWMutex
	kinds  map[types.TokenKind]types.TokenKindDef
	frozen bool
}

func NewDefaultTokenCatalog() *DefaultTokenCatalog {
	return &DefaultTokenCatalog{kinds: map[types.TokenKind]types.TokenKindDef{}}
}

func (c *DefaultTokenCatalog) Declare(def types.TokenKindDef) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return behemotherr.NewConfigurationError("TokenCatalog.Declare", "cannot Declare after boot has completed", nil)
	}
	if def.Kind == "" {
		return behemotherr.NewConfigurationError("TokenCatalog.Declare", "TokenKindDef.Kind must not be empty", nil)
	}
	if def.Owner == "" {
		return behemotherr.NewConfigurationError("TokenCatalog.Declare", fmt.Sprintf("kind %q missing Owner", def.Kind), nil)
	}
	if def.Backend != types.TokenBackendDB && def.Backend != types.TokenBackendKV {
		return behemotherr.NewConfigurationError("TokenCatalog.Declare", fmt.Sprintf("kind %q declared with invalid Backend %q", def.Kind, def.Backend), nil)
	}
	if existing, dup := c.kinds[def.Kind]; dup {
		return behemotherr.NewConfigurationError("TokenCatalog.Declare", fmt.Sprintf("kind %q already declared by %q", def.Kind, existing.Owner), nil)
	}
	c.kinds[def.Kind] = def
	return nil
}

func (c *DefaultTokenCatalog) Lookup(kind types.TokenKind) (types.TokenKindDef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	def, ok := c.kinds[kind]
	return def, ok
}

func (c *DefaultTokenCatalog) Freeze() { c.mu.Lock(); c.frozen = true; c.mu.Unlock() }

var _ types.Dispatcher = (*DefaultDispatcher)(nil)
var _ types.RateLimitCatalog = (*DefaultRateLimitCatalog)(nil)
var _ types.RateLimiter = (*DefaultRateLimiter)(nil)
