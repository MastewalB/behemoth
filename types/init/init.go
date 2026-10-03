package types

import (
	"context"
	"errors"
	"fmt"
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

	// Schema declares the application's own tables under owner "app". It
	// runs after every plugin has declared, so it can also extend plugin
	// tables (e.g. a column on "users"). nil = no application tables.
	Schema func(reg schema.Registry) error

	// Migrations are hand-authored migrations, ordered among generated
	// operations by their DependsOn. Each is emitted into exactly one
	// generated migration, recorded there by Name; names are therefore
	// permanent and must never be reused.
	Migrations []core.CustomMigration
}

// PreparedApp is the connection-free result of Prepare: every catalog and
// the schema registry, frozen, plus the SchemaResolver derived from them.
// Build storage adapters and migration drivers with Resolver, then hand the
// adapter to Boot.
type PreparedApp struct {
	Order      []string
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
	coreIC := newScopedInitContext(hookCatalog, tokenCatalog, rateLimitCatalog, schemaRegistry, "core")
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
		if err := cfg.Schema(&scopedSchemaRegistry{inner: schemaRegistry, owner: "app"}); err != nil {
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
	Telemetry *types.Telemetry

	RateLimit types.RateLimitConfig
	Session   types.SessionConfig
	Token     types.TokenConfig

	// Router configures behemoth's routes: base path, error mapping and
	// client-IP resolution. Zero value = documented defaults.
	Router types.RouterConfig

	// HTTP mounts behemoth's routes onto the application's framework
	// instance, e.g. ginadapter.New(engine). nil = routes are built and
	// checked but not served (workers, CLIs).
	HTTP types.FrameworkDriver
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
	plugins, order := app.plugins, app.Order
	kv := cfg.KV

	tel := cfg.Telemetry
	if tel == nil {
		tel = types.NewTelemetry(nil, nil, nil)
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

	frozenChains, err := freezeAllHookChains(app.Hooks, hookRegistry, order)
	if err != nil {
		return nil, err
	}

	// Counters fire no data hooks, so they get a store of their own: the
	// one plugins use is built later, from the dispatcher this feeds.
	counterStore, err := resolveRateLimitStore(kv, store.New(db, store.WithSchema(app.Resolver))) // backend selection, below
	if err != nil {
		return nil, err
	}
	rateLimiter := &DefaultRateLimiter{catalog: app.RateLimits, store: counterStore, cfg: cfg.RateLimit, tel: tel}
	dispatcher := &DefaultDispatcher{catalog: app.Hooks, frozenChains: frozenChains, rateLimiter: rateLimiter, tel: tel}

	ac := &types.AuthContext{
		DB:          db,
		KV:          kv,
		Dispatcher:  dispatcher,
		RateLimiter: rateLimiter,
		Crypto:      cryptoSuite,
		Telemetry:   *tel,
	}
	// The store's data hooks dispatch with ac, and the managers persist
	// through the store, so they are built in that order.
	ac.Store = store.New(db, store.WithHooks(dataHooks{ac: ac, points: coreDataHookPoints}), store.WithSchema(app.Resolver),
		store.WithEncryptor(cryptoSuite.AtRest))
	ac.TokenManager = transport.NewDefaultTokenManager(ac.Store, kv, app.Tokens, cryptoSuite, dispatcher, cfg.Token)
	ac.SessionManager = transport.NewSessionManager(ac.Store, kv, cryptoSuite, cfg.Session, dispatcher, tel)

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
	ipCfg, err := types.NewClientConfig(cfg.Router.TrustedProxies, cfg.Router.ClientIPHeader)
	if err != nil {
		return nil, err
	}
	router.ApplyRateLimiting(rateLimiter, app.RateLimits, ipCfg)

	if cfg.HTTP != nil {
		if err := router.Build(cfg.HTTP, globalMiddleware...); err != nil {
			return nil, err
		}
	}
	return ac, nil
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

	rh := registeredHandler{plugin: plugin, handler: fn, priority: types.PriorityNormal}
	if opts != nil {
		rh.priority, rh.before, rh.after = opts.Priority, opts.Before, opts.After
	}
	r.pending[point] = append(r.pending[point], rh)
	return nil
}
func (r *DefaultHookRegistry) OnBefore(point types.HookPoint, fn types.BeforeHookFunc, opts *types.HookOptions) error {
	return r.register(point, types.BeforeHookPhase, "", fn, opts) // owner filled in by scopedHookRegistry below, never left blank in practice
}
func (r *DefaultHookRegistry) OnAfter(point types.HookPoint, fn types.AfterHookFunc, opts *types.HookOptions) error {
	return r.register(point, types.AfterHookPhase, "", fn, opts)
}
func (r *DefaultHookRegistry) OnFailed(point types.HookPoint, fn types.FailedHookFunc, opts *types.HookOptions) error {
	return r.register(point, types.FailedHookPhase, "", fn, opts)
}

// scopedHookRegistry injects the registering plugin's identity. A plugin's Register(reg HookRegistry) call receives one
// of these, typed as the interface, and can't override `owner`.
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

// topoSortBucket resolves handler order within one priority bucket, reusing
// KahnSort exactly as specified. Ties (no Before/After edge between
// two handlers) resolve alphabetically by the plugin name
// KahnSort's fixed signature has no room for a registration-
// order comparator, so this deliberately matches plugin-level ordering's
// tie-break rather than inventing a second mechanism.
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

func (s *dbCounterStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.store.IncrementRateLimit(ctx, key, ttl)
}

type DefaultRateLimiter struct {
	catalog types.RateLimitCatalog
	store   types.AtomicIncrementer
	cfg     types.RateLimitConfig
	tel     *types.Telemetry
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
		key := rule.Name + ":" + rule.KeyFunc(hctx)

		if err := rl.evaluate(ctx, rule.Name, key, rule.Algorithm, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
			return err
		}
	}

	return nil
}

func (rl *DefaultRateLimiter) CheckRouteLimit(ctx context.Context, rule types.RouteRateLimitRule, r *http.Request, ipCfg *types.ClientIPConfig) error {
	ip := types.ClientIP(r, ipCfg)
	key := rule.Name + ":" + rule.KeyFunc(r, ip)

	if err := rl.evaluate(ctx, rule.Name, key, rule.Algorithm, rule.Limit, rule.Action, rule.LockoutFor); err != nil {
		return err // *behemotherr.DomainError, CategoryRateLimited; ErrorMapper already maps this to 429 + Retry-After, no body parsing or session lookup ever ran
	}

	return nil
}

func (rl *DefaultRateLimiter) GetBestMatchforRoute(ctx context.Context, method, path string) (types.RouteRateLimitRule, bool) {
	rules := rl.catalog.RulesForRoute()
	return types.BestRouteMatch(rules, method, path)
}

// evaluate is the shared core that touches the
// AtomicIncrementer store and compares against Limit.Max. Both the
// point-scoped path and route-scoped path call through here, so there is exactly one
// increment/compare/lockout implementation in the whole pillar.
func (rl *DefaultRateLimiter) evaluate(
	ctx context.Context,
	name, key string,
	algo types.Limiter,
	limit types.Limit,
	action types.RateLimitAction,
	lockoutFor time.Duration,
) error {
	allowed, retryAfter, err := algo.Allow(ctx, key, limit)
	if err != nil {
		return rl.handleStoreFailure(ctx, name, err)
	}

	if !allowed {
		if rl.tel != nil {
			rl.tel.Audit.Record(ctx, types.AuditEvent{Type: "ratelimit.exceeded", Metadata: behemoth.M{"rule": name, "key": key}, Timestamp: time.Now()})
		}
		if action == types.ActionLockout && lockoutFor > 0 {
			retryAfter = lockoutFor
		}
		return behemotherr.NewRateLimited(name, name, retryAfter)
	}

	return nil
}

func (rl *DefaultRateLimiter) handleStoreFailure(ctx context.Context, rule string, err error) error {
	if rl.tel != nil {
		rl.tel.Logger.Warn(ctx, "rate limit store unavailable", behemoth.M{"rule": rule, "error": err.Error()})
	}
	if rl.cfg.FailureMode == types.FailClosed {
		return behemotherr.NewRateLimited(rule, rule, 0)
	}
	return nil // FailOpen request proceeds
}

func CoreDeclareHookPoints(ic *types.PluginInitContext) error {
	points := []types.HookPointDef{
		// {Point: hooks.HookSignInBefore, Owner: "core", Phase: BeforeHookPhase},
		// {Point: hooks.HookSignInCredentialsVerified, Owner: "core", Phase: BeforeHookPhase}, // also Before; a distinct checkpoint, not signIn's "after"
		// {Point: hooks.HookSignInAfter, Owner: "core", Phase: AfterHookPhase},
		// {Point: hooks.HookSignInFailed, Owner: "core", Phase: FailedHookPhase, Audit: &AuditSpec{}},
		// data hooks the store fires (see coreDataHookPoints)
		{Point: hooks.HookUserBeforeCreate, Owner: "core", Phase: types.BeforeHookPhase},
		{Point: hooks.HookUserAfterCreate, Owner: "core", Phase: types.AfterHookPhase},
		{Point: hooks.HookUserBeforeUpdate, Owner: "core", Phase: types.BeforeHookPhase},
		{Point: hooks.HookUserAfterUpdate, Owner: "core", Phase: types.AfterHookPhase},
		// ...
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
	} {
		if err := ic.Schemas.Declare(d.model, d.table); err != nil {
			return err
		}
	}
	return nil
}

func CoreDeclareRateLimitRules(ic *types.PluginInitContext) error {
	//Declare HookPointRateLimitRules
	// Declare RouteRateLimitRules
	coreRules := []types.RouteRateLimitRule{
		{
			Name:      "core.signin.route",
			Method:    http.MethodPost,
			Path:      "/sign-in/email",
			KeyFunc:   func(r *http.Request, ip string) string { return ip },
			Limit:     types.Limit{Max: 10, Window: time.Minute},
			Algorithm: ratelimit.IdentityLimiter{}, // TODO: real algorithm; allows every request for now
			Action:    types.ActionReject,
			Owner:     "core",
			Disabled:  true,
		},
		// analogous baseline declared for /sign-up/email, /forgot-password
	}
	for _, r := range coreRules {
		if err := ic.RateLimits.DeclareRouteRateLimitRule(r); err != nil {
			return err
		}
	}
	return nil
}

func resolveRateLimitStore(kv behemoth.KeyValueStorage, st *store.Store) (types.AtomicIncrementer, error) {
	if kv != nil {
		if inc, ok := kv.(types.AtomicIncrementer); ok {
			return inc, nil // Redis-backed path — atomic, fast
		}
	}
	return &dbCounterStore{store: st}, nil // KV absent, or lacks native INCR — DB-transactional fallback, still correct
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
	if rule.Algorithm == nil {
		return fmt.Errorf("ratelimit: rule %q missing Algorithm", rule.Name)
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
	if !rule.Disabled && rule.Algorithm == nil {
		return fmt.Errorf("ratelimitcatalog: route rule %q missing Algorithm", rule.Name)
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

var frozenChains map[types.HookPoint][]registeredHandler

type DefaultDispatcher struct {
	catalog      types.HookCatalog
	frozenChains map[types.HookPoint][]registeredHandler
	rateLimiter  types.RateLimiter // nil-safe; a deployment with no declared point rules simply skips this
	tel          *types.Telemetry
}

func NewDefaultDispatcher(
	catalog types.HookCatalog,
	frozenChains map[types.HookPoint][]registeredHandler,
	rateLimiter types.RateLimiter,
	tel *types.Telemetry,
) *DefaultDispatcher {
	return &DefaultDispatcher{catalog: catalog, frozenChains: frozenChains, rateLimiter: rateLimiter, tel: tel}
}

// checkPhase is a single check point for point validity (existing & matching phase)
func (d *DefaultDispatcher) checkPhase(point types.HookPoint, expected types.HookPhase) types.HookPointDef {
	def, ok := d.catalog.Lookup(point)
	if !ok {
		panic(fmt.Sprintf("dispatcher: point %q was never declared", point))
	}
	if def.Phase != expected {
		panic(fmt.Sprintf("dispatcher: point %q is phase %q, cannot dispatch as %q", point, def.Phase, expected))
	}
	return def
}

func (d *DefaultDispatcher) safeInvokeBefore(hctx *types.HookContext, fn types.BeforeHookFunc, payload behemoth.M, point types.HookPoint, plugin string) (m behemoth.M, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Dispatcher.RunBefore", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
			d.logError(hctx.Ctx, "before-hook panicked", err, behemoth.M{"point": string(point), "plugin": plugin})
		}
	}()
	return fn(hctx, payload)
}

func (d *DefaultDispatcher) safeInvokeAfter(hctx *types.HookContext, fn types.AfterHookFunc, result any, point types.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Dispatcher.RunAfter", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, result)
}

// RunBefore implements [Dispatcher].
func (d *DefaultDispatcher) RunBefore(hctx *types.HookContext, point types.HookPoint, payload behemoth.M) (behemoth.M, error) {
	d.checkPhase(point, types.BeforeHookPhase)

	// rate-limiting, evaluated before any registered before-hook handler runs
	// rate limiter will handle auditing
	if d.rateLimiter != nil {
		if err := d.rateLimiter.CheckHookLimit(hctx.Ctx, point, hctx); err != nil {
			return nil, err // CategoryRateLimited: indistinguishable, to every existing caller, from a before-hook abort
		}
	}

	// Existing before-hook chain, unchanged.
	mutated := payload
	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.BeforeHookFunc)
		if !ok {
			// Should be structurally impossible. HookRegistry.OnBefore only
			// ever stores a BeforeHookFunc under a Before-phase point. If this
			// fires, it's a bug in the registry itself
			err := behemotherr.NewInternalError("Dispatcher.RunBefore",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Before", point, h.plugin))

			d.logError(hctx.Ctx, "before-hook type assertion failed", err, behemoth.M{"point": string(point), "plugin": h.plugin})
			return nil, err
		}

		result, err := d.safeInvokeBefore(hctx, fn, mutated, point, h.plugin)
		if err != nil {
			return nil, err // abort and propagate error (caller decides whether/how to Fail)
		}
		mutated = result

	}
	return mutated, nil
}

// RunAfter implements [Dispatcher].
func (d *DefaultDispatcher) RunAfter(hctx *types.HookContext, point types.HookPoint, result any) {
	def := d.checkPhase(point, types.AfterHookPhase)

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.AfterHookFunc)
		if !ok {
			err := behemotherr.NewInternalError("Dispatcher.RunAfter",
				fmt.Errorf("point %q: handler from %q has wrong type for phase After", point, h.plugin))
			d.logError(hctx.Ctx, "after-hook type assertion failed", err, behemoth.M{"point": string(point), "plugin": h.plugin})
			continue // execution continues since one bad registration must not stop the rest
		}
		if err := d.safeInvokeAfter(hctx, fn, result, point, h.plugin); err != nil {
			// Errors in AfterHookPhase are not propagated
			d.logError(hctx.Ctx, "after-hook failed", err, behemoth.M{"point": string(point), "plugin": h.plugin})
		}
	}

	d.recordAudit(hctx, point, def, result, nil)
}

// Fail implements [Dispatcher].
func (d *DefaultDispatcher) Fail(hctx *types.HookContext, point types.HookPoint, reason types.FailureReason) {
	if point == "" {
		return // Tier 1 CRUD paths have no Failed-phase point to cascade to (hook taxonomy round)
	}
	def := d.checkPhase(point, types.FailedHookPhase)

	for _, h := range d.frozenChains[point] {
		fn, ok := h.handler.(types.FailedHookFunc)
		if !ok {
			err := behemotherr.NewInternalError("Dispatcher.Fail",
				fmt.Errorf("point %q: handler from %q has wrong type for phase Failed", point, h.plugin))
			d.logError(hctx.Ctx, "failed-hook type assertion failed", err, behemoth.M{"point": string(point), "plugin": h.plugin})
			continue
		}
		if err := d.safeInvokeFailed(hctx, fn, reason, point, h.plugin); err != nil {
			d.logError(hctx.Ctx, "failed-hook handler errored", err, behemoth.M{"point": string(point), "plugin": h.plugin})
		}
	}

	d.recordAudit(hctx, point, def, nil, &reason)

}

func (d *DefaultDispatcher) safeInvokeFailed(hctx *types.HookContext, fn types.FailedHookFunc, reason types.FailureReason, point types.HookPoint, plugin string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Dispatcher.Fail", fmt.Errorf("panic in %q's handler on %q: %v", plugin, point, r))
		}
	}()
	return fn(hctx, reason)
}

func (d *DefaultDispatcher) logError(ctx context.Context, msg string, err error, fields behemoth.M) {
	fields["error"] = err
	d.tel.Logger.Error(ctx, msg, fields)
}

func (d *DefaultDispatcher) recordAudit(hctx *types.HookContext, point types.HookPoint, def types.HookPointDef, result any, reason *types.FailureReason) {
	if def.Audit == nil {
		return
	}
	meta := behemoth.M{}
	if reason != nil {
		meta["code"] = reason.Code
		if reason.Cause != nil {
			meta["cause"] = reason.Cause.Error() // AuditRecorder's own write path applies redaction (Telemetry round) — nothing extra needed here
		}
	}
	event := types.AuditEvent{
		Type:      coalesce(def.Audit.Type, string(point)),
		ActorID:   actorFrom(hctx),
		SubjectID: subjectFrom(result),
		Metadata:  meta,
		// RequestID: RequestIDFrom(hctx.Ctx),
		Timestamp: time.Now(),
	}
	if err := d.tel.Audit.Record(hctx.Ctx, event); err != nil {
		d.tel.Logger.Warn(hctx.Ctx, "audit record failed", behemoth.M{"point": string(point), "error": err.Error()})
	}
}
func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func actorFrom(hctx *types.HookContext) any {
	if hctx == nil {
		return nil
	}
	return ""
	// return hctx.Values[HookValueUserID] // nil if absent
}

// subjectFrom recognizes the concrete result types hook points actually
// carry today — extend this switch as new result-carrying points are added,
// rather than requiring every AfterHookFunc caller to pre-extract an ID.
func subjectFrom(result any) any {
	switch r := result.(type) {
	case behemoth.Model: // a user, session, token, ... — whatever the point's result is
		return r.PrimaryKeyField()
	// case *behemoth.Session:
	// 	return r.ID
	// case *behemoth.Token:
	// 	return r.ID
	default:
		return nil
	}
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
