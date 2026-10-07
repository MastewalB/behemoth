## **Request Routing**

This document explains how a request to one of behemoth's HTTP endpoints reaches a plugin's handler: how plugins declare routes and middlewares, how `Boot` turns them into one route table, how that table is checked for conflicts, how every handler is wrapped, and how the table is handed to the application's HTTP framework.

The code lives in:

- `types/router.go` — `Router`, `RouterConfig`, `FrameworkDriver`, the wrapping pipeline
- `types/plugins.go` — `Plugin`, `Route`, `Middleware`, `RequestContext`, `ResponseRecorder`
- `types/init/init.go` — `Boot`, which drives everything below
- `plugins/adapters/{gin,echo,chi}` — one `FrameworkDriver` per framework, each in its own module

### **Ownership boundary**

`[Convention, important]` Behemoth never owns the HTTP server. The application creates its framework instance (`*gin.Engine`, `*echo.Echo`, `chi.Router`), registers its own routes on it, and hands it to `Boot` wrapped in an adapter:

```go
engine := gin.New()
engine.GET("/", ...) // the application's own routes

ac, err := binit.Boot(ctx, app, db, binit.BootConfig{
	Crypto: cryptoCfg,
	Router: types.RouterConfig{BasePath: "/api/auth"}, // optional; defaults shown
	HTTP:   ginadapter.New(engine),
})
engine.Run(addr)
```

Behemoth adds its routes to that instance and touches nothing else on it — no `engine.Use()`, no 404 handler, no server settings. `BootConfig.HTTP == nil` builds and conflict-checks the route table without mounting it (workers, CLIs that boot but don't serve), so a routing misconfiguration fails `Boot` the same way in every process.

`[Question, resolved]` — "should adapters register themselves through a blank import (`_ ".../adapters/gin"`) and a global driver registry, like `database/sql`?" No. A `database/sql` driver is a stateless factory and the caller still names it (`sql.Open("postgres", …)`); a framework driver needs the application's own instance, which a self-registering `init()` cannot reach. A registry would force either an adapter-owned engine handed back as `any`, or a `(name string, engine any)` pair — no shorter for the user, untyped, and global state shared by every app in the process (including parallel tests). Passing the driver value in `BootConfig.HTTP` is the same one line, type-checked.

---

# **Declaration — what plugins provide**

### **Routes**

```go
type Plugin interface {
	Meta() PluginMeta         // MountPath: optional prefix for this plugin's routes
	Routes() []Route
	Middlewares() []Middleware
	...
}

type Route struct {
	Method      string       // "GET", "POST", ...
	Path        string       // relative to BasePath + MountPath, e.g. "/sign-in/email"
	Handler     HandlerFunc  // func(*RequestContext) error
	Middlewares []Middleware // this route only; Middlewares[0] runs first
}

type Middleware func(next HandlerFunc) HandlerFunc
```

- A route's full path is `path.Join(RouterConfig.BasePath, PluginMeta.MountPath, Route.Path)`. `BasePath` defaults to `/api/auth`; `MountPath` defaults to empty, mounting the plugin flat under `BasePath`. E.g. `BasePath "/api/auth"`, `MountPath "/audit"`, `Path "/status"` → `GET /api/auth/audit/status`.
- **Path parameters** use `{name}` (`/users/{id}`), read in the handler with `rctx.Param("id")`. Adapters translate to their framework's syntax where it differs (gin and echo use `:id`; chi uses `{id}` natively).
- `Route.Middlewares` apply to that route only. `Plugin.Middlewares()` apply to **every** behemoth route — see Global Middleware below.
- `[Convention]` `Boot` calls every plugin's `Init` **before** it calls `Routes()` or `Middlewares()`, so a plugin may build handlers from state it sets up in `Init` (services, `WithLifecycle`-wrapped flows).
- `[Implementation Detail]` `Boot` visits plugins in **dependency order** (`ResolvePluginOrder`) for both `Mount` and middleware collection. Route order within the table has no routing significance — frameworks match by pattern — but it fixes which plugin is reported as the second claimant of a conflict, and it fixes global middleware order.

### **Absolute routes**

`Router.MountAbsolute(owner, routes...)` registers routes at their exact `Path`, bypassing `BasePath` and `MountPath`, for standards-fixed locations that must not move with the developer's API prefix (e.g. a JWKS endpoint at `/.well-known/jwks.json`). They are conflict-checked and wrapped exactly like mounted routes. `[Deferred]` Nothing calls it yet; the JWKS mount in `Boot` is commented out until external JWT lands.

### **Handlers and the request context**

```go
type HandlerFunc func(ctx *RequestContext) error

type RequestContext struct {
	Ctx      context.Context
	Request  *http.Request     // the original request
	Response *ResponseRecorder // buffered; flushed by the adapter after the handler returns
	Auth     *AuthContext      // set by the router, see Wrapping
	Values   behemoth.M        // per-request scratch space shared by middlewares and the handler
	Params   map[string]string // path parameters, filled in by the adapter
}
```

- One `RequestContext` is built per request, by the adapter, and the **same instance** flows through every middleware and the handler, so `Values` set by a middleware are visible to the handler.
- Handlers never touch the framework's response writer. They write into `ResponseRecorder` (`JSON`, `Text`, `Status`, `Cookie`, `Redirect`, `SetHeader`); nothing reaches the client until the adapter calls `Flush` after the whole chain returns. This is what lets a middleware short-circuit with a response without knowing the framework.
- **Two ways to end a request:** write a response and return `nil`, or return an error and let the router map it (see Error Mapping).
- `[Convention, important]` Never do both. `ResponseRecorder.JSON` appends to the buffered body, so a handler that writes a body and then returns an error produces the handler's body followed by the error body, under the error's status.

---

# **Route Table Construction — `Boot`**

After the AuthContext is fully built and every plugin's `Init` has run, `Boot`:

1. Creates the router: `types.NewRouter(cfg.Router, ac)`. The `AuthContext` is captured here, once.
2. For each plugin, in dependency order: `router.Mount(name, meta.MountPath, p.Routes())`, and appends `p.Middlewares()` to the global middleware list.
3. Builds the client-IP configuration from `RouterConfig.TrustedProxies` / `ClientIPHeader` and calls `router.ApplyRateLimiting(rateLimiter, rateLimitCatalog, ipCfg)`.
4. If `cfg.HTTP != nil`: `router.Build(cfg.HTTP, globalMiddleware...)`.

Any error aborts `Boot`. Steps 1–3 run whether or not a driver is configured.

---

# **Duplicate Path Detection**

Conflicts are checked at two levels: between behemoth's own routes, inside the router, and against the application's routes, inside each adapter.

### **Level 1 — within behemoth (`Router.claim`)**

- The router keeps `routeOwners map[routeKey]string`, `routeKey{method, fullPath}` → owning plugin name. Every route passing through `Mount` or `MountAbsolute` is claimed under its **full** path, so two plugins may use the same relative path under different `MountPath`s, and an absolute route conflicts with a mounted route at the same full path.
- A route whose key is already claimed is **not added**. `Mount` keeps going through the rest of that plugin's routes and returns one `ConfigurationError` listing every conflict in the call:

  ```
  route conflicts detected:
    GET /api/auth/status: claimed by both "sessions" and "emailpassword"
  ```

- The first claimant wins and the second is reported, so with dependency ordering a plugin conflicting with one it depends on is always the one named second.
- `[Implementation Detail]` Detection is per `Mount` call: `Boot` stops at the first plugin whose `Mount` fails, so conflicts belonging to later plugins surface on the next run.
- `[Convention]` Keys are compared literally. `GET /users/{id}` and `GET /users/{user_id}` are different keys to the router even though they match the same requests. Whether the framework then rejects the second depends on the framework (Level 2).

### **Level 2 — against the application's routes (adapters)**

Behemoth's routes share the framework instance with the application's, so a behemoth route can collide with one the developer registered. Each framework reacts differently; each adapter turns the reaction into an error from `FrameworkDriver.Mount`, which fails `Boot`:

| Framework | Native reaction to a duplicate | Adapter |
|---|---|---|
| gin | panics at registration | recovers the panic into an error |
| echo v5 | `AddRoute` returns an error (unless `AllowOverwritingRoute`) | uses `AddRoute`, returns the error |
| chi | **silently replaces** the existing handler | walks the existing routes first (`chi.Walk`, which lists a route registered for all methods once per method) and rejects an exact method + pattern match; also recovers chi's panics for invalid patterns |

`[Convention]` The chi pre-check matches patterns exactly, so the same caveat as Level 1 applies: a differently spelled but equivalent pattern is not caught there.

`[Convention]` A rejected mount must never disturb the application's existing route — in chi's case the check runs **before** registering, precisely because registering would already have replaced it.

---

# **Wrapping — the request pipeline**

Every route reaches the framework as a single `HandlerFunc` built from layers added at three points: `Mount`, `ApplyRateLimiting`, and `Build`.

### **Layer order**

From outermost (runs first) to innermost:

```
adapter: build RequestContext (Request, Params, empty Response, Values)
  │
  ├─ withRequestScope         sets rctx.Auth, assigns the request ID,         (Build)
  │                           puts both the ID and rctx on rctx.Ctx
  ├─ withTracing              one span per request; rctx.Ctx carries it         (Build)
  ├─ withMetrics              counts and times the request, by route pattern    (Build)
  ├─ wrapWithErrorMapping     returned error → mapped JSON response             (Build)
  ├─ global middleware[0]                                                      (Build)
  ├─ …
  ├─ global middleware[n]     every plugin's Middlewares(), dependency order    (Build)
  ├─ route rate limit         most specific matching RouteRateLimitRule, if any (ApplyRateLimiting)
  ├─ route middleware[0]                                                       (Mount)
  ├─ …
  ├─ route middleware[n]      Route.Middlewares                                (Mount)
  └─ handler                  Route.Handler
  │
adapter: Response.Flush(writer)  — or 500 if the chain returned an error
```

How each step builds it:

- **`Mount`:** `h = route.Middlewares[0](… route.Middlewares[n](route.Handler))` — iterated in reverse so `Middlewares[0]` ends up outermost and runs first.
- **`ApplyRateLimiting`:** for each route, `BestRouteMatch` picks the single most specific `RouteRateLimitRule` for its method and **match path** (below). No match, or a `Disabled` best match, leaves the route untouched; otherwise `h = rateLimitWrap(h, rule, …)`, which calls `RateLimiter.CheckRouteLimit` and returns its error instead of calling `h` when the limit is exceeded. Resolved once at boot, not per request.

  `[Convention, important]` **Rule paths are relative to `BasePath`.** Core and plugins declare rules without knowing the developer's `BasePath` — core's sign-in rule is `POST /sign-in/email` — so the router records, for every route, the path rules are matched against:

  | Route kind | Match path | Example (`BasePath "/api/auth"`) |
  |---|---|---|
  | mounted (`Mount`) | `MountPath + Route.Path`, i.e. the full path minus `BasePath` | `/api/auth/audit/status` → `/audit/status` |
  | absolute (`MountAbsolute`) | the full path, since it lives outside `BasePath` | `/.well-known/jwks.json` → `/.well-known/jwks.json` |

  A rule written with the full path of a mounted route (`/api/auth/audit/status`) never matches. Changing `BasePath` never requires touching a rule.
- **`Build`:** `h = global[0](… global[n](h))`, then `h = withRequestScope(withTracing(withMetrics(wrapWithErrorMapping(h))))`. `withTracing` and `withMetrics` each return `h` itself when no tracer or metrics sink is configured. `Build` works on a copy of the table, so the router's own routes stay unwrapped by this step.

### **Why this order**

- **Request scope outermost.** `withRequestScope` sets `rctx.Auth` before anything else runs, so every middleware — global or per-route — and the handler can rely on it. The router captured the `AuthContext` in `NewRouter`; adapters build the `RequestContext` without ever knowing about it. It also puts the `RequestContext` on `rctx.Ctx` (`types.ContextWithRequest`), so code that only receives a `context.Context` still knows which request it serves — the store's data hooks read it back with `types.RequestFrom` to give hooks `HookContext.Request`. `[Convention]` Only the request travels through the context, because it is request-scoped by definition; everything else is passed explicitly. A `context.Context` without one (CLI, background job) is a call made outside any request.
- **Request ID with the scope.** `withRequestScope` also assigns the request ID: the one already on the context, else a usable value of the `RouterConfig.RequestIDHeader` request header (default `X-Request-ID`), else a generated one. It stores the ID on `rctx.Ctx` (`telemetry.ContextWithRequestID`) and sets it on the response header. Doing this in the outermost wrapper means every log line written for the request carries the ID, and an error response has the header too. See `docs/internal/telemetry/foundations.md`.
- **Tracing inside the request scope.** `withTracing` needs the request ID for the span, and replaces `rctx.Ctx` with the span's context so middleware and the handler nest under it. See `docs/internal/telemetry/tracing.md`.
- **Metrics outside error mapping.** `withMetrics` reads the status after the mapper has run, so `behemoth.http.requests` reports what the client received. See `docs/internal/telemetry/metrics.md`.
- **Error mapping inside that, outside everything that can fail.** An error from a global middleware, the rate limiter, a route middleware or the handler all become a response through the same mapper. Before this order, only handler errors were mapped; a rate-limit rejection reached the adapter as a raw error.
- **Global middleware outside route-specific layers.** Cross-cutting concerns (request IDs, security headers, CSRF) see every request first, including ones the rate limiter is about to reject.
- **Route middleware innermost.** It is the route's own concern and sees the request last, after everything general has passed.

`[Question, open]` Rate limiting currently runs *after* global middleware, so a rate-limited request still pays for every global middleware. Moving it to just inside error mapping would make rejection cheaper, at the cost of global middleware (e.g. a request logger) no longer seeing rejected requests.

### **Error mapping**

`wrapWithErrorMapping` is the only place a returned error becomes a response, and the place it is logged:

- `RouterConfig.ErrorMapper.Map(err)` returns `(status, body)`. The default, `behemotherr.DefaultErrorMapper`, maps a `*DomainError` through its category (`categoryToStatus`) to a status and `{"error": PublicMessage, "code": Code}`. Anything else — a plain error, or a `DomainError` whose category has no status, such as configuration or internal errors — becomes `500 {"error": "internal server error"}`, so raw error text never reaches a client.
- A `*DomainError` with `RetryAfter > 0` (rate limiting) also sets the `Retry-After` header, in whole seconds.
- The mapped body is written with `rctx.Response.JSON`, and the wrapper returns `nil`.
- The error is logged here, once: at Error when the status is 5xx, at Debug otherwise, with the route's method and pattern, the status and the fields of `telemetry.ErrorFields`. Components below the router return their errors without logging them. See `docs/internal/telemetry/logging.md`.

`[Convention]` Because the mapper always handles the error, **a route reaching an adapter never returns a mapped error**. An error returned to the adapter therefore means the response itself could not be built (e.g. JSON marshalling failed), and every adapter answers it with a bare `500` instead of flushing. Adapters take no error mapper of their own.

---

# **Handoff — `FrameworkDriver`**

```go
type FrameworkDriver interface {
	Mount(routes ...Route) error
}
```

The only seam between behemoth and an HTTP framework. Each adapter, for every route:

1. Translates the path syntax if needed (`{id}` → `:id` for gin and echo).
2. Registers a native handler on the application's instance that builds a `RequestContext` from the native request (`Ctx`, `Request`, `Params`, a fresh `ResponseRecorder`, empty `Values`), calls the route's handler, and then flushes the recorder to the native writer — or writes `500` if the handler returned an error.
3. Returns an error, never panics, when the framework rejects the route (Level 2 above).

| | gin | echo | chi |
|---|---|---|---|
| Constructor | `New(gin.IRoutes)` — engine or `*RouterGroup` | `New(*echo.Echo)` | `New(chi.Router)` — mux, `Group` or `Route` |
| Path params | `{id}` → `:id` | `{id}` → `:id` | unchanged |
| Params from | `c.Params` | `c.PathValues()` | `chi.RouteContext(r.Context()).URLParams` |

Passing a group (gin `RouterGroup`, chi `Group`/`Route`) puts behemoth's routes behind that group's prefix and the group's own middleware — the developer's way to wrap behemoth's routes in application middleware, without behemoth installing anything.

`[Convention]` Adapters stay thin: no error mapping, no auth, no middleware composition. Everything above the native handler is done once in the router, so a new adapter only needs the three steps above.

---

# **Global Middleware**

### **What exists: middleware across behemoth's routes**

`Plugin.Middlewares()` is behemoth-wide: every plugin's list is composed, in dependency order, around **every behemoth route** (mounted and absolute). It is applied by the router during `Build`, never with the framework's `Use()`. Cross-cutting concerns that apply to every auth endpoint — request IDs, security headers, CSRF/origin checks — belong here; without it every plugin would repeat them per route.

`[Convention, important]` Behemoth-wide does **not** mean server-wide. A plugin's global middleware never runs on the application's own routes. Registering it with `engine.Use()` would have done exactly that, which is why the router composes it instead.

Known gaps:

- **Ordering between plugins is implicit.** Global middleware runs in plugin dependency order — a by-product of plugin resolution, not a decision anyone makes. Hooks already have explicit ordering (`HookPriority`, `HookOptions.Before/After`); middleware should get the same model, so "the CSRF check runs before the audit logger" is declared rather than inherited.
- **Scope is all-or-nothing.** A plugin wanting middleware on its own routes only already has `Route.Middlewares`. For anything in between, a declared path pattern could reuse the matcher route rate-limit rules already use (`MatchesMethod` / `MatchesPath` / `BestRouteMatch`). `[Deferred]` until a plugin needs it.

### **What does not exist: plugins intercepting every request to the server**

`[Question, resolved]` — "should a plugin be able to intercept every request to the application, not just behemoth's routes?" **Not automatically.** Three reasons:

1. **Behemoth doesn't own the server.** A middleware installed on the application's instance changes the application's own routes without the developer having written that line: it can add latency, reject requests, consume request bodies, and see every request the application receives. That is surprising, hard to debug, and a security concern for third-party plugins — a developer adopts a plugin for an auth feature, not to grant it all of their traffic.
2. **It is fragile in practice.** In gin, `engine.Use()` only affects routes registered *after* it (each route copies the handler chain at registration), so whether a plugin's middleware covered the application's routes would depend on whether `Boot` ran before or after the application registered them. Each framework has its own variant of this, so the adapters could not promise one behaviour.
3. **It contradicts the ownership boundary.** `BootConfig.HTTP` exists so that the developer's wiring is explicit; behemoth installing middleware on the developer's instance would bring back the hidden setup that decision avoided.

### **Future: exported middleware the developer opts into**

The real needs behind "intercept every request" are things like *make the current user available in my own handlers* or *protect my `/dashboard` routes*. Those are met by plugins **exporting** `types.Middleware` values and the developer applying them where they choose:

```go
// a plugin exports types.Middleware; the adapter bridges it to the framework
engine.Use(ginadapter.Middleware(ac, sessions.LoadSession))              // whole app — the developer's call
admin := engine.Group("/admin", ginadapter.Middleware(ac, sessions.RequireAuth))

func handler(c *gin.Context) {
	user, ok := ginadapter.CurrentUser(c) // values set by the middleware, through typed accessors
}
```

Implementation outline:

1. **A bridge per adapter** — `Middleware(ac *types.AuthContext, mw types.Middleware)` returning the framework's native middleware (`gin.HandlerFunc`, `echo.MiddlewareFunc`, `func(http.Handler) http.Handler` for chi). It builds a `RequestContext` with `Auth` set, runs `mw` with a `next` that continues the native chain, and stores the `RequestContext` on the native context (`c.Set`, `c.Set`, `context.WithValue`). If `mw` returns without calling `next`, the bridge flushes the middleware's `Response` and aborts the native chain; if it returns an error, the bridge maps it with the same `ErrorMapper` the router uses, so an application route rejected by a behemoth middleware answers exactly like a behemoth route would.
2. **Typed accessors per adapter** — `CurrentUser(c)`, `Session(c)`, … read what the middleware stored, so application handlers never handle `RequestContext` or untyped `Values`.
3. **A `net/http` form in core** — `func(http.Handler) http.Handler` built on the same bridge logic, covering chi and the standard library's `ServeMux` without a framework-specific adapter; framework adapters can wrap it where their native type differs.
4. **Shared `RequestContext` with behemoth's own routes is not required.** The bridge serves application routes; behemoth's routes keep building their context in the adapter's route handler. Anything both need (session lookup) lives in the plugin's service, called from both.

`[Convention]` Plugins provide the middleware; only the developer decides where it runs.
