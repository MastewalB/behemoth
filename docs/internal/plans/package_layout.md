# Package layout

This document describes the layout Behemoth's packages move to: which package holds what, the order in which packages may import each other, and where each exported identifier of a moving package ends up. It also lists the steps of the move, which leaves behavior unchanged.

**Status:** part 1 done, as of 2026-10-19. Part 2 done, as of 2026-10-21: the HTTP types are in `httpapi`, and `layout_test.go` checks that no package below it serves HTTP. [Implementation steps](#implementation-steps) lists the work, and [Decisions](#decisions) what part 2 settled.

The documents it builds on are:

- [ADR-0007](../decisions/0007-layering-the-packages.md): the layout, and the options weighed against it.
- [`caller.md`](caller.md): the caller plan. Its step 1 is part 1 of this move, and its step 3 removes what keeps the HTTP types in the contracts package.
- [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md): the import rule, which `TestNoServerSideHTTPBelowHTTPAPI` checks now that the HTTP types have a package of their own.
- [`../guidelines/service_ready_components.md`](../guidelines/service_ready_components.md): a new dependency gets a module of its own.

## Context

`types` started as the place for Behemoth's core type definitions. It now holds four kinds of code:

- **The plugin contracts,** such as `AuthContext`, `HookContext`, `Dispatcher`, `SessionManager`, and `Plugin`.
- **Implementations,** such as `Router`, `OriginCheck`, `TrustedOrigins`, `ClientIP`, `ResponseRecorder`, `NewPublicView`, `RequireSession`, `WriteSignIn`, and `KahnSort`.
- **The HTTP types,** such as `RequestContext`, `Route`, `Middleware`, and the route rate-limit rules.
- **Aliases of types that live elsewhere:** 22 type aliases and 8 constants of `types/cryptotypes`, and `Token`, `TokenKind`, and `CodeKind` of `models`.

The crypto aliases come from the import graph. `types` imports `store`, because `AuthContext.Store` and `HookContext.Tx` are a `*store.Store`, so `store` can't import `types`. The crypto contracts that the store needs moved below `types`, to `types/cryptotypes`, and came back into `types` as aliases.

The packages around it have problems of their own:

- `types/init` holds the composition root, `Prepare` and `Boot`, and declares `package types`, so every importer renames it (`bmth`). Its `init.go` is 2,012 lines: the composition root, the dispatcher, three catalogs, the rate limiter, and the audit event builder.
- `crypto` imports `types` for the aliases, for `Environment`, and for `RequestContext` and `Route`, because the key set route is an HTTP handler inside `crypto`.
- `migration/core` imports `types` for `KahnSort` only.
- `errors` has the name of a standard library package, so all 124 files that import it rename it (`behemotherr`).
- `transport` holds the session, token, and code managers, while the caller plan uses "transport" for HTTP or another protocol.
- `types.SessionState` duplicates `models.SessionState`.
- `types/database.go`, `types/models.go`, the root `main.go`, `session.go`, and `transport.go`, and `middleware/` hold no code.

"`types` mixes contracts, implementations and HTTP, and its layering forces aliases" in `docs/ongoing.md` recorded these until part 1 resolved them.

## Goals

- Each concept has one home and one name: no aliases, and no two types for one thing.
- A package imports only packages below it, so no contract is moved or redeclared to avoid a cycle.
- A plugin author imports one package for the plugin API, and no Behemoth package needs an import alias in Behemoth's own code.
- Implementations sit apart from the contracts they implement.
- The HTTP types get a package of their own, so that a test can check the import rule of `transport_neutral_flows.md`.

## Non-goals

- Changing behavior. Part 1 moves and renames code, and the existing tests are its check.
- Splitting the plugin contracts by domain. [ADR-0007](../decisions/0007-layering-the-packages.md) has the reason.
- Moving each plugin's handlers into a package of their own. [Open questions](#open-questions) lists it.
- Renaming `utils`, `clause`, `models`, `store`, `telemetry`, `outbound`, or `keysource`.

## The layout

### Rows

The table lists the packages in the order they may import each other. A package imports only packages in earlier rows, and, within its own row, only where the last column says so:

| Row | Packages | Imports from Behemoth |
| --- | --- | --- |
| 1 | `clause`, `utils`, `identity`, `storage` | none |
| 2 | `behemoth`, the root package | `clause` |
| 3 | `errs` | the root package |
| 4 | `telemetry` | the root package, `errs`, `identity` |
| 5 | `schema`, `outbound`, `telemetry/telemetrytest`, `telemetry/adapters/otel` | earlier rows |
| 6 | `models`, `crypto` | earlier rows |
| 7 | `store`, `migration`, `keysource`, `storage/adapters` and the storage adapter modules | earlier rows. The storage adapter modules also import `storage/adapters`, and the SQL ones `migration`. |
| 8 | `core` | earlier rows |
| 9 | `core/hooks` | `core` and earlier rows |
| 10 | `auth`, `dispatch`, `ratelimit`, `messaging` | rows 1 to 9 |
| 11 | `httpapi`, in part 2 | rows 1 to 9 |
| 12 | `plugins/*`, the framework adapters included | rows 1 to 9 and 11. `plugins/username` and `plugins/phonenumber` also import `plugins/emailpassword`. |
| 13 | `engine`, `cli`, `cmd/behemoth` | every earlier row. `cli` also imports `engine`, and `cmd/behemoth` imports `cli`. |
| 14 | `examples/*`, `tests` | every earlier row |

A plugin imports no package of row 10. It reaches the implementations through the contracts in `core`, so that an application can replace an implementation without breaking a plugin.

### What each package holds

| Package | Holds | Comes from |
| --- | --- | --- |
| `behemoth` | `M`, `Model`, `Database`, `KeyValueStorage`, and the other storage contracts, as now, and `Environment` | the root package, `types/env.go` |
| `identity` | the caller's types, described in [`caller.md`](caller.md) | new |
| `errs` | the error taxonomy | `errors` |
| `schema` | the schema contracts, the registry, the field types, and the public view | `types/schema`, `types/public_view.go` |
| `crypto` | the crypto contracts and their implementations | `types/cryptotypes`, `crypto` |
| `migration` | the migration engine | `migration/core` |
| `core` | the plugin contracts, and the helpers plugins call over them. Until part 2, also the HTTP types and their implementations. | `types` |
| `core/hooks` | the hook point constants and the `HookValue` keys | `types/hooks` |
| `auth` | the session, token, and code managers, session tokens, and the token catalog. Later also the authenticator and `Access`. | `transport`, `types/init` |
| `dispatch` | the hook catalog, the hook registry, the dispatcher, the data hooks, and the audit event builder | `types/init` |
| `ratelimit` | the rate limiter, its catalog, and the fixed window | `types/init`, `types/ratelimit` |
| `messaging` | the mailer, the SMS sender, and their send queue | `types/init` |
| `httpapi` | the HTTP types, their implementations, and the routes of core's own features | `core`, `errs`, and `auth`, in part 2 |
| `engine` | `Prepare`, `Boot`, their configuration, and core's own declarations | `types/init` |

`store.Hooks` stays where it is. It is an interface that the store declares for what it consumes, which is the Go convention. Its implementation moves out of `types/init` with the dispatcher.

## Where each identifier goes

An identifier keeps its name unless the new package makes the name stutter or collide. A method moves with its type, and a test moves with the code it tests.

### `types`

| Identifiers | Part 1 | Part 2 |
| --- | --- | --- |
| `AuthContext`, `PluginInitContext`, `PluginMeta`, `PluginDependency` | `core` | |
| `Plugin` | `core` | `Routes` and `Middlewares` move to the optional `httpapi.Plugin` |
| `SessionConfig`, `SameSiteMode` and its values | `core` | |
| `HookPoint`, `HookPhase` and its values, `HookRegistry`, `HookContext`, `HookCatalog`, `HookPointDef`, `HookOptions`, `HookPriority` and its values | `core` | |
| `BeforeHookFunc`, `AfterHookFunc`, `FailedHookFunc`, `FailureReason`, `FailureRejectedByHook`, `Dispatcher`, `AuditSpec`, `AuditSubject` | `core` | |
| `ContextWithHookValues`, `HookValuesFrom`, `NestedHookValues`, `BeginOperation`, `AsOperation`, `FailIfRejected`, `WithLifecycle` | `core` | |
| `ContextWithRequest`, `RequestFrom` | `core` | `httpapi`. The field `HookContext.Request` is removed in step 12a: a handler reads the request with `RequestFrom(hctx.Ctx)`. |
| `RequestContext`, `ResponseRecorder`, `NewResponseRecorder`, `HandlerFunc`, `Middleware`, `Route`, `RouterConfig`, `Router`, `NewRouter`, `FrameworkDriver`, `ErrorMapper` | `core` | `httpapi` |
| `AuthenticateRequests`, `Router.ApplyAuthentication` | `core` | `httpapi`. `Credential`, `AuthOutcome`, and `Authenticator` stay. |
| `OriginCheck`, `NewOriginCheck`, `RefuseFormContentTypes`, `ClientIPConfig`, `NewClientConfig`, `ClientIP` | `core` | `httpapi` |
| `TrustedOrigins`, `NewTrustedOrigins`, `TrustedRedirect` | `core` | stay; see *`TrustedOrigins` stays in `core`* |
| `KahnSort` | `utils` | |
| `PublicView`, `NewPublicView` | `schema` | |
| `Environment`, `EnvProduction`, `EnvDev` | the root package | |
| `MailKind` and its values, `MailMessage`, `MailSender`, `MailSenderFunc`, `MailConfig`, `Mailer` | `core` | |
| `SMSKind` and its values, `SMSMessage`, `SMSSender`, `SMSSenderFunc`, `SMSConfig`, `SMS` | `core` | |
| `CodeOptions`, `CodeManager` | `core` | |
| `CodeKind`, `TokenKind`, `Token` | removed. Callers use `models.CodeKind`, `models.TokenKind`, and `models.Token`. | |
| `TokenKindEmailVerification`, `TokenKindPasswordReset`, `TokenKindMagicLink`, `TokenKindOAuthState`, `TokenKindAPIKey` | `core`, typed `models.TokenKind` | |
| `TokenBackend` and its values, `TokenKindDef`, `TokenConfig`, `TokenCatalog`, `TokenManager` | `core` | |
| `SessionState` and its values | removed. Callers use `models.SessionState`. | |
| `SessionManager`, `SessionMeta`, `SessionRevokedUserDeleted` | `core` | |
| `TokenDelivery` and its values, `SameSiteMode` and its values, `DefaultSessionCookieName`, `TokenCarrierConfig`, `TokenCarrier` | `core` | `httpapi`. `AuthContext.TokenCarrier` gives way to `RequestContext.TokenCarrier` in step 12a. |
| `SessionTokenHeader`, `RequireSession`, `RequireFreshSession` | `core` | `httpapi` |
| `SessionTokenRequest`, `SessionToken`, `SessionTokens`, `SessionTokenAudienceKey`, `SessionTokenClaimsKey` | `core` | |
| `PathSessionToken` | `core` | `httpapi` |
| `SignInResult` | `core` | |
| `SignInUserKey`, `SignInTokenKey`, `SignInStatusKey`, `SignInStatusSecondFactor`, `WriteSignIn` | `core` | `httpapi` |
| `RateLimitAlgorithm`, `AlgorithmFixedWindow`, `Limiter`, `Limit`, `RateLimitAction` and its values, `FailureMode` and its values, `RateLimitConfig`, `HookRateLimitRule`, `KeyByValues`, `AtomicIncrementer` | `core` | |
| `RateLimitCatalog`, `RateLimiter` | `core` | Their route methods go. Step 12a replaces `CheckRouteLimit` with `CheckRule` and adds `RateLimitRule`, `DeclareRule`, and `Rule`; step 12b removes `DeclareRouteRateLimitRule` and `RulesForRoute`. See *Route rules are matched in `httpapi` and counted in `core`*. |
| `RouteRateLimitRule`, `SplitPath`, `MatchesPath`, `MatchesMethod`, `BestRouteMatch` | `core` | `httpapi` |
| the crypto aliases in `types/crypto.go` | removed. Callers use `crypto`. | |
| `types/database.go`, `types/models.go` | deleted | |

Step 3 of the caller plan moved four `SessionManager` methods to `TokenCarrier`, renamed `TokenTransport` to `TokenDelivery`, and moved the cookie fields of `SessionConfig` to `TokenCarrierConfig`, which is `RouterConfig.Carrier`. The rows above show the result.

### `types/cryptotypes`

| Identifiers | Destination |
| --- | --- |
| `Crypto` | `crypto.Services`, since `crypto.Crypto` would stutter |
| `KeyPurpose` and its values, `KeyManager`, `PasswordHasher`, `SecretHasher`, `Encryptor`, `SigningKey`, `Signer`, `Randomizer` | `crypto` |
| `JWTKind` and its values, `JWTConfig`, `DefaultJWTTTL`, `DefaultJWKSPath`, `JWTRequest`, `Claims`, `JWTProvider` | `crypto` |
| `KeySet`, `ExternalKeySet`, `ExternalSigningKey`, `PublishedKey` | `crypto` |
| `SecretSource`, `WatchableSecretSource` | `crypto` |
| `OriginValidator` | `core`, since it isn't cryptography |
| `CSRFProtector` | removed. It has no implementation and no caller, and "Trusted origins match exactly" proposed its removal. |

No name in `types/cryptotypes` collides with a name in `crypto`. The file imports the standard library's `crypto` package, which needs an import alias inside a package named `crypto`.

### `crypto`

| Identifiers | Destination |
| --- | --- |
| `JWTProviderImpl.HandleJWKS`, `JWTProviderImpl.Routes` | The key set route moves to `transport`, next to the session token route, as `KeySetRoutes`, which serves the key set's `PublicKeys`. It reaches `auth` with step 8, and `httpapi` in part 2. |
| the `Environment` field of its configuration | typed `behemoth.Environment` |
| `New` | returns `crypto.Services` |

### `types/hooks`, `types/schema`, and `types/ratelimit`

| Package | Destination |
| --- | --- |
| `types/hooks` | `core/hooks`, every identifier |
| `types/schema` | `schema`, every identifier |
| `types/ratelimit`: `FixedWindow`, `NewFixedWindow` | `ratelimit` |

### `types/init`

| Identifiers | Destination |
| --- | --- |
| `PrepareConfig`, `PreparedApp`, `Prepare`, `BootConfig`, `IndexChecker`, `Boot`, `ResolvePluginOrder`, `DetectPluginNameConflicts`, `CoreDeclareHookPoints`, `CoreDeclareSchema`, `CoreDeclareRateLimitRules` | `engine` |
| `DefaultHookCatalog`, `NewDefaultHookCatalog`, `DefaultHookRegistry`, `NewHookRegistry`, `DefaultDispatcher`, `NewDefaultDispatcher`, the data hooks of `datahooks.go`, and the audit event builder | `dispatch` |
| `DefaultRateLimiter`, `DefaultRateLimitCatalog`, `NewRateLimitCatalog` | `ratelimit`. In part 2, `DefaultRateLimiter.CheckRouteLimit` gives way to `CheckRule`, and the router keeps the route half: matching a request to a rule, and its key. |
| `DefaultMailer`, `NewMailer`, `ErrMailQueueFull`, `ErrMailerClosed`, `DefaultSMS`, `NewSMS`, `ErrSMSQueueFull`, `ErrSMSClosed`, and the send queue | `messaging` |
| `DefaultTokenCatalog`, `NewDefaultTokenCatalog` | `auth` |

### `transport`

| Identifiers | Destination |
| --- | --- |
| `DefaultSessionManager`, `NewSessionManager`, `DefaultTokenManager`, `NewDefaultTokenManager`, `DefaultSessionTokens`, `NewSessionTokens`, `DefaultCodeManager`, `NewCodeManager` | `auth` |
| the session token route (`DefaultSessionTokens.Routes`) | `auth` in part 1, `httpapi` in part 2 |

### `errors`

| Identifiers | Destination |
| --- | --- |
| every identifier not listed below | `errs` |
| `Is` | `errs.IsCategory`, since `errs.Is` next to `errors.Is` reads as the standard function |
| the `ErrorCode...` constants | `errs.Code...`, such as `errs.CodeSessionMissing`. The values clients receive don't change. |
| `DefaultErrorMapper`, and the table from categories to HTTP statuses | `errs` in part 1, `httpapi` in part 2 |

### `migration/core`

Every identifier moves to `migration`, so that two packages aren't both named `core`.

### Files without code

`types/database.go`, `types/models.go`, the root `main.go`, `session.go`, and `transport.go`, and `middleware/middleware.go` are deleted. None of them holds code or a package doc comment.

## Implementation steps

Each step is one commit. It builds every module and passes the suite: the root module, and the 16 modules beside it, which are the examples, the framework and storage adapters, the OpenTelemetry adapter, and `tests`. It updates the docs and the `docs/ongoing.md` entries that name what it moves, in the same commit.

### Part 1

| Step | Content | Status |
| --- | --- | --- |
| 1 | Delete the files without code. Move `KahnSort` to `utils`, and `Environment` to the root package. | Done |
| 2 | `errors` becomes `errs`, `Is` becomes `IsCategory`, and the error code constants lose their `ErrorCode` prefix. The two functions that use `errs` as a variable name rename it first. | Done |
| 3 | `migration/core` becomes `migration`. | Done |
| 4 | `types/schema` becomes `schema`, and `PublicView` and `NewPublicView` join it. | Done |
| 5 | `types/cryptotypes` merges into `crypto`, and the crypto aliases go. `Crypto` becomes `crypto.Services`, `OriginValidator` moves to `types`, and `CSRFProtector` goes. The key set route moves to `transport`, so `crypto` imports nothing of `types`. | Done |
| 6 | The duplicates go: `types.SessionState`, and the aliases `Token`, `TokenKind`, and `CodeKind`. | Done |
| 7 | The implementations leave `types/init` for `dispatch`, `ratelimit` (which takes in `types/ratelimit`), and `messaging`, and the token catalog moves to `transport`. | Done |
| 8 | `transport` becomes `auth`. | Done |
| 9 | `types/init` becomes `engine`. | Done |
| 10 | `types` becomes `core`, and `types/hooks` becomes `core/hooks`. The repository table in `CLAUDE.md` follows. | Done |
| 11 | `layout_test.go` parses the imports of every package in every module and checks [the rows](#rows): it fails when a package imports a package of a later row, when a plugin imports a package of row 10, or when a package has no row. | Done |

The order moves code out of `types` before `types` gets its new name, so that no identifier is renamed twice. A plugin's `types.PasswordHasher`, for example, becomes `crypto.PasswordHasher` in step 5, and step 10 doesn't touch it.

To move code, use `git mv`, which keeps each file's history. Change import paths and qualifiers with a scripted replacement across all modules, then run `gofmt` and build every module. Behavior doesn't change, so the existing tests are the check.

### Part 2

Part 2 waited for [`caller.md`](caller.md), which is built: `SessionManager` has no HTTP method any more, and the session manager, the audit log, and the rate limiter read the caller instead of the request. What still ties `core` to the HTTP types is `HookContext.Request`, the router and its stages, `TokenCarrier`, and `Plugin.Routes` and `Plugin.Middlewares`, which step 12 moves.

Step 12 is two commits. The first makes the changes that can be made in place, so that the second only moves code and renames qualifiers, apart from the two optional interfaces that take the place of methods `core` can no longer name.

| Step | Content | Status |
| --- | --- | --- |
| 12a | In place: `HookContext.Request` goes, and a handler reads the request with `RequestFrom(hctx.Ctx)`. The token carrier leaves `AuthContext`: the router builds it from `RouterConfig.Carrier` and hands it to every handler as `RequestContext.TokenCarrier`. The route half of the rate limiter counts through `RateLimiter.CheckRule`, against the `RateLimitRule` each route rule declares under its name, and `CheckRouteLimit` goes. | Done |
| 12b | The HTTP types and their implementations move from `core` to `httpapi`, as the tables above list, with the routes of core's own features: the session token route and the key set route. `Plugin.Routes` and `Plugin.Middlewares` move to the optional `httpapi.Plugin`, and a plugin returns its route rules from the optional `httpapi.RouteRulesPlugin` in place of `DeclareRouteRateLimitRule`, which `Prepare` declares with `httpapi.DeclareRouteRules`. The table from categories to HTTP statuses and `DefaultErrorMapper` leave `errs`. `core` exports `ParseOrigin` and `OriginOf` for the origin check. `layout_test.go` gets the row of `httpapi`, which, like a plugin, does not import row 10. | Done |
| 13 | `TestNoServerSideHTTPBelowHTTPAPI`, next to the test of step 11, fails when a package of rows 1 to 10 uses the server side of `net/http`, such as `http.Request` or `http.ResponseWriter`. `outbound`, which sends requests to other services, may name `http.Request` for them. | Done |

## Decisions

### The HTTP package is `httpapi`

**Context:** the plan called it `web`, to be confirmed when part 2 started. Plugin and application code name it on every handler signature.

**Options considered:**

- *`web`.* Short. It suggests browsers and HTML, while the routes also serve mobile apps, command line tools, and other servers, and many applications have a `web` package of their own, which would force an import alias.
- *`router`.* Matches `RouterConfig` and the router adapters. `router.Router` stutters, a variable named `router` is common and hides the package, and the package also holds the token carrier, the origin check, and `WriteSignIn`.
- *`httpx`, `server`, `behemothhttp`.* The first says nothing, the second is wrong, since behemoth never owns the server, and the third is long.
- *`httpapi`.* Says what it holds: the HTTP API behemoth serves. No standard library package and no common variable has the name.

**Decision:** `httpapi`. `web.HTTPPlugin` becomes `httpapi.Plugin`, which reads without the stutter.

### A plugin keeps its routes, behind an optional interface

**Context:** `Plugin` required `Routes` and `Middlewares`, whose types move to `httpapi`, which imports `core`.

**Options considered:**

- *The plugin type implements `httpapi.Plugin`, and imports `httpapi`.* An application sets a plugin up as today. A plugin's package still imports `net/http`, so the import check of step 13 covers rows 1 to 10, and not the plugins.
- *A type in a package of the plugin's own adds the routes, and the application registers that type.* A plugin's flows would be free of HTTP types, which a check could enforce. Every plugin splits in two, and an application registers two values per plugin. Moving each plugin's handlers is a non-goal of this plan.

**Decision:** the first. Boot mounts the routes of each plugin that implements `httpapi.Plugin`, and a plugin with no routes leaves both methods out.

**Revisit if:** a second transport is built, or a check that a flow does not depend on HTTP is wanted for the plugins too.

### Route rules are matched in `httpapi` and counted in `core`

**Context:** a route rule's `KeyFunc` takes the `*http.Request`, so the rule moves to `httpapi`. Plugins declared route rules through `PluginInitContext.RateLimits`, which `core` defines and which can't name an `httpapi` type, and `ratelimit`, which counts them, can't import `httpapi`.

**Decision:** step 12a splits a route rule into the part the router needs, the method, the path, and the key, and the part the rate limiter counts with, a `core.RateLimitRule` declared under the rule's name. The router counts a request through `RateLimiter.CheckRule`. In step 12b, a plugin returns its route rules from the optional `httpapi.RouteRulesPlugin`, and `Prepare` declares each rule's counting part with `DeclareRule`, so names stay unique across hook and route rules and `RateLimitConfig` changes either kind by name. The reasoning is under *The route half counts through `CheckRule`* in [`../ratelimit/rate_limiter.md`](../ratelimit/rate_limiter.md).

### The token carrier belongs to the router

`AuthContext` is in `core`, so it can't hold the `httpapi.TokenCarrier`. The router builds the carrier from `RouterConfig.Carrier`, the settings it already holds, and hands it to every handler as `RequestContext.TokenCarrier`, as it hands over `Auth`. Only route handlers used it.

### `TrustedOrigins` stays in `core`

The tables first moved `TrustedOrigins` and `NewTrustedOrigins` with the origin check. `TrustedOrigins` implements `core.OriginValidator`, holds no HTTP type, and shares its parsing of an origin with `TrustedRedirect`, which flows call and which stays. Step 12b exports that parsing, as `core.ParseOrigin` and `core.OriginOf`, for the origin check.

## Related entries

These entries in `docs/ongoing.md` are resolved by this plan:

- **"`types` mixes contracts, implementations and HTTP, and its layering forces aliases".** Part 1 resolved it and removed the entry. The HTTP types that remain in `core` are part 2, which the next entry tracks.
- **"The request pipeline lives in the HTTP router, and a plugin's handlers share its package"**, which was "`Plugin` requires HTTP routes, and the request pipeline lives in the router". Step 12b made the routes optional and moved the HTTP types, and step 13 added the check. The entry stays open for the stages of the pipeline and the plugins' handlers.
- **"Trusted origins match exactly".** Step 5 removes `CSRFProtector`, which the entry also covered. The point about wildcards stays open.
