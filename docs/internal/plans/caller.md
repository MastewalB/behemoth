# The caller of an operation

This document describes how a flow learns who called it and where the call came from. It covers the caller value, the principals it names, how a transport authenticates a call through core, the permissions a flow requires, and how code in the process calls a flow. It also records the decisions taken and the order of the work.

**Status:** planned, as of 2026-10-19. Step 1, the package layout, is done; the caller itself is not built. [Implementation steps](#implementation-steps) lists the work.

The documents it builds on are:

- [ADR-0004](../decisions/0004-carrying-the-caller-in-the-context.md): the caller travels in the context.
- [ADR-0005](../decisions/0005-treating-a-missing-caller-as-anonymous.md): a call without a caller is anonymous.
- [ADR-0006](../decisions/0006-requiring-declared-permissions.md): self-service flows and admin operations require declared permissions.
- [`package_layout.md`](package_layout.md): the package layout. Its part 1 is this plan's step 1.
- [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md): "Learn about the caller from the context", "A protection belongs to the operation, not to the path", and the places where the code differs today.
- [`../guidelines/service_ready_components.md`](../guidelines/service_ready_components.md): a hook payload can leave the process.
- [`../guidelines/http_contract.md`](../guidelines/http_contract.md): an error code that has shipped stays.
- [`../sessions/token_delivery.md`](../sessions/token_delivery.md): how the session token travels, and what the session check answers.
- [`session_tokens.md`](session_tokens.md): the JWT issued for other services, which Behemoth never accepts as a credential.
- [`oauth.md`](oauth.md): account linking, the first new flow that needs the caller's session.
- [`../telemetry/audit.md`](../telemetry/audit.md): the audit event's actor.

## Terms

| Term | Meaning |
| --- | --- |
| Caller | Who an operation runs for, and where the call came from. Every operation has one. The zero value is an anonymous caller. |
| Principal | The identity an operation runs for: a user, a service, or the system. |
| Delegate | The identity that acts for the principal when it isn't the principal itself: an admin who impersonates a user, an agent, or a job that acts for a user. |
| Credential | What a transport takes from a request to authenticate it. Today that is the session token. |
| Sign-in credential | What a sign-in flow exchanges for a session: a password, a magic link token, a one-time code, or an authorization code. It is flow input, not a credential in the sense above. |
| Authenticator | The component in core that turns a credential into a caller. |
| Permission | A name that a flow requires of its caller, such as `email:change`. |
| Grant | The permissions a caller holds. |
| Public flow | A flow that any caller may run, anonymous included, such as sign-in. |
| Self-service flow | A flow that acts on the caller's own account, such as an email change. |
| Admin operation | A flow that acts on an account named in its input, such as `SetPassword`. |

## Context

A flow learns about its caller in three ways today:

- **A user id in its input.** The handler fills it from the session: `phonenumber.SendRequest.UserID`, `phonenumber.VerifyRequest.UserID`, and `emailverification.ChangeRequest.UserID`.
- **A session as an argument.** `emailpassword.SignOut(hctx, sessionID)`, and `SessionTokenRequest.Session` for `SessionTokens.Issue`.
- **The HTTP request on the context.** `DefaultSessionManager.requestMeta` takes a session's address and user agent from it. `DefaultDispatcher.auditEvent` takes an event's address, user agent, and actor from it, and reads the session from `RequestContext.Values["session"]`. `telemetry.NormalizeAuditEvent` treats an event with a request ID as anonymous and an event without one as the system.

What follows from that:

- The check a protected call needs exists only as HTTP middleware (`RequireSession`, `RequireFreshSession`), and the phone number plugin keeps a partial copy of it (`optionalSession`).
- The fresh-session rule of an email change is on its route only. A wrapper for another transport has to know to repeat it.
- The per-address limits of sign-in, sign-up, and the session token route are route rules, so a call from code runs without them, and a hook rule has no resolved client address to key on.
- A flow reached without HTTP records no address, and its audit event names the system as the actor.

The plugins planned next act on the signed-in user's own account: a second factor, passkeys, OAuth account linking, a password change, account deletion, and a list of the user's sessions. Without a shared model, each would pick its own way to learn the caller.

## Goals

- One value describes the caller, for flows, hook handlers, rate-limit rules, the session manager, and the audit log.
- Core implements authentication and session validation once. A transport translates its input and calls core.
- A flow enforces what it requires (a user, a fresh session, a permission), however it is reached.
- Services, delegates, and partial grants fit in later without a change to any flow.

## Non-goals

- Roles, an admin plugin, and the application's own authorization.
- API keys, client credentials, and Behemoth as an OAuth provider. The model leaves room for each of them, and this plan builds none.
- Moving each plugin's handlers into a package of its own. "`Plugin` requires HTTP routes, and the request pipeline lives in the router" tracks it.

## The caller

As built in step 2, in package `identity`:

```go
type PrincipalType string // PrincipalUser, PrincipalService (not built), PrincipalSystem

// Principal is who an operation runs for. The zero value is nobody.
type Principal struct {
	Type PrincipalType
	ID   string
}

// SessionRef is the session a caller was authenticated with, as plain data.
type SessionRef struct {
	ID, UserID, State, ImpersonatorID string
	ExpiresAt, FreshAt                time.Time
}

// Peer is what a transport knows about a call besides its credential.
type Peer struct{ Transport, IPAddress, UserAgent string }

// Caller is who an operation runs for, and where the call came from. Its
// fields are unexported. The zero value is anonymous and holds no permission.
type Caller struct{ /* principal, delegate, session, grant, authErr, peer */ }

func (c Caller) Principal() Principal
func (c Caller) Delegate() Principal
func (c Caller) Session() (SessionRef, bool) // a copy
func (c Caller) AuthError() error
func (c Caller) Peer() Peer
func (c Caller) IsAnonymous() bool
func (c Caller) Holds(permission string, admin bool) bool

func WithCaller(ctx context.Context, c Caller) context.Context
func CallerFrom(ctx context.Context) Caller // the zero Caller when ctx carries none

// For code in the process.
func System(name string) Caller
func (c Caller) For(userID string) Caller // ErrInvalidFor on any caller but a system one

// For an authenticator.
func Anonymous(peer Peer) Caller
func Unauthenticated(peer Peer, reason error, pending *SessionRef) Caller
func SignedIn(session SessionRef, peer Peer) Caller
```

A grant is all of a kind or nothing: a signed-in user holds every self-service permission, a system caller every permission, and an anonymous caller none. A grant that lists permissions one by one waits for the first delegated credential.

`HookContext` gains a method, `Caller`, that returns `CallerFrom(hctx.Ctx)`. It gets no caller field, so there is no copy to keep in step ([ADR-0004](../decisions/0004-carrying-the-caller-in-the-context.md)).

### Where the types live

The caller's own types (`Principal`, `SessionRef`, `Peer`, `Caller`, `WithCaller`, `CallerFrom`, `System`, and the constructors an authenticator uses) live in a new package, `identity`, below `telemetry`, so that `NormalizeAuditEvent` can read the caller. `identity` imports no other Behemoth package, which is why a caller holds a `SessionRef` and not a `*models.Session`. The authenticator, the permission catalog, and `Access` are contracts in `core`, the package that `types` became in step 1 ([`package_layout.md`](package_layout.md)).

### Who builds a caller

A caller's fields are unexported, so a caller comes from a constructor:

- **`System` and `For`,** for code in the process.
- **`Anonymous`, `Unauthenticated`, and `SignedIn`,** for an authenticator. The first two grant nothing. `SignedIn` grants a user's rights, so `TestOnlyAuthBuildsSignedInCallers` in `layout_test.go` fails when a package other than `auth` calls it.

No code can write a struct literal that claims to be a signed-in user.

### Principals and delegates

| Who calls | Principal | Delegate | Built |
| --- | --- | --- | --- |
| A visitor | none: anonymous | none | yes |
| A user with a session | the user | none | yes |
| An admin who impersonates a user | the user | the admin | no. `sessions.impersonator_id` exists, and no flow sets it. |
| A job | the system, by name | none | with this plan |
| A job that acts for a user | the user | the system, by name | with this plan |
| A service with a key of its own | the service | none | no |
| An agent that acts for a user | the user | the agent | no. It needs Behemoth as an OAuth provider. |

An agent is not a principal type. An autonomous agent is a service, and an agent that acts for a user is a delegate whose grant limits what it may do. That is the shape of the `act` claim in OAuth token exchange (RFC 8693).

A session that waits for a second factor authenticates nobody. The caller keeps the session, so that a second-factor flow can find it, and its principal stays empty.

## Authentication

### The layers

| Layer | What it does |
| --- | --- |
| Framework adapter (gin, echo, chi, fiber, net/http) | Turns the framework's request into an `*http.Request`, as now. |
| Transport (the router; later a module per transport) | Takes the credential from where the token carrier says, and notes the transport, the resolved address, and the user agent. Calls the authenticator and puts the caller on the context. Writes back what the outcome asks for: the cookie with a new expiry, or a cleared cookie. |
| Authenticator: `core.Authenticator`, implemented by `auth.DefaultAuthenticator` | Validates the token, maps "not found" to `session_invalid`, checks the state, applies the rolling extension, and builds the caller. |
| Flow | Requires what it needs, through `Access`. |

The contracts, to be settled in step 3:

```go
// Credential is what a transport takes from a request.
type Credential struct {
	Kind  CredentialKind // CredentialSession today
	Value string         // the raw secret
}

// Authenticator turns a credential into a caller.
type Authenticator interface {
	// Authenticate returns the caller of a call that presented cred, or an
	// anonymous caller when cred is nil. A missing or dead credential is not
	// an error: the caller is anonymous and keeps the reason
	// (Caller.AuthError). A failed lookup is kept in the same way, and
	// logged by the authenticator.
	Authenticate(ctx context.Context, cred *Credential, peer identity.Peer) (identity.Caller, AuthOutcome)
}

// AuthOutcome is what the transport may have to write back.
type AuthOutcome struct {
	Extended *identity.SessionRef // the session, when the rolling extension extended it
	Ended    bool        // the credential belongs to a session that has ended
}
```

### What the transport does

The transport follows these rules:

- **It authenticates every call that presents a credential,** whether the flow needs a user or not. A public flow ignores the caller's principal. A protected flow returns the caller's `AuthError`, so a client keeps getting today's codes.
- **It replaces any caller already on the context.** An application's middleware in front of Behemoth can't plant one.
- **It decides nothing a flow decides.** Cookies, `Cache-Control`, and the shape of a body stay the wrapper's.

### What changes in the session API

These parts of the session API change:

- **The token carrier.** The four HTTP methods of `SessionManager` (`WriteToken`, `ExtractToken`, `ClearToken`, and `ExtendToken`) move to a token carrier that the HTTP layer owns. `SessionManager` keeps the lifecycle, which takes a context. Built as `core.TokenCarrier`, with `Write`, `Extract`, `Clear`, and `Extend`. Its settings, the delivery and the cookie's attributes, moved from `SessionConfig` to `RouterConfig.Carrier`. `TokenTransport` is `TokenDelivery`, because a transport here means HTTP or another protocol. See [`../sessions/token_delivery.md`](../sessions/token_delivery.md).
- **The middleware.** `RequireSession`, `RequireFreshSession`, and the phone number plugin's `optionalSession` become thin wrappers over the caller. `RequireSession` and `RequireFreshSession` stay public, because applications protect their own routes with them. They require a caller that was authenticated with a session, and take no permission, since an application's own routes declare none.
- **The session in `Values`.** `RequestContext.Values["session"]` and `Values["sessionID"]` go. A handler reads `CallerFrom(rctx.Ctx).Session()`. `docs/api/sessions.md` shows the old keys and changes with them.
- **`HookContext.Request`.** It stays for handlers that want HTTP details. The session manager, the audit log, and rate-limit rules stop reading it. It becomes an accessor in the HTTP package when the HTTP types leave `core`.

## What a flow requires

### `Access`

The require helpers are methods of a service on `AuthContext`, like the dispatcher, because they check the permission catalog. As built in step 2, with `auth.DefaultAccess` as the implementation; `NewAccess` takes the catalog and `SessionManager.IsFresh`:

```go
// Access answers whether the caller on a context may run a flow.
type Access interface {
	// RequireUser returns the user the caller acts for, when the caller
	// holds p. p must be declared with PermissionSelf.
	RequireUser(ctx context.Context, p Permission) (userID string, err error)

	// RequireFreshUser is RequireUser, and the caller's session must be
	// fresh (SessionConfig.FreshAge). A system caller that acts for a user
	// passes.
	RequireFreshUser(ctx context.Context, p Permission) (userID string, err error)

	// OptionalUser is for a flow that acts for a user when there is one and
	// runs as a public flow when there is none, such as the phone number
	// plugin's send and verify. ok is false for an anonymous caller that
	// presented no credential.
	OptionalUser(ctx context.Context, p Permission) (userID string, ok bool, err error)

	// RequireAdmin lets an admin operation through. p must be declared with
	// PermissionAdmin. Only a system caller passes until admin principals
	// exist.
	RequireAdmin(ctx context.Context, p Permission) error
}
```

`RequireUser` answers as follows:

| Caller | Answer |
| --- | --- |
| Anonymous, no credential presented | `session_missing` (401) |
| Anonymous, the credential belongs to no session, or to a revoked or expired one | `session_invalid`, `session_revoked`, or `session_expired` (401) |
| A session that waits for a second factor | `session_pending` (401) |
| The session lookup failed | that error, a failure of the system (500) |
| A user without the permission | `forbidden`, with the code `insufficient_scope` (403) |
| A user whose session isn't fresh, for `RequireFreshUser` | `session_not_fresh` (401) |
| A system caller that acts for nobody | a configuration error (500): code that runs a self-service flow names the user with `For` |
| A user with the permission, or a system caller that acts for a user | the user's id |

The first four rows are what `RequireSession` answers today, so the HTTP contract doesn't change. No caller can hold a partial grant yet, so no client receives `insufficient_scope` until one can.

### Permissions

A plugin declares the permissions its flows require in `Declare`, through a catalog on `PluginInitContext`. As built in step 2, with `auth.DefaultPermissionCatalog` as the implementation:

```go
type Permission string

type PermissionKind string

const (
	PermissionSelf  PermissionKind = "self"  // on the caller's own account
	PermissionAdmin PermissionKind = "admin" // on an account named in the input
)

type PermissionDef struct {
	Name        Permission
	Kind        PermissionKind
	Description string // what a consent screen or an API key form shows
	Owner       string // set by the catalog the declarer receives
}

type PermissionCatalog interface {
	Declare(def PermissionDef) error // fails when another owner declared Name
	Lookup(p Permission) (PermissionDef, bool)
	All() []PermissionDef
}
```

The catalog follows these rules:

- **A name is `resource:action`,** in lowercase snake case: `email:change`, `session_token:issue`. That is the usual form of an OAuth scope, so a name can become a scope without a translation.
- **One name stands for one action a user would grant on its own.** Sending and verifying a new phone number share `phone:change`. A scope that a user consents to can later bundle several names.
- **A self-service grant never reaches an admin operation.** The two kinds are separate sets, and each require method accepts one kind only.
- **The zero value of a grant holds nothing.** The authenticator gives a session every self-service permission, and a system caller holds every permission.
- **An undeclared permission is a configuration error,** in the same way as dispatching an undeclared hook point.
- **Freshness is required at the call site,** not in the declaration. Policy such as "never grantable to a delegate" can be added to `PermissionDef` later, as a field whose zero value is the safe one.

The flows that require a caller today, with names to confirm in review:

| Flow | Permission | Requirement |
| --- | --- | --- |
| `emailpassword.SignOut` | `session:sign_out` | `RequireUser`, and a session |
| `emailverification.RequestChange` | `email:change` | `RequireFreshUser` |
| `SessionTokens.Issue` | `session_token:issue` | `RequireUser`, and a session |
| `phonenumber.SendCode` and `phonenumber.Verify` | `phone:change` | `OptionalUser` |
| `emailpassword.SetPassword`, `username.SetUsername`, `phonenumber.SetPhoneNumber`, `phonenumber.AddNumber` | `user:set_password`, `user:set_username`, `user:set_phone`, `user:add_phone` | `RequireAdmin` |

Public flows (sign-up, sign-in, the reset and link requests, and every verify by token) require no principal and declare no permission. The single-use token of a verify, a confirm, or a reset grants one action. Its caller stays anonymous, and the audit log credits a success to the token's user, as it does today.

## Code in the process

Code in the process calls flows under these rules:

- **A nested call inherits the caller.** When the username plugin's sign-in calls `emailpassword.SignInWith`, or a flow calls the session manager, the rate limits and the audit log see the original client. Nothing gains a privilege on the way down.
- **Code names itself.** A job puts `System("purge-sessions")` on its context. To run a self-service flow for a user, it uses `System("support-tool").For(userID)`.
- **An admin operation requires a privileged caller.** Today that is a system caller. An admin principal with the permission can pass later, through an admin plugin or the standalone service's API.
- **The store and the managers check nothing.** They are the layer below the flows, and code that holds them is trusted.
- **Anything that leaves the process carries the caller as data,** such as a hook callout's envelope. The context ends at the process boundary.

## Readers of the caller

| Reader | Today | With this plan |
| --- | --- | --- |
| `DefaultSessionManager.requestMeta` | the request's address and user agent | the caller's. `SessionMeta` still overrides them. |
| The audit event's actor | the request's session; otherwise anonymous inside a request, and the system outside one | the caller's principal and delegate. A successful operation of an anonymous caller is credited to its subject's user, as today. |
| `NormalizeAuditEvent` | anonymous when the event has a request ID | the caller on the context, when the event names no actor |
| Hook rate-limit rules | `hctx.Request`, with a `ClientIPConfig` of their own | `hctx.Caller().IPAddress()`, through a `KeyByClientIP` helper |
| The per-address limits of sign-in, sign-up, the session token, and each plugin's `Rule*Route` | route rules | hook rules on the flows' before points. A flow without a before point keeps its route rule until it has one. |

The audit log gains two nullable columns for the delegate's type and id, and `ActorType` gains `service`. Both are additions, so the previous version keeps working against the new schema. `ActorID` stays the principal, in the same way as an impersonation session stores the impersonated user in `user_id`.

## Rules the design depends on

The design holds only while these rules hold:

- **A transport builds a caller only through the authenticator,** and replaces any caller it finds on the context. Otherwise a middleware in front of Behemoth can plant an identity.
- **A flow branches on who calls, never on how the call arrived.** `Transport()` is recorded, never compared. Otherwise a second transport behaves differently from the first.
- **A flow that acts on the caller's account takes the account from the caller, never from its input.** Otherwise a client can name another user's account.
- **The zero values of a caller and of a grant grant nothing.** Otherwise code that forgets to set a caller runs with privileges.
- **A session token, the JWT issued for other services, is never a credential to Behemoth.** [`session_tokens.md`](session_tokens.md) has the reasons under "Security rules". Otherwise a service that receives one can act as the user on Behemoth.

## Decisions

Three decisions have records of their own:

- [ADR-0004](../decisions/0004-carrying-the-caller-in-the-context.md): the caller travels in the context.
- [ADR-0005](../decisions/0005-treating-a-missing-caller-as-anonymous.md): a call without a caller is anonymous, and the system is explicit.
- [ADR-0006](../decisions/0006-requiring-declared-permissions.md): every self-service flow and admin operation requires a declared permission, and self and admin permissions are separate sets.

The other decisions taken for this plan follow.

### The security context is `Caller`, and `AuthContext` keeps its meaning

`core.AuthContext` already names the services every plugin receives in `Init`. Giving the name to the caller means renaming the service container, which changes every plugin's `Init` and every `hctx.Auth`, for a name. The caller takes a name of its own.

### An agent is a delegate, not a principal type

A principal type for agents would have to say whose account an agent acts on, and with what limits. Delegation already says both: the principal is the user, the delegate is the agent, and the grant limits it. An agent with an identity of its own is a service. The same slot serves an admin who impersonates a user and a job that acts for a user.

### A dead credential makes the caller anonymous

The transport authenticates every call that presents a credential, including calls to public flows. Refusing the call would refuse a sign-in from a browser that still holds the cookie of an expired session. Anonymous, with the reason kept, lets a public flow proceed and lets a protected flow answer with the precise code.

### A caller holds a session reference, not the session row

The caller's package sits below `telemetry`, and a hook callout sends the caller to another process. A `*models.Session` would put `models` under `telemetry`, and the session's token hashes into every hook payload. A `SessionRef` holds the fields flows read: the id, the user, the state, the expiry, the time of the last credential check, and the impersonator.

## Open questions

- `Access` and `Peer` are working names.
- Whether a session created by impersonation holds every self-service permission.

## Implementation steps

| Step | Content | Status |
| --- | --- | --- |
| 1 | Part 1 of [`package_layout.md`](package_layout.md): the packages move to their layout, except for the HTTP types | Done |
| 2 | The caller's package, `WithCaller`, `CallerFrom`, `System`, `For`, `HookContext.Caller`, the permission catalog, and `Access`, with tests. Nothing reads them yet. | Done |
| 3 | The authenticator. The router authenticates every call and puts the caller on the context. The token carrier takes the four HTTP methods of `SessionManager`, and `TokenTransport` gets its new name, `TokenDelivery`. `RequireSession`, `RequireFreshSession`, and `optionalSession` become wrappers, and the session keys in `RequestContext.Values` go. | Done |
| 4 | The readers: `requestMeta`, the audit actor with the delegate columns and their migration, `NormalizeAuditEvent`, `KeyByClientIP`, and the per-address limits as hook rules. The hook rules get new names that end in `.address`, such as `core.signin.address`, and the route rules they replace go. Every sign-in plugin fires `auth.signIn.before`, so the sign-in rule keys on the address and the sign-in method, which each flow publishes in the operation's `Values`: each method keeps a limit of its own. | Not started |
| 5 | The flows: the permissions declared, and the flows in the table above require them. The `UserID` fields of `phonenumber.SendRequest`, `phonenumber.VerifyRequest`, and `emailverification.ChangeRequest` go, and so does `SessionTokenRequest.Session`. | Not started |
| 6 | Admin operations require a privileged caller. The examples, the CLI, and the tests name their callers. | Not started |
| 7 | The docs: the guideline's list of differences, `docs/api/sessions.md`, `docs/api/hooks.md`, the token delivery and audit pages, and the hook context page | Not started |

Each step leaves the code working. Steps 3, 5, and 6 change what an application or a plugin author writes, so they land before a tagged release.

After step 6, nothing in `core` refers to the HTTP types except `HookContext.Request`, and part 2 of [`package_layout.md`](package_layout.md) moves them out.

## Related entries

These entries in `docs/ongoing.md` are resolved by this plan. Each is removed with the step that resolves it:

- **"The caller of an operation is known only through the HTTP request".** Steps 2 to 4.
- **"The session manager also carries the token over HTTP".** Step 3.
- **"The phone number plugin reads an optional session itself".** Step 3.
- **"A hook rule has no direct way to the resolved client address".** Step 4.
- **"A flow called from code skips the per-address limits of its route".** Step 4.
- **"The fresh-session rule of an email change is checked by its route only".** Step 5.

These entries affect the plan:

- **"Audit events record the IP address whatever the session setting says".** Step 4 changes the code that records the address. The fix lands with it or before it.
- **"No route answers with the caller's session, and sign-out belongs to one plugin".** A session route in core reads the caller.
- **"`Plugin` requires HTTP routes, and the request pipeline lives in the router".** The HTTP types leave `core` after step 6, as part 2 of [`package_layout.md`](package_layout.md).
- **"Some flows take loose arguments instead of a request type".** `SignOut` takes its session from the caller.
