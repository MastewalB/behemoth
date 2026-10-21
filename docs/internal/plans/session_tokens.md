# Session tokens for other services

This document describes how a service other than the application checks who a request is from: Behemoth issues a short-lived JWT for a signed-in session, and the service verifies it with Behemoth's published keys. It also records the approaches that were weighed, those that may follow, and one that must never be built.

**Status:** built, as of 2026-10-14. The API guide is [`../../api/session-tokens.md`](../../api/session-tokens.md).

The documents it builds on are:

- [ADR-0002](../decisions/0002-deriving-external-jwt-keys.md): the signing keys are derived from the master secret, behind `ExternalKeySet`.
- [`../sessions/token_delivery.md`](../sessions/token_delivery.md): how the session token travels, and `RequireSession`.
- [`../guidelines/http_contract.md`](../guidelines/http_contract.md) and [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md): the guidelines for the route and the flow.

## The problem

A session is checked by the session manager, in the application's process. A service in another process or another language had nothing to call. A service that has to know the user behind a request needs one of these:

- a credential it can check on its own
- a call that asks Behemoth
- a gateway in front of it that asks Behemoth

## The design

A signed-in client exchanges its session for a session token: a JWT signed with an EdDSA key and valid for 15 minutes. It sends the token to the other service, and the service checks it with the key set Behemoth publishes. Behemoth is not called.

| Step | Who | What happens |
| --- | --- | --- |
| 1 | client | posts to `POST /session/token` with its session, by the configured delivery, and optionally an audience |
| 2 | Behemoth | checks the session, runs the hook point that may add claims, and signs the token |
| 3 | client | sends the token to the service as `Authorization: Bearer <token>` |
| 4 | service | fetches `/.well-known/jwks.json` once and caches it, then checks every token against it: the signature, `iss`, `aud`, and `exp` |
| 5 | client | asks for a new token before the old one expires |

### The route

`POST /session/token`, below the router's base path. It requires an active session: `SessionTokens.Issue` requires `session_token:issue` (`Access.RequireUser`) and the caller's session, so a missing, revoked, expired, or pending session gets the session errors every protected route gives.

| Request body | Meaning |
| --- | --- |
| empty, or `{}` | a token for the first configured audience |
| `{"audience": "https://api.example.com"}` | a token for that audience, which has to be one of the configured ones |

The answer is `200` with `Cache-Control: no-store`:

```json
{"token": "eyJ...", "expires_at": "2026-10-14T10:15:00Z", "audience": "https://api.example.com"}
```

The token is in the body only. It is never set as a cookie, and never put in a URL.

| When | Status | Code |
| --- | --- | --- |
| the body is not JSON, or `audience` is not a string | `400` | `request_validation_error`, `audience_invalid_input` |
| `audience` is not a configured one | `400` | `audience_invalid_input` |
| no session, or one that is revoked, expired, or pending | `401` | the session codes of `RequireSession` |
| a handler on `auth.sessionToken.beforeIssue` refused | the error's status | the error's code |
| too many requests from one address | `429` | `rate_limited` |

### The token

The header is `{"alg": "EdDSA", "typ": "JWT", "kid": "<secret version>"}`. The claims:

| Claim | Value |
| --- | --- |
| `iss` | `JWTConfig.Issuer` |
| `aud` | the audience of the request |
| `sub` | the user's id |
| `sid` | the session's id |
| `iat`, `exp` | the time of issue, and 15 minutes after it by default |
| `jti` | a random id of the token |
| `custom` | the claims a hook handler added, such as roles. Absent when there are none. |

`sid` is the claim OpenID Connect uses for a session. A service that has to react to a sign-out at once can ask about that session (see [Introspection](#introspection)).

### Lifetime and revocation

A session that ends gets no new token. A token already issued stays valid until it expires. The lifetime is therefore the delay between a revoked session and the moment its tokens stop working, and it is kept short: 15 minutes by default, `JWTConfig.TTL[JWTExternal]` to change it.

### Audiences

`JWTConfig.Audiences[JWTExternal]` lists the services a token may be issued for. The first is the default. A request may name another one of the list, and nothing outside it. A service checks that `aud` names itself, so a token issued for service A is refused by service B.

### Claims a handler adds

`auth.sessionToken.beforeIssue` is a before point with the payload `userID`, `sessionID`, `audience`, and `claims`, an empty object. A handler can refuse the token, or set keys of `claims`, which end up under `custom`. Nothing else of the payload is read back: a handler can't change who the token is about, or for whom.

`auth.sessionToken.afterIssue` gets the issued token's record without the token, and `auth.sessionToken.issueFailed` fires for a refusal. None of the three is audited: a client asks for a token every few minutes, and the session it is for is audited when it is created.

### The keys

The keys are derived from the master secret, one EdDSA key per secret version ([ADR-0002](../decisions/0002-deriving-external-jwt-keys.md)). The `kid` is the version. `/.well-known/jwks.json` publishes the public key of every version the secret source holds, so a token stays verifiable across a rotation as long as its version stays in the source. The route is outside the base path, where RFC 8615 puts well-known resources.

### Configuration

`BootConfig.JWT` is a `crypto.JWTConfig`, which is data:

| Field | Meaning |
| --- | --- |
| `Issuer` | the `iss` of every token. Empty means `RouterConfig.BaseURL`. One of the two is required once there is an external audience. |
| `Audiences[JWTExternal]` | the audiences of session tokens. Empty means the feature is off: neither route is mounted. |
| `TTL[JWTExternal]` | the lifetime. Zero means 15 minutes. |
| `JWKSPath` | where the key set is served. Empty means `/.well-known/jwks.json`. |

### Security rules

The route follows these security rules:

- **The route is a `POST`.** Under the cookie deliveries, the origin check refuses a request from another site, which a `GET` would not get.
- **A pending session gets no token.** A session that still waits for a second factor is not a signed-in user.
- **The token never reaches a cookie or a URL.** It is a bearer credential for another service. A cookie would send it with every request to Behemoth's host, and a URL ends up in logs and in `Referer` headers.
- **Behemoth never accepts a session token as a session.** `RequireSession` takes the session's own token only. A session token can't be used to call Behemoth's routes, so a service that receives one can't sign in as the user.
- **The algorithm comes from the key, not from the token's header** ([ADR-0002](../decisions/0002-deriving-external-jwt-keys.md)). A service should do the same, which every common JWT library allows.

## Other approaches

These are not built. They answer other needs, and any of them can exist next to session tokens.

### Introspection

A service posts a session's token to Behemoth and gets back whether it is active, and for whom (RFC 7662).

Introspection has these properties:

- **Revocation:** immediate.
- **Cost:** one call per request, which a service may cache for a few seconds, and the service has to authenticate to Behemoth, so that the route is not an oracle for stolen tokens.
- **Fits:** a few services, or an operation that has to see a sign-out at once. With `sid`, a service can use session tokens for most requests and introspect only for the sensitive ones.

### Forward authentication

A gateway in front of the services (nginx `auth_request`, Traefik `forwardAuth`, Envoy `ext_authz`) calls a route of Behemoth for every request. The route reads the session from the request and answers `200` with the user in headers, or `401`.

Forward authentication has these properties:

- **Revocation:** immediate.
- **Cost:** Behemoth is on the path of every request.
- **Fits:** services behind one gateway that should hold no authentication code at all. It is introspection with the request as its input, and the two could share most of their code.

### Behemoth as an OAuth 2.0 and OpenID Connect provider

Behemoth would issue tokens to other applications, with client registration, consent, the authorization code flow, and ID tokens. This is planned. Session tokens are laid out so that it fits later:

- **The keys and the key set** are the same. An OpenID Connect provider publishes its keys at a `jwks_uri`, which is the key set route.
- **The path `/token` is kept free** for the provider's token endpoint (RFC 6749, section 3.2). Session tokens use `/session/token`.
- **`iss`, `sub`, `sid`, and `aud`** have the meanings OpenID Connect gives them.
- **The issuer** is the provider's issuer, so a discovery document can name the same value.

## Never: a session token that is a JWT

`Not to be built.` The token that authenticates a session to Behemoth must stay an opaque random value, looked up in `sessions`, at any time. It must not be replaced by a self-contained JWT, not as an option, and not for "stateless sessions". The reasons:

- **Revocation stops working.** A sign-out, a revoked session, a deleted user, or a password change would leave the token valid until it expires. The session limits (`MaxConcurrent`) and the rolling expiry rest on the row too.
- **A key rotation ends every session**, or the old keys have to stay valid for as long as the longest session, which is days.
- **The token grows** with every claim, and travels with every request.
- **Session tokens already give** what a JWT session would: a credential other services verify without a call. They do it for 15 minutes, and next to a session that can still be revoked.

## Design decisions

### A token per audience, from a list

**Context:** Several services may accept session tokens. A token that every service accepts can be replayed from one to the other.

**Options considered:**

- *One audience for every service.* Simple. A service that leaks a token leaks a credential for all of them.
- *An audience the request names, from a configured list.* A token for service A is refused by B. The client asks for a token per service it calls.

**Decision:** the list, with its first entry as the default, so that a deployment with one service names nothing in its requests.

**Revisit if:** clients need one token for several services in one call. An `aud` array is a standard form, and the request could name several.

### A hook point adds the claims

**Context:** A service often needs more than the user's id: roles, a tenant, a plan.

**Options considered:**

- *No extra claims.* The service looks them up itself, with a call or a database of its own.
- *A function in the configuration.* Code in the options, which a configuration file can't carry (`service_ready_components.md`).
- *A before point whose payload has a `claims` object.* A plugin or the application adds claims, and a handler reachable over HTTP later can do it too, since the payload is data.

**Decision:** the before point, with the claims under `custom` so that they can't stand in for a registered claim.

**Revisit if:** services need claims at the top level, as some libraries read roles. A list of keys a handler may set there could be added.

### 15 minutes, set per deployment

**Context:** The lifetime is the delay of a revocation, and the rate at which clients come back for a new token.

**Decision:** 15 minutes by default, `JWTConfig.TTL[JWTExternal]` to change it. Shorter makes revocation quicker and costs more requests. A deployment that needs a sign-out to take effect at once adds introspection for the operations that need it.

## Implementation steps

| Step | Content | Status |
| --- | --- | --- |
| 1 | ADR-0002: `ExternalKeySet`, the key set derived from the master secret, the provider on it, and the stored key pairs removed | Done |
| 2 | `BootConfig.JWT`, the provider on `AuthContext`, and the key set route | Done |
| 3 | The session token flow, its hook points, `POST /session/token` and its rate limit, with tests and docs | Done |

## Where the code lives

| Piece | Code |
| --- | --- |
| the contract: `SessionTokens`, `SessionTokenRequest`, `SessionToken`, `PathSessionToken` | `core/session_tokens.go` |
| the flow and the route | `auth/session_tokens.go` (`DefaultSessionTokens`), `httpapi/session_tokens.go` (`SessionTokenRoutes`) |
| the JWT provider and the key set route | `crypto/jwt.go` (`JWTProviderImpl`) and `httpapi/key_set.go` (`KeySetRoutes`), with the set written by `crypto/jwk.go` (`MarshalJWKSet`) and external tokens checked by `crypto/verify.go` (`VerifyJWT`) |
| the derived keys | `crypto/external_keys.go` (`NewDerivedKeySet`) |
| `JWTConfig`, its defaults and its checks, `ExternalKeySet` | `crypto/contracts.go` |
| the wiring, the hook points, and `core.session_token.address` (30 a minute per address, a hook rule on `auth.sessionToken.beforeIssue`) | `engine/init.go` (`Boot`, `CoreDeclareHookPoints`, `CoreDeclareRateLimitRules`) |
| the tests | `crypto/jwt_test.go`, `tests/plugins/session_token_test.go` |

The flow reads the token back with `JWTProvider.Verify` after signing it, for its `jti` and `exp`. That keeps `Sign` returning a string, at the cost of one signature check per issued token.
