# Session tokens

A session token tells another service who a request is from. A signed-in client exchanges its session for a short-lived JWT, sends it to the service, and the service checks it with Behemoth's published keys. Behemoth is not called on those requests.

Use session tokens when your API, a worker, or a service in another language has to know the signed-in user, and does not share your application's process.

## How it works

| Step | Who | What happens |
| --- | --- | --- |
| 1 | client | posts to `POST /session/token` with its session |
| 2 | Behemoth | checks the session and returns a JWT valid for 15 minutes |
| 3 | client | calls the service with `Authorization: Bearer <token>` |
| 4 | service | checks the token with the keys at `/.well-known/jwks.json` |
| 5 | client | asks for a new token before the old one expires |

## Setup

Name the services that accept session tokens in `BootConfig.JWT`:

```go
ac, err := engine.Boot(ctx, app, db, engine.BootConfig{
	JWT: crypto.JWTConfig{
		Issuer: "https://auth.example.com",
		Audiences: map[crypto.JWTKind][]string{
			crypto.JWTExternal: {"https://api.example.com", "https://reports.example.com"},
		},
	},
	// ...
})
```

| Field | Default | Meaning |
| --- | --- | --- |
| `Issuer` | `RouterConfig.BaseURL` | The `iss` of every token. One of the two is required once an external audience is named. |
| `Audiences[crypto.JWTExternal]` | none | The services a token may be issued for. The first is the default. Without any, session tokens are off and neither route is mounted. |
| `TTL[crypto.JWTExternal]` | 15 minutes | How long a token is valid. |
| `JWKSPath` | `/.well-known/jwks.json` | Where the keys are published, outside the router's base path. |

`Boot` returns a configuration error for an external audience without an issuer, an empty audience, a negative lifetime, and a key set path that does not start with `/`.

The signing keys are derived from your master secret (`crypto.Config.Secrets`), one per secret version. There is nothing to create or store. When you rotate the secret, keep the previous version in the source for at least the token lifetime: a token signed with a version that is gone no longer verifies.

## Routes

| Route | Body | Result |
| --- | --- | --- |
| `POST /session/token` (`core.PathSessionToken`), below the base path | empty, `{}`, or `{"audience": "..."}` with one of the configured audiences | `200` with `{"token": "...", "expires_at": "2026-10-14T10:15:00Z", "audience": "..."}`, sent with `Cache-Control: no-store` |
| `GET /.well-known/jwks.json` | none | `200` with the public keys as a JWK set (RFC 7517), sent with `Cache-Control: public, max-age=300` |

The token route requires an active session, sent the way `RouterConfig.Carrier.Delivery` says. It answers like every protected route when there is none.

| When | Status | Code |
| --- | --- | --- |
| the body is not JSON | `400` | `request_validation_error` |
| `audience` is not a string, or not a configured audience | `400` | `audience_invalid_input` |
| no session, an invalid, revoked, or expired one | `401` | `session_missing`, `session_invalid`, `session_revoked`, `session_expired` |
| a session that waits for a second factor | `401` | `session_pending` |
| a hook handler rejected the token with a typed error | the error's status | the error's code |
| more than 30 requests a minute from one address (`engine.RuleSessionTokenAddress`) | `429` with `Retry-After` | `rate_limited` |

## The token

The header is `{"alg": "EdDSA", "typ": "JWT", "kid": "<secret version>"}`. The claims:

| Claim | Value |
| --- | --- |
| `iss` | `JWTConfig.Issuer` |
| `aud` | the audience of the request |
| `sub` | the user's id |
| `sid` | the session's id |
| `iat`, `exp` | when it was issued, and when it expires |
| `jti` | a random id of the token |
| `custom` | claims a hook handler added. Absent when there are none. |

## Verify a token in a service

A service fetches the key set, caches it, and checks every token against it:

- the signature, with the key whose `kid` the header names, and the algorithm `EdDSA` only
- `iss` is the issuer, and `aud` names the service itself
- `exp` has not passed

Every common JWT library does this. In Go, use `crypto.VerifyJWT` with a cached key set over the route:

```go
source, err := keysource.NewJWKSet(nil, "https://auth.example.com/.well-known/jwks.json")
if err != nil {
	return err
}
keys, err := crypto.NewCachedKeySet(source, crypto.CacheOptions{})
if err != nil {
	return err
}

// For each request:
verified, err := crypto.VerifyJWT(ctx, token, keys, crypto.VerifyOptions{
	Issuers:    []string{"https://auth.example.com"},
	Audiences:  []string{"https://api.example.com"},
	Algorithms: []string{"EdDSA"},
})
```

`verified.Subject` is the user's id, and `verified.Claims` decodes `sid` and `custom`. The key set keeps the keys for five minutes, the `max-age` of the route, and fetches them again when a token names a `kid` it lacks. See [JWT verification](jwt-verification.md) for the checks, the errors, and the cache.

With another library, decode each key's `x` member (`OKP`, `Ed25519`), look it up by `kid`, and fetch the set again when a token names a `kid` you don't have.

A service checks that `aud` names itself, so a token issued for one service is refused by the others. Ask for a token per service you call.

## Revocation

A session that ends gets no new token. A token already issued stays valid until it expires, so the lifetime is how long a sign-out takes to reach other services. Keep it short. A service that has to see a sign-out at once needs to ask Behemoth, which session tokens don't do.

A session token is a credential for other services only. Behemoth never accepts one as a session: sent to a Behemoth route as a bearer token, it is refused with `session_invalid`. Don't put a session token in a cookie or a URL.

## Hooks

| Point | Phase | What the handler gets |
| --- | --- | --- |
| `auth.sessionToken.beforeIssue` (`hooks.HookSessionTokenBeforeIssue`) | before | payload `userID`, `sessionID`, `audience`, and `claims`, an empty object. Set keys of `claims` to add them to the token under `custom`. Nothing else is read back. Return an error to refuse the token. |
| `auth.sessionToken.afterIssue` (`hooks.HookSessionTokenAfterIssue`) | after | a `*core.SessionToken` without the token: its id, user, session, audience, and expiry |
| `auth.sessionToken.issueFailed` (`hooks.HookSessionTokenIssueFailed`) | failed | code `rejected_by_hook` |

`hctx.Values[hooks.HookValueUserID]` and `hctx.Values[hooks.HookValueSessionID]` hold the user and the session on all three, for a rate-limit rule per user or per session. None of the three is audited.

```go
reg.OnBefore(hooks.HookSessionTokenBeforeIssue, func(hctx *core.HookContext, payload behemoth.M) (behemoth.M, error) {
	userID, _ := payload[hooks.HookValueUserID].(string)
	claims, _ := payload[core.SessionTokenClaimsKey].(behemoth.M)
	claims["roles"] = ROLES_OF(userID)
	return payload, nil
}, nil)
```

Replace `ROLES_OF` with your own lookup.

## Call the flow from code

`ac.SessionTokens.Issue` is the flow behind the route, for a transport other than HTTP:

```go
issued, err := ac.SessionTokens.Issue(ctx, core.SessionTokenRequest{Session: session, Audience: "https://api.example.com"})
// issued.Token, issued.ExpiresAt, issued.ID
```

`session` is a session your code has validated, such as the one `ac.SessionManager.Validate` returns. A pending or expired session is refused with its session code. With session tokens off, `Issue` returns a configuration error with the code `external_jwt_not_configured`.
