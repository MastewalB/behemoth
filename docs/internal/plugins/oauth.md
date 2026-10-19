# OAuth plugin

This document explains the part of `plugins/oauth` that is built: the provider contract, the options and their checks, `Begin`, the flow that starts a sign-in, `Complete`, the flow that finishes it, the two routes, and the three built-in providers. The plugin is not complete: it does not link accounts, and it does not store the provider's tokens.

[`../plans/oauth.md`](../plans/oauth.md) has the whole design: the components, the threats and their controls, the decisions, and the steps that remain. Read it first. This document covers how the built part works and the choices made while building it.

The code lives in:

- `plugins/oauth/oauth.go`: the plugin, its options, and `Init`
- `plugins/oauth/provider.go`: `Provider`, `Identity`, and the two request types
- `plugins/oauth/begin.go`: `Begin`
- `plugins/oauth/complete.go`: `Complete`, the lookup of the user, and the sign-up of a new one
- `plugins/oauth/routes.go`: the two routes and the binding cookie
- `plugins/oauth/builtin.go`: `ProviderConfig`, the kinds, and the checks of a configuration
- `plugins/oauth/protocol.go`: what the built-in providers share: the HTTP client, the code exchange, client authentication
- `plugins/oauth/oidc.go`: the OpenID Connect provider: discovery, the key set, the ID token
- `plugins/oauth/github.go`: the GitHub provider
- `core/token_carrier.go`: `TokenCarrier.Config`, which the routes read through `AuthContext.TokenCarrier`
- `store/seal.go`: `Store.Seal` and `Store.Open`, which `Begin` uses for the PKCE verifier

## What the plugin contributes

| `core.Plugin` method | Result |
| --- | --- |
| `Meta` | name `oauth`, no dependencies, no mount path |
| `Declare` | the `oauth_state` token kind, three hook points, and two rate-limit rules |
| `Register` | nothing |
| `Middlewares` | nothing |
| `Init` | checks `Options`, indexes the providers by id, and wraps `Complete` and its sign-up with core's points |
| `Routes` | `POST /sign-in/oauth`, `POST /oauth/complete` |

| Declared | Value |
| --- | --- |
| token kind | `core.TokenKindOAuthState`, single use, `Options.StateTTL` (10 minutes by default), database backend |
| hook points | `auth.oauth.beforeBegin` (before), `.afterBegin` (after), `.beginFailed` (failed). None is audited. |
| hook rule per address | `oauth.begin.address` on `auth.oauth.beforeBegin`: 10 a minute per client address (`core.KeyByClientIP`). A completion is a sign-in, which core's `core.signin.address` counts per address and method; `Complete` publishes `HookValueMethod` for it, and the sign-up of a new user inherits it |

`Complete` declares no point. It fires core's `auth.signIn.*` points, and `auth.signUp.*` for a user it creates.

Compare with the magic link plugin, which audits its request points. A link request is about an account. `Begin` needs no session and names no account, so an audit event for each call would record clicks on a button.

## The provider contract

`Provider` is the interface the flows call. It is exported, so an application can pass an implementation of its own.

| Method | Called by | Receives | Returns |
| --- | --- | --- | --- |
| `ID` | `Init`, `Begin` | | the provider's id |
| `AuthorizationURL` | `Begin` | the state, the redirect URI, the S256 challenge, the nonce | the URL to send the browser to |
| `Exchange` | `Complete` | the code, the redirect URI, the verifier, the nonce | an `ExchangeResult` with the `Identity` |

- **The id is stored.** It is the `provider_id` of the accounts the provider signs in, and the last segment of its redirect URI. Changing it separates users from their accounts.
- **The plugin can't check what a provider does with the challenge and the nonce.** A provider that leaves the challenge out of its URL has no PKCE, and nothing reports it. The built-in providers use both. An application's own provider is responsible for itself.
- **A provider tells a refusal from an outage.** `Exchange` wraps `ErrExchangeRefused` when the code was refused or its own checks failed. `Complete` then refuses the sign-in. Any other error is a failure of the system.
- **`ExchangeResult` is a struct with one field.** The provider's tokens join it when stored provider tokens are built. A new field does not break an implementation, and a changed return type would.

## What `Init` checks

Each failure is a configuration error from `Boot`.

| Check | Why |
| --- | --- |
| `StateTTL` is not negative | a token that expired before it was issued |
| `CallbackURL` is an absolute `http` or `https` URL without credentials, a query, or a fragment | the provider's id is appended as a path segment, and a provider refuses a redirect URI with a fragment |
| at least one provider, and none is nil | the plugin does nothing without one |
| an id is 1 to 64 characters of `a-z`, `0-9`, `-`, and `_`, and starts with a letter or a digit | it is a path segment and a `provider_id`, a column of 64 characters |
| an id is not `credential` | `models.ProviderCredential` is the `provider_id` of the account that holds a password |
| no two providers share an id | a request names a provider by its id |

## Starting a sign-in

`Plugin.Begin` builds the operation's `HookContext` and runs these steps:

| Step | What | On failure |
| --- | --- | --- |
| 1 | `RunBefore(auth.oauth.beforeBegin)` on `provider`, `redirect_url`, and the extra fields | `FailIfRejected`: `auth.oauth.beginFailed` with `rejected_by_hook` for a rejection |
| 2 | find the provider by its id | a validation error, code `provider_invalid_input` |
| 3 | check `RedirectURL` with `core.TrustedRedirect(ac.Origins, url)`, if one was given | a validation error, code `redirect_url_invalid_input` |
| 4 | create the PKCE verifier, the nonce, and the binding value: 32 random bytes each | a security error |
| 5 | `Store.Seal(verifier)` | the error is returned |
| 6 | `TokenManager.Issue(oauth_state, no subject, metadata)` | `FailIfRejected`, for a refusal on `token.beforeIssue` |
| 7 | `Provider.AuthorizationURL` with the state, the redirect URI, the S256 challenge, and the nonce. Then check that the URL is absolute `http` or `https`. | revoke the token, and return the error wrapped |
| 8 | `RunAfter(auth.oauth.afterBegin)` with a copy of the result that has no URL, no state, and no binding value | |

Steps 2 and 3 come before anything is written, so a refused request leaves no token.

The token's metadata is the authorization transaction:

| Key | Value | Why in this form |
| --- | --- | --- |
| `provider` | the provider's id | |
| `redirect_url` | the checked redirect target. Absent when none was given. | |
| `nonce` | the nonce, as it is | The provider puts it into the ID token, so it is not a secret. |
| `verifier_secret` | the PKCE verifier, sealed | Handlers on the token points and readers of the database see the metadata. |
| `binding_hash` | the SHA-256 of the binding value, in hex | The raw value is only in `BeginResult`. Finishing the sign-in compares hashes. |

Both key names end in a word the telemetry redactor knows (`secret`, `hash`).

Invariants:

- **The raw token is the state.** `Begin` hands it to the provider and returns it in `BeginResult.State`, and keeps no copy. Finishing a sign-in finds the transaction by consuming the state, which is also what makes a state single use.
- **The binding value is in no URL and in no row.** The authorization code and the state pass through the callback page's URL. If the binding value were there too, or in the database, whoever reads a URL or a row could finish somebody else's sign-in.
- **The token has no subject.** Nobody is signed in when it is issued. `Store.DeleteUser` and `RevokeAllForSubject` therefore never touch it.
- **A provider's error does not quote the URL.** The URL holds the state, and the error ends up in a log line.

The limits per client address are hook rules, so they hold for `Begin` and `Complete` called from any transport whose caller has an address. Code in the process has none and is not counted.

## Completing a sign-in

`Plugin.Complete` first refuses a request without a provider, a code, or a state, as a validation error. Nothing fires for it.

It then reads the state's token without consuming it (`TokenManager.Verify`). The checks before the consume need the token's metadata, and the result needs the redirect target. A state that does not check out still enters the flow, so its refusal fires `auth.signIn.failed` like any other.

`completeBody`, wrapped with core's three sign-in points:

| Step | What | On failure |
| --- | --- | --- |
| 1 | the state's token was found, and names a provider the plugin has | `Fail` with `invalid_oauth_state` |
| 2 | the request's provider is the token's | `Fail` with `oauth_provider_mismatch` |
| 3 | the SHA-256 of the binding value equals `binding_hash`, compared in constant time | `Fail` with `oauth_binding_mismatch` |
| 4 | `TokenManager.Consume(oauth_state, state)` | `Fail` with `invalid_oauth_state` |
| 5 | `Store.Open(verifier_secret)`, then `Provider.Exchange` with the code, the redirect URI, the verifier, and the nonce | `Fail` with `oauth_exchange_refused` for `ErrExchangeRefused`. Any other error is returned. |
| 6 | the identity has a subject | an error of the system: the provider's mistake, not the user's |
| 7 | `resolveUser`: find or create the user | see below |
| 8 | `RunBefore(auth.signIn.credentialsVerified)`; `requireStepUp` makes the session pending | `FailIfRejected`: `Fail` with `rejected_by_hook` for a rejection |
| 9 | `SessionManager.Create` | the error is returned |
| 10 | return a `*core.SignInResult` with `Method: "oauth"` | |

Every `Fail` of steps 1 to 5 answers with one typed unauthorized error, code `invalid_oauth_callback`. The audit event of `auth.signIn.failed` has the real code, and the provider in its metadata.

The payload on `auth.signIn.before` is `method` and `provider`, and it is veto only. The code, the state, and the binding value are not in it.

### Finding the user

`resolveUser` decides what an identity means for `users` and `accounts`:

| What it finds | Outcome | Code on `auth.signIn.failed` | Error |
| --- | --- | --- | --- |
| an account for `(provider, subject)` | sign in the account's user | | |
| that account, and its user is gone | refuse | `user_not_found` | `invalid_oauth_callback` (401) |
| no account, and no usable email in the identity | refuse | `email_not_provided` | `email_not_provided` (403) |
| no account, and a user with the email | refuse | `account_not_linked`, with that user as the subject | `account_not_linked` (409) |
| no account, and no user with the email | sign the user up | | |

A usable email is one that `utils.IsValidEmail` accepts and that fits the column.

The sign-up is an operation of its own, nested under the sign-in:

- **It fires `auth.signUp.before`, `.after`, and `.failed`.** The payload is `method`, `provider`, `email`, `email_verified`, `firstname`, `lastname`, and `image_url`, and it is veto only.
- **The user and the account are one transaction.** `auth.signUp.after` fires once it has committed, and before the session exists.
- **`email_verified` is the provider's statement.** `Identity.EmailVerified` sets it, and nothing else does.
- **The profile is taken as far as it goes.** A full name stands in when the provider gives no parts. A name is cut to 255 characters. A picture that is not an `http` or `https` URL is dropped.
- **No token of the provider is stored.** The account row has the provider's id and the subject.

Invariants:

- **Steps 1 to 3 run before the consume.** A request that fails one of them leaves the state usable. If the consume came first, whoever read a state in a URL could end the sign-in it belongs to.
- **The consume runs before the exchange.** Of two requests with one state, one loses before either reaches the provider. A state is not given back when a later step fails.
- **A user is found by the subject.** `FindUserByEmail` is called only to refuse. If it ever returned the user to sign in, every provider would open every account with a matching email.
- **A sign-in writes nothing to an existing user.** The provider's email, name, and picture are read at sign-up only.
- **`oauth_provider` is in `Values` from the start, and the email once it is known.** `oauth.HookValueProvider` is published before the first dispatch. `hooks.HookValueEmail` is published for a new subject, after the exchange, so a handler on `auth.signUp.before` and the failed points have it.

`[Limit]` `account_not_linked` tells whoever signed in at the provider that an account with the email exists. When the provider verified the email, that is the mailbox's holder. When it did not, it is anyone who can claim the address at that provider. The email/password sign-up already answers `email_taken` to anyone, so this adds no new way to learn it.

## The routes

Both routes are JSON `POST`s, so the origin check and the refusal of form content types cover them under the cookie deliveries. Each handler decodes the body, calls one flow, and encodes the result.

| Route | Flow | Answer |
| --- | --- | --- |
| `POST /sign-in/oauth` (`PathBegin`) | `Begin` | `{"authorization_url": ...}`, plus `binding` for a client without cookies, with `Cache-Control: no-store` |
| `POST /oauth/complete` (`PathComplete`) | `Complete` | `core.WriteSignIn` with `redirect_url` as the extra key |

Each flow is limited per client address on its before point, 10 a minute: `oauth.begin.address` for `Begin`, and core's `core.signin.address` for `Complete`.

### Where the binding value goes

The handlers read `AuthContext.TokenCarrier.Config()`: `RouterConfig.Carrier` with its defaults applied. The binding value follows the session token:

| `RouterConfig.Carrier.Delivery` | Begin's answer | Complete reads it from |
| --- | --- | --- |
| `DeliveryCookie` | a cookie only | the body, else the cookie |
| `DeliveryBoth` | a cookie and the body | the body, else the cookie |
| `DeliveryHeader`, `DeliveryBody` | the body only | the body |

Accepting a value from the body under `DeliveryCookie` costs nothing: a page there has no value to send, and a value somebody guessed does not match.

The cookie is built in `bindingCookie`:

| Attribute | Value | Why |
| --- | --- | --- |
| name | `__Host-behemoth_oauth_` and 16 hex characters of the state's SHA-256 | one cookie per sign-in, so two tabs don't overwrite each other's. The state itself stays out of the name. |
| `HttpOnly`, `Path=/`, no `Domain` | always | a script can't read it, and it goes only to Behemoth's host |
| `Secure` | unless `CookieInsecure` | |
| `SameSite` | the session cookie's | it has to reach the complete route on the requests the session cookie reaches. A front end on another site needs `SameSiteNone` for both. |
| `Max-Age` | until the sign-in expires | `Complete` sets `Max-Age=0` once the sign-in is done |

Invariants:

- **The `__Host-` prefix is what keeps a sibling subdomain out.** Without it, a page on `evil.example.com` could set a cookie for the parent domain with its own binding value, and send the victim's browser to the callback page with its own code and state. With `CookieInsecure` set the prefix can't be used, because a browser accepts it only on a `Secure` cookie, so that development setting loses this protection.
- **The binding value is in the body only for a delivery that already puts the session token where a script reads it.** Under `DeliveryCookie`, a script on the application's page can neither read the session token nor the binding value.

`[Limit]` A refused completion leaves its cookie until the sign-in expires. Only a successful one removes it.

## The built-in providers

`Options.Providers` is a list of `ProviderConfig`, which is data. `Init` turns each into a `Provider` with `newBuiltinProvider`, and checks the result like an application's provider in `Options.CustomProviders`: the ids of both lists share one namespace.

| Kind | Type | Protocol | User from |
| --- | --- | --- | --- |
| `oidc` | `oidcProvider` | OpenID Connect, endpoints from discovery | the ID token, then the userinfo endpoint when the token has no email |
| `google` | `oidcProvider` with Google's issuer | OpenID Connect | the ID token. `iss` may be `https://accounts.google.com` or `accounts.google.com`. |
| `github` | `githubProvider` | OAuth 2.0, fixed endpoints | `GET /user` and `GET /user/emails` |

What `newBuiltinProvider` refuses, each as a configuration error from `Boot`:

- a kind it does not know, a missing client id, and a `KindOIDC` provider without an id or an issuer
- a missing client secret for Google and GitHub, and a source whose current secret can't be read
- an issuer that is not `https` (or `http` on a loopback address), or has a query, and an issuer set for Google or GitHub
- scopes without `openid` for an OpenID Connect kind

`Init` calls no provider. Discovery and the key set are fetched at the first sign-in, so a provider that is down fails sign-ins and not the boot.

### The calls to a provider

`providerHTTP` makes every call, with `Options.HTTPClient`, or else `AuthContext.HTTPClient`, the client `Boot` builds from `BootConfig.Outbound`. The rules are the ones `outbound` gives every outbound call (ADR-0003, [`../http/outbound.md`](../http/outbound.md)):

| Rule | Where | Why |
| --- | --- | --- |
| 10-second timeout, by default | `outbound.NewClient` | a provider that hangs holds a sign-in request |
| no redirect followed, by default | `outbound.NewClient` | the code exchange sends the code, the verifier, and the client secret, and they go only to the configured endpoint |
| at most 1 MiB read of an answer | `outbound.GetJSON`, `outbound.PostForm` | a hostile or broken endpoint can't make the plugin read without end |
| `User-Agent: behemoth`, unless configured | `outbound.NewClient` | GitHub's API refuses a request without one |
| a span per call, `behemoth.outbound.request` | `outbound.NewClient` | a slow provider shows in the trace of the sign-in |
| the request's context | every call | a client that disconnects cancels the call |

A client in `Options.HTTPClient` keeps the rules it was built with. The option's comment asks for one built with `outbound.NewClient`, or one that follows no redirect. `Init` builds a client of its own only for an `AuthContext` that `Boot` did not build, which has no `HTTPClient`.

`redeemCode` is the one code exchange. It refuses with `ErrExchangeRefused` an answer that names an OAuth error, whatever its status: GitHub answers a refused code with `200`. Any other answer without an access token is a failure of the system. The client authenticates with HTTP Basic (id and secret form-encoded first, RFC 6749 section 2.3.1), in the form, or with its id alone for a public client. `authMethod` picks Basic unless the discovery document lists only `client_secret_post`. GitHub always gets the form. The client secret is read from its source for every exchange.

### The OpenID Connect provider

`oidcProvider` keeps the discovery document on the value, under its mutex, and a `crypto.CachedKeySet` for the document's `jwks_uri`, which has a mutex of its own:

| Cache | Fetched | Refetched |
| --- | --- | --- |
| discovery document | at the first sign-in | after `discoveryTTL`, 24 hours |
| key set | at the first ID token | after `keysTTL`, one hour, or when a token names a key the set lacks and the last fetch is older than `keyRefetchInterval`, one minute. While the set can't be fetched, its keys are used for `crypto.DefaultKeySetMaxStale`, one hour, past `keysTTL`. |

`document` builds the key set when the document is fetched, and keeps it, with its keys, while a new document names the same `jwks_uri`. The cache rules are those of [`../crypto/key_sets.md`](../crypto/key_sets.md#the-cached-key-set).

A replica keeps its own caches. That is fine: they hold what the issuer publishes, and a replica that fetches later sees the same.

The document is refused when its `issuer` is not exactly the configured one (OpenID Connect Discovery, section 4.3), or when the authorization, token, key set, or userinfo endpoint fails `outbound.CheckURL`. A failure here is a failure of the system.

`Exchange` checks, in this order:

| Check | Refusal |
| --- | --- |
| the `iss` parameter is the issuer, when one was sent; and one was sent, when the document says the issuer sends it (RFC 9207) | `ErrExchangeRefused` |
| the code is redeemed (`redeemCode`) | `ErrExchangeRefused` for an OAuth error |
| the answer has an ID token | a failure of the system |
| `verifyIDToken`, through `crypto.VerifyJWT`: the signature with an algorithm of `signingAlgs` and a key of the set; `aud` has the client id; `exp` is required, and `exp` and `iat` are checked with one minute of leeway; `iss` is one of the provider's issuers. Then the rules of OpenID Connect: `azp` is the client id when there is one or several audiences; `nonce` is the sign-in's; `sub` is not empty. | `ErrExchangeRefused`, wrapping the `CategoryToken` error of `VerifyJWT`. Any other error of `VerifyJWT`, such as a key set that can't be fetched or has no usable key, is a failure of the system. |
| without an email in the token: the userinfo endpoint's `sub` is the token's | `ErrExchangeRefused` |

`signingAlgs` holds the RSA, RSA-PSS, and ECDSA algorithms, and `VerifyJWT` refuses every symmetric one anyway. A key's own algorithm, and its type, have to fit the token's (`fits`), so an HMAC token would fail twice: no HMAC algorithm is allowed, and no symmetric key is ever in the set.

The set comes through a `keysource.JWKSet` on the plugin's client, and `crypto.ParseJWKSet` decides which keys are kept. An Ed25519 key can be in the set, but no ID token is accepted with `EdDSA`, since `signingAlgs` does not list it. A set without a usable key is `keysource.ErrNoUsableKey`, a failure of the system, and not a refused token: no ID token could be checked with it.

An ID token without a `kid` is checked against every key of the set that fits its algorithm (`AllowMissingKID`). The plugin's rule before `VerifyJWT` accepted one only when exactly one key fitted, which refused every such token while a provider published two keys of one type.

`email_verified` counts as true when it is the boolean `true` or the string `"true"`. Some providers send the string.

### The GitHub provider

`githubProvider` redeems the code at `https://github.com/login/oauth/access_token`, then calls `GET /user` and `GET /user/emails` with the access token:

- **The subject is the numeric `id`,** as a string. A login can be renamed, and the old one taken by somebody else.
- **The email is the primary address, and only when GitHub verified it.** The other addresses are ignored. Without the `user:email` scope, `/user/emails` answers `404`, and the identity has no email.
- **GitHub names no issuer,** so an `iss` parameter is not checked.

`[Limit]` The ID token's `at_hash` is not checked. In the code flow the ID token comes from the token endpoint over TLS, and OpenID Connect Core makes the check optional there.

`[Limit]` A Microsoft endpoint for several tenants publishes a discovery document whose `issuer` holds a `{tenantid}` placeholder. The exact comparison refuses it, so such a provider works only with the endpoint of one tenant.

## Design decisions

### One redirect URI per provider, derived from `CallbackURL`

**Context:** A redirect URI per provider is the control against provider mix-up: finishing a sign-in can compare the page a code arrived at with the provider the state names. The application also needs a page for the provider to send the browser to.

**Options considered:**

- *A redirect URI in each provider's own configuration.* Any shape of URL works. The plugin can't know the URI of a provider an application implements, and nothing stops two providers from sharing one.
- *One `CallbackURL`, with the provider's id as a query parameter.* One page for the application. The id then shares the query with the `code` and the `state` the provider adds, and `CallbackURL` could no longer be required to have no query.
- *One `CallbackURL`, with the provider's id appended as a path segment.* One option, one route with a parameter in the application, and the URIs can't collide because the ids can't. The application's route has to have that shape.

**Decision:** the path segment. `oauth.RedirectURI` returns the URI, so an application registers the same string the plugin sends.

**Revisit if:** an application can't serve `<CallbackURL>/<id>`, for example because a provider's console accepts one fixed URI that is already in use.

### The state token is kept in the database

**Context:** The plan notes that the key-value backend suits `oauth_state`, because an entry there expires by itself. A token kind names one backend when it is declared, before `Boot` knows whether a key-value storage exists.

**Options considered:**

- *The key-value backend.* No row outlives its sign-in. `Boot` fails for an application without a key-value storage.
- *The database backend.* The plugin works wherever core does. Used and expired rows stay, since nothing purges tokens.
- *An option.* Each application picks. One more setting, for a problem that a purge of tokens solves for every kind.

**Decision:** the database backend.

**Revisit if:** a purge of tokens is not built and the rows become a problem. "Nothing removes old sessions, tokens, or rate-limit counters" in `docs/ongoing.md` is the entry.

### Handlers on the after point do not get the URL or the binding value

**Context:** `core.WithLifecycle` hands the flow's result to the after point as it is. `Begin`'s result holds the authorization URL, which holds the state, and the binding value. Hook handlers are planned to be reachable in other processes, as `service_ready_components.md` describes.

**Options considered:**

- *`WithLifecycle`, with the full result.* The shortest code, and what the sign-in points do with a session token. Every handler and every forwarder then holds what finishes the sign-in.
- *Write the three dispatches out in `Begin`, and give the after point a copy without the two fields.* About fifteen lines that repeat `WithLifecycle`. A handler learns the provider, the transaction's id, and the expiry.

**Decision:** the copy. `Begin` calls `AsOperation`, `RunBefore`, `FailIfRejected`, and `RunAfter` itself.

**Revisit if:** a second flow needs the same, and `WithLifecycle` gets a way to say what the after point receives.

### `Store.Seal` and `Store.Open` are exported

**Context:** The verifier has to be sealed before it goes into the token's metadata. The store's sealing was private, and its form (`v<key version>:<base64>`) is what a re-encryption sweep selects on.

**Options considered:**

- *Repeat the form in the plugin, over `ac.Crypto.AtRest`.* No change to the store. Two places then define what a sealed value looks like.
- *Package functions that take an `Encryptor`.* Usable without a store. A plugin has the store at hand, and would have to pass the same encryptor the store already holds.
- *Two methods on `Store`.* One form, one encryptor, and nothing new to configure.

**Decision:** `Store.Seal` and `Store.Open`. A plugin with a secret column of its own uses the same two methods.

**Revisit if:** code without a store needs to seal a value.

### The checks that need no write run before the consume

**Context:** A state has to be single use, and the consume is what makes it so. The state travels in two URLs, so more people can read it than can finish the sign-in.

**Options considered:**

- *Consume first, then check.* One read of the token. Any request with a valid state ends the sign-in, whether or not it has the binding value.
- *Read, check, then consume.* Two reads. A request without the binding value changes nothing. The checks run on a token that may be consumed a moment later, which the consume itself catches.

**Decision:** read, check, then consume. `Complete` hands the token it read to the flow, so the flow does not read it a second time.

**Revisit if:** the token's metadata can change after it is issued. The checks would then have to run on what the consume returns.

### One error code for a refused callback

**Context:** A callback can be wrong in several ways: the state, the binding value, the provider, or the code. A client does the same thing for all of them: it starts the sign-in again.

**Options considered:**

- *A code per cause.* A developer sees at once what failed. The answer also tells a caller without the binding value that the state it tried is valid.
- *One code.* The response says nothing about which part was wrong. The cause is in the audit event and the log.

**Decision:** one code, `invalid_oauth_callback`, as the magic link plugin answers every refused link with `invalid_magic_link`. `account_not_linked` and `email_not_provided` have their own, because the user has to do something different for each.

**Revisit if:** client developers can't find the cause of a refusal in practice.

### A new user's sign-up is a nested operation with a veto-only payload

**Context:** A first sign-in creates a user. Handlers and counters for sign-ups are attached to `auth.signUp.*`, which the email/password plugin fires.

**Options considered:**

- *Create the user inside the sign-in and fire no sign-up point.* Less code. A handler that keeps a domain out, a welcome email, and the sign-up counter would all miss these users.
- *Fire `auth.signUp.*` with a payload a handler can rewrite, as for an email sign-up.* One contract for both. A handler could then change the email the provider reported.
- *Fire `auth.signUp.*` with a veto-only payload.* A handler can refuse and can read the profile. The payload has `method` and no `password`, so a handler written for email sign-up has to allow for that.

**Decision:** the veto-only payload, in an operation nested under the sign-in. A refused sign-up fires `auth.signUp.failed` and then `auth.signIn.failed`: both operations failed.

**Revisit if:** applications need to complete a new user's profile at this point. A data hook on `data.user.beforeCreate` already can.

### A sign-up that loses a race is resolved once more

**Context:** Two callbacks of one new person can both find no account and no user, for example from two tabs. The second insert fails on a unique index.

**Options considered:**

- *Return the store's error.* No code. The loser gets a `409` with the store's code for a sign-in that should have worked.
- *Look again, once.* By then the winner has committed. The loser signs in the winner's user, or is refused with `account_not_linked` when the winner was a sign-up with the same email by another way.

**Decision:** look again, once. A second duplicate is returned as it is.

**Revisit if:** the store gains a retry for writes that lose a race.

### The binding value follows the session token

**Context:** A started sign-in hands the client a binding value that it shows again at completion. A browser client of the cookie deliveries should not be able to read it from a script, and a client without cookies has nowhere else to keep it.

**Options considered:**

- *Always a cookie.* One behavior. A native application, whose callback runs in the system browser, does not have the cookie when it completes the sign-in.
- *Always the body.* One behavior. A script on the page can read a value that an `HttpOnly` cookie would keep from it, which the cookie deliveries exist to avoid.
- *The way the session token travels.* A client that already handles the session token one way handles the binding value the same way. The plugin needs to know the delivery.

**Decision:** the way the session token travels. `Boot` puts the session settings on `AuthContext` as `SessionConfig`. The settings and not only the transport, because the cookie also needs the session cookie's `SameSite` and `Secure`.

The settings have since moved with the HTTP side of the session manager to the token carrier, as this decision expected. The handlers read them from `AuthContext.TokenCarrier.Config()`, and the transport is now called the delivery. See *The token travels with a carrier of its own* in [`../sessions/token_delivery.md`](../sessions/token_delivery.md).

### One binding cookie per sign-in

**Context:** A user can start two sign-ins in one browser, from two tabs or with a second click.

**Options considered:**

- *One cookie for all sign-ins.* One name. The second sign-in overwrites the first one's value, and completing the first fails.
- *A cookie per sign-in, named after the state.* Each sign-in finds its own. A browser keeps a cookie for every sign-in that was started and not completed, until it expires.

**Decision:** a cookie per sign-in. The name has 16 hex characters of the state's SHA-256, which the complete route computes from the state in the body.

**Revisit if:** applications report hitting a browser's limit on cookies per host.

### Built-in providers are data, and the application's providers are a second list

**Context:** `service_ready_components.md` asks for a data form next to an option that is an interface ("The OAuth plugin's providers are Go values" in `docs/ongoing.md` until this step). `Options.Providers` was the list of `Provider` values.

**Options considered:**

- *Constructors, such as `oauth.Google(cfg)`, that return a `Provider`.* Short in Go. A configuration file still can't name a provider, and a service would have to map each kind to a constructor itself.
- *A second option for the data, next to `Providers`.* No rename. The common case gets the longer name.
- *`Providers` for the data, and `CustomProviders` for the application's own.* The common case reads naturally. The plugin's earlier `Options.Providers` changes type, which an experimental plugin can still do.

**Decision:** `Providers []ProviderConfig` and `CustomProviders []Provider`.

**Revisit if:** a kind needs a setting that is code, such as a function. It would get a data form of its own.

### The client secret is a `SecretSource`, read for every exchange

**Context:** A client secret is a secret, which `service_ready_components.md` keeps out of the options. The core already has `SecretSource`, built for versioned keys: a map of secrets and the current version.

**Options considered:**

- *A string field.* Simple. It ends up in a configuration file and is printed with it.
- *A source of its own, with one value.* A new interface for one use.
- *`SecretSource`, using its current secret.* The type that a file or environment source implements anyway. A source with one entry is a little verbose.

**Decision:** `SecretSource`. `Init` reads it once to fail early, and every code exchange reads it again, so a rotated secret takes effect at once.

**Revisit if:** sources that are slow to read appear. The exchange would then cache the secret for a short time.

### Discovery happens at the first sign-in, not at `Boot`

**Context:** An OpenID Connect provider is described by its issuer, and its endpoints come from a document on the network.

**Options considered:**

- *Fetch at `Init`.* A wrong issuer fails the boot, where `service_ready_components.md` wants a wrong value to fail. A provider that is down also fails the boot, and with it every other way to sign in.
- *Fetch at the first use, and keep it.* The boot does not depend on the provider. A wrong issuer shows up at the first sign-in, as a failure of the system.

**Decision:** at the first use. `Init` checks everything it can without the network: the issuer's form, the client id, the secret.

**Revisit if:** applications ask for a check at start. A method that fetches every provider's document could be called by the application after `Boot`.

### An unknown key is fetched at most once a minute

**Context:** An issuer rotates its keys, and the key set is cached. A token that names a key the cache lacks is either newly signed or forged.

**Options considered:**

- *Fetch the set for every unknown key.* A rotation is picked up at once. Anybody can make the plugin call the issuer by sending tokens with made-up key ids.
- *Fetch on a schedule only.* No call can be caused from outside. A rotation fails sign-ins until the next fetch.
- *Fetch for an unknown key, at most once a minute, and every hour anyway.* At most one call a minute can be caused, and a rotation fails sign-ins for a minute at most.

**Decision:** the third. Issuers publish a new key before they sign with it, so in practice the hourly fetch already has it.

**Revisit if:** an issuer rotates without publishing ahead, and the minute shows up as failed sign-ins.

### GitHub's subject is its numeric id, and its email is the primary verified address

**Context:** GitHub has no ID token. Its API returns a login, a numeric id, and a list of addresses.

**Options considered:**

- *The login as the subject.* Readable. A renamed login can be taken by somebody else, who would then sign in to the first user's account.
- *The numeric id as the subject.* It never changes.
- *For the email, the public address on the profile.* One call less. Whether GitHub verified it is not part of that answer.
- *For the email, the primary address from `/user/emails`, when it is verified.* One more call, and the `user:email` scope. The address is one GitHub verified.

**Decision:** the numeric id, and the primary verified address. A user whose primary address is not verified has no email, and a first sign-in is refused with `email_not_provided`.

**Revisit if:** users with a verified address that is not primary are refused in practice. Another verified address could stand in.

## Deferred

Each item is a step of the plan:

- `Deferred:` linking: the link intent, the option that links by a verified email, and the link, unlink, and list routes. Until then a new subject whose email belongs to a user is always refused.
- `Deferred:` stored provider tokens.
