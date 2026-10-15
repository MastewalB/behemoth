# 0003. Verify remote JWTs in `crypto` over a key source, and call other services through one client

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** MastewalB
- **Affects:** `crypto`, `types/cryptotypes` (`KeySet`, `ExternalKeySet`), `outbound` (new), `keysource` (new), `types` (`AuthContext`), `types/init` (`Boot`, `BootConfig`), `telemetry`, `plugins/oauth`

## Context and problem

Two pieces of work meet here.

**Verifying JWTs that someone else signed.** `plugins/oauth/oidc.go` checks a provider's ID tokens. It turns JWKs into keys, fetches and caches the provider's key set with a limit on refetches, and checks the signature and the registered claims against an allowlist of algorithms. `crypto/jwt.go` does the same for Behemoth's external tokens, against the key set derived from the master secret (ADR-0002). Algorithm pinning, key lookup and claim checks exist twice. A third user is coming: a service, or an SDK, that verifies Behemoth's session tokens with the published key set (`docs/api/session-tokens.md`).

**Calling other services.** The OAuth plugin is the only code that makes outbound calls today. It has its own rules for them: a timeout, no redirects, a cap on the answer, and a user agent (`plugins/oauth/protocol.go`). More callers are planned: hook callouts and a mail sender that posts to a URL (`service_ready_components.md`), and the key set fetch above. Nothing gives them the same rules, and no outbound call shows in a trace.

An earlier proposal moved the remote key set into `crypto`, with an `*http.Client` passed in. `crypto` would then call the network, and its key sets would assume HTTP.

## Decision drivers

In priority order:

1. One implementation of JWT verification, for Behemoth's tokens and for other issuers' tokens.
2. `crypto` makes no outbound call. It computes, and it is tested without a server.
3. The key set contract names no protocol. Keys may come over HTTPS, from a file the platform mounts, or from a KMS SDK.
4. Every outbound call gets the same safe defaults without its caller having to remember them.
5. No abstraction over protocols for requests in general. `transport_neutral_flows.md` rejects one for inbound requests ("Thin wrappers per transport, without a shared transport interface"), for the same reasons.

## Options considered

### Option A: leave the verification where it is
The plugin keeps its own verifier, and `crypto` keeps its own.
- **Pros:** no work, and no API designed ahead of its users.
- **Cons:** two implementations of the checks that matter most. An SDK that verifies session tokens would need a third, or would import an OAuth plugin to get one.
- **Fails when:** a fix to algorithm pinning or key rotation is made in one place and not the other.

### Option B: move verification and the remote key set into `crypto`
`crypto.NewRemoteKeySet(url, client)` fetches the key set itself.
- **Pros:** one package for everything about JWTs.
- **Cons:** `crypto` makes network calls, and the key set is tied to HTTP: a KMS or a mounted file would need a second kind of key set with the same caching.
- **Fails when:** keys have to come from anywhere but an HTTP URL, or a test of the caching needs a server.

### Option C: verification in `crypto` over a key source, with sources and one outbound client outside it
`crypto` verifies against a `KeySet`, and caches keys from a `KeySource`. The sources do the I/O. Outbound HTTP calls go through one client that a new package builds.
- **Pros:** `crypto` stays free of I/O, the caching is tested with a fake source and a clock, and a source can be any protocol. The safe defaults live in one place.
- **Cons:** one more interface (`KeySource`) and one more package (`outbound`).
- **Fails when:** a source needs more from the cache than keys, such as the time the set may be cached for. The interface would grow.

### Option D: a client interface that hides the protocol
One `Client` with HTTP and gRPC implementations, used for every outbound call.
- **Pros:** callers don't name a protocol.
- **Cons:** HTTP and gRPC differ in status, headers, streams, and errors. The shared type would carry what means nothing on one of them, and callers would depend on the protocol after all.
- **Fails when:** a caller needs a header, a status, or a stream, which every caller of the token exchange does.

## Decision

We chose Option C.

| Layer | Owns | Network |
| --- | --- | --- |
| `types/cryptotypes` | `KeySet` (`PublicKey`, `PublicKeys`), and `ExternalKeySet`, a `KeySet` that also signs | none |
| `crypto` | `VerifyJWT`, the JWK codec, `KeySource`, and the key set that caches a source | none |
| `keysource` | the sources: a JWK set fetched over HTTPS (`JWKSet`), built on `outbound`; later a file. A KMS SDK goes in a module of its own. | each its own |
| `outbound` | the client every outbound HTTP call goes through, helpers that read a bounded answer, and the rule for a URL that receives a credential or serves a key (`CheckURL`) | HTTP |
| `plugins/oauth` | discovery, and the OpenID Connect rules: `nonce`, `azp`, Google's two issuer forms, `email_verified`, userinfo | through `outbound` and a source |

The shape, to be settled in the implementation:

```go
// crypto
type KeySource interface {
	// Keys returns the set's keys as they are now. An error is a failure
	// of the system.
	Keys(ctx context.Context) ([]types.PublishedKey, error)
}

func NewCachedKeySet(src KeySource, opts CacheOptions) (*CachedKeySet, error) // a types.KeySet
func ParseJWKSet(data []byte) ([]types.PublishedKey, error)
func MarshalJWKSet(keys []types.PublishedKey) ([]byte, error)
func VerifyJWT(ctx context.Context, token string, keys types.KeySet, opts VerifyOptions) (*VerifiedJWT, error)

// keysource
func NewJWKSet(client *http.Client, url string) (*JWKSet, error) // a KeySource

// outbound
func NewClient(opts Options, tel *telemetry.Telemetry) *http.Client
func CheckURL(raw string) error
```

This refines ADR-0002: `ExternalKeySet` becomes a `KeySet` that also signs, so that a key set that can only verify, such as a provider's, implements `KeySet` alone.

The questions this raised are settled as follows:

- **The sources are in package `keysource`,** which imports `crypto` and `outbound`. `outbound` stays free of key formats, and `crypto` of network calls. `docs/internal/crypto/key_sets.md` has the options.
- **The package is `outbound`.** `transport` already names the managers' package and `TokenTransport` (`docs/ongoing.md`, "The session manager also carries the token over HTTP").
- **`AuthContext.HTTPClient` is the shared client.** `Boot` builds it from `BootConfig.Outbound`. A plugin uses it unless an option of the plugin replaces it.
- **An address guard is not built yet.** It would refuse private, loopback, and link-local addresses for URLs that come from a configuration file, and it comes with the standalone service. `outbound.Options` says where it goes.
- **Outbound calls are traced from the first version**: one span per call, `behemoth.outbound.request`, with the method, the host, and the status. The telemetry is a parameter of `NewClient`, not an option, and `Boot` passes its own.

## Rationale

Option C meets drivers 1 to 3 by keeping the parts apart that change for different reasons: the checks change with the JWT specifications, the caching with rotation policy, and the sources with where keys live. Option B meets driver 1 and loses 2 and 3. Option A loses 1, which matters most: verification is where a mistake turns into a forged sign-in.

Driver 4 is met by one constructor and not by a wrapper type. The client is a plain `*http.Client`, so anything that takes one works with it, a cloud SDK included. Option D loses driver 5, and gains nothing a caller needs.

## Consequences

- **Gains:**
  - one verifier, used by the OAuth plugin, by Behemoth's external tokens, and by a future SDK;
  - key caching tested without a network;
  - every outbound call with a timeout, no redirects, a bounded answer, a user agent, and a span.
- **Costs and risks we accepted:**
  - `KeySource` and `outbound` are two more things to learn;
  - the shared client does not retry, so a caller that needs retries writes them for its own calls;
  - the default transport takes the proxy from the environment, as Go's does, which `service_ready_components.md` asks core not to do ("Core reads no environment, file or flag"). `docs/internal/http/outbound.md` has the reasoning.
- **Follow-up work,** all four steps done on 2026-10-14:
  1. `outbound`, `BootConfig.Outbound`, `AuthContext.HTTPClient`, and the OAuth plugin on them;
  2. the JWK codec, and the JWK set source (`keysource`) on `outbound`;
  3. the `KeySet` split, the cached key set, and `VerifyJWT`, with the external tokens moved onto it;
  4. `oidc.go` on the cached key set and `VerifyJWT`, keeping only the OpenID Connect rules.

## Invariants

- **`crypto` makes no outbound call.** A key set that needs the network gets its keys from a source.
- **A source's error is a failure of the system.** A token whose `kid` the set lacks even after a refetch is a refused token (`CategoryToken`).
- **A token's algorithm comes from its key.** For a key that names none, it comes from the caller's allowlist, and has to fit the key's type. It never comes from the token's header alone.
- **The shared client follows no redirect unless its options say so, and never retries.** An authorization code works once, and a redirect could take a client secret elsewhere.
- **The client is a plain `*http.Client`.** No interface wraps it.

## Revisit when

- Keys have to come over another protocol, such as gRPC. Write a source for it in a module of its own.
- URLs come from a configuration file, as in the standalone service. Build the address guard.
- A caller needs retries. Give that caller a policy of its own, rather than the shared client.

## References

- [ADR-0002](0002-deriving-external-jwt-keys.md): the derived key set, refined here by the `KeySet` split
- `plugins/oauth/oidc.go`, `plugins/oauth/protocol.go`: the verification and the client rules this moves
- `docs/internal/http/outbound.md`: the client as built in step 1
- `docs/internal/crypto/key_sets.md`: the codec and the sources as built in step 2, and the cached key set and `VerifyJWT` as built in step 3
- `crypto/jwt.go`: the verification of Behemoth's external tokens
- `docs/internal/guidelines/transport_neutral_flows.md`: why no shared transport interface
- RFC 7517: the JWK set format
