# Outbound calls

Every outbound HTTP call behemoth makes goes through a client that `outbound.NewClient` builds. This document covers the rules that client applies, how `Boot` hands it to plugins, and what is not built. [ADR-0003](../decisions/0003-remote-jwt-verification-and-outbound-calls.md) is the decision behind it (Proposed, 2026-10-14), and [`../../api/outbound.md`](../../api/outbound.md) is the API guide.

## Goals and non-goals

Goals:

- every outbound call has the same safe defaults, without its caller having to remember them
- an outbound call shows in the trace of the request that caused it
- the client is a plain `*http.Client`, so a library or a cloud SDK that takes one gets the same rules

Non-goals:

- an abstraction over protocols. A gRPC call belongs in a package or a module of its own, as `transport_neutral_flows.md` decides for inbound requests.
- retries. A caller whose calls can be repeated writes the retry for its own calls.
- network calls from `crypto`. A key set that needs the network gets its keys from a source built on `outbound` (step 2 of the ADR's follow-up work).

## Where it sits

| Piece | File | Role |
| --- | --- | --- |
| `Options` | `outbound/outbound.go` | the settings: timeout, redirects, user agent, transport |
| `NewClient(opts, tel)` | `outbound/outbound.go` | a `*http.Client` with the rules applied |
| `roundTripper`, `spanBody` | `outbound/outbound.go` | the user agent and the span, around `Options.Transport` |
| `Do`, `ReadLimited` | `outbound/outbound.go` | send a request, and read a bounded answer |
| `GetJSON`, `PostForm` | `outbound/helpers.go` | the two shapes of call the OAuth plugin makes |
| `CheckURL` | `outbound/url.go` | the rule for a URL that receives a credential or serves a key: `https`, or `http` on a loopback address |
| `BootConfig.Outbound`, `AuthContext.HTTPClient` | `engine/init.go`, `types/auth-context.go` | one client per `Boot`, built before any plugin's `Init` |
| `providerHTTP` | `plugins/oauth/protocol.go` | the OAuth plugin's calls, on `Options.HTTPClient` or else `AuthContext.HTTPClient` |

## The rules

| Rule | Where | Why |
| --- | --- | --- |
| a timeout, 10 seconds by default, that covers reading the body | `http.Client.Timeout` | a service that hangs holds the request that called it |
| no redirect, unless `FollowRedirects` | `CheckRedirect` returns `http.ErrUseLastResponse` | a request that carries a credential reaches only the URL it was sent to. The caller sees the `3xx` as the answer. |
| a user agent on a request that has none | `roundTripper` | GitHub's API refuses a request without one. A user agent the caller set is kept. |
| a span, `behemoth.outbound.request`, with `method`, `host`, and `status` | `roundTripper` | see [The span](#the-span) |
| a bounded answer, 1 MiB by default | `ReadLimited` | a hostile or broken service can't make behemoth read without end |
| no retry | nothing retries | an authorization code works once |
| errors name the scheme, the host, and the path | `describe` | a query can hold a secret. `url.Redacted` hides a password only, not a query. |
| the caller's request is not changed | `req.Clone` in `RoundTrip` | the `http.RoundTripper` contract |

`ReadLimited` reads one byte more than the limit, and returns `ErrTooLarge` when it gets it. A truncated answer is never returned: cut at the limit, a JSON document can still parse, with fields missing.

### URLs that carry a credential or a key

`CheckURL` refuses a URL that is not absolute, carries credentials or a fragment, or is not `https`, except `http` on a loopback address for development. The OAuth plugin applies it to an issuer and to the endpoints of a discovery document, and `keysource.NewJWKSet` to a key set's URL. Over plain `http`, an attacker on the path could read a client secret, or serve keys of their own and sign tokens with them.

The client does not apply it to every call. A call to a service on the same network, such as a hook callout, may be plain `http`. The address guard, when it is built, is the rule for every call to a URL from a configuration file.

### The span

`roundTripper.RoundTrip` starts the span from the request's context, so the call is a child of the span the caller is in, such as `behemoth.request`. A transport error ends it at once with `telemetry.FinishSpan`. Otherwise the status is set, and `spanBody` ends the span when the caller closes the body, once (`sync.Once`), so the span covers reading the answer. A caller that never closes the body leaks the span along with the connection.

The span names the host and not the URL. A query can hold a secret, and a path can hold an id, which would break the bounded-value rule of [`../telemetry/tracing.md`](../telemetry/tracing.md#span-sites).

## How plugins get the client

`Boot` validates `BootConfig.Outbound`, builds the client with `outbound.NewClient(cfg.Outbound, tel)`, and sets `AuthContext.HTTPClient` before the first `Init`. The field is never nil on an `AuthContext` that `Boot` returns.

A plugin that calls out uses `ac.HTTPClient`, unless an option of its own names a client. It never builds an `http.Client{}` of its own: such a client has no timeout, follows redirects, and records no span.

The OAuth plugin's `Init` takes `Options.HTTPClient`, then `ac.HTTPClient`, and builds `outbound.NewClient(outbound.Options{}, ac.Telemetry)` only for an `AuthContext` that `Boot` did not build.

## Invariants

These invariants hold:

- **Every outbound call goes through `outbound.NewClient`.** A plugin's own option may replace the client. The plugin then documents that the replacement should follow no redirect.
- **The client follows no redirect unless its options say so, and never retries.** A redirect could take a client secret elsewhere, and a repeated code exchange fails.
- **The span names no path and no query.**
- **The client is a plain `*http.Client`.** No interface wraps it (ADR-0003).

## Design decisions

### Telemetry is a parameter of `NewClient`, not an option

**Context:** The client needs a tracer for its spans.

**Options considered:**

- *A `Telemetry` field in `Options`, which `Boot` fills when it is nil.* One argument. `BootConfig.Outbound.Telemetry` would repeat `BootConfig.Telemetry`, and `Boot` would change the application's options behind its back.
- *A parameter.* The dependency shows in the signature, and `BootConfig.Outbound` holds settings only, apart from `Transport`.

**Decision:** the parameter. A nil `tel` records no span.

**Revisit if:** the client needs a second dependency, such as a metrics sink of its own.

### The default transport reads the proxy from the environment

**Context:** `service_ready_components.md` says core reads no environment variable. `http.DefaultTransport` takes its proxy from `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY`.

**Options considered:**

- *Keep the environment proxy.* It is what every Go program does. A platform sets the variables on the process, and the application's own clients honor them already.
- *No proxy by default, and a `ProxyURL` option.* The setting would show in a configuration file, and the composition root would read the environment. A library application that relies on the variables would lose its proxy without a warning.

**Decision:** keep the environment proxy, like the system's certificate authorities, which Go also reads from the platform. The deviation is recorded in `docs/ongoing.md` under "An application configures behemoth with Go values only".

**Revisit if:** the standalone service needs the proxy in its configuration file.

### A redirect is the answer, not an error

**Context:** With redirects off, `CheckRedirect` can return an error, or `http.ErrUseLastResponse`.

**Options considered:**

- *An error.* The call fails where the redirect is refused. The caller can't see where the redirect pointed.
- *The redirect as the answer.* `client.Do` returns the `3xx`. `GetJSON` turns it into an error like any other status that is not `2xx`, and the OAuth plugin's code exchange does the same.

**Decision:** the redirect as the answer. A caller that wants to report the `Location` can.

**Revisit if:** a caller treats a `3xx` as success by mistake.

## Deferred

These parts are deferred:

- **An address guard.** It would refuse private, loopback, and link-local addresses, for URLs that come from a configuration file. It comes with the standalone service (ADR-0003). Today the URLs come from the application's code, and `CheckURL` asks for `https`, or `http` on a loopback address for development, where a credential or a key is involved.
- **A proxy URL and a CA bundle as plain values next to `Transport`.** Today they need a `Transport`. Tracked in `docs/ongoing.md` under "An application configures behemoth with Go values only".
- **Metrics for outbound calls.** The span carries the timing and the status. No counter or histogram counts the calls yet.
