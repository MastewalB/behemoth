# Outbound calls

Behemoth calls other services over HTTP through one client, such as the OAuth plugin calling a provider. You configure the client once, in `BootConfig.Outbound`, and every plugin that calls out uses it.

## Setup

Every field is optional:

```go
ac, err := engine.Boot(ctx, app, db, engine.BootConfig{
	Outbound: outbound.Options{
		Timeout:   5 * time.Second,
		UserAgent: "shop-auth/1.4",
	},
	// ...
})
```

| Field | Default | Meaning |
| --- | --- | --- |
| `Timeout` | 10 seconds | How long one call may take, reading the answer included. |
| `FollowRedirects` | `false` | Whether the client follows a redirect. Without it, the redirect is the answer. |
| `UserAgent` | `behemoth` | The `User-Agent` of a request that sets none. |
| `Transport` | a copy of `http.DefaultTransport` | What carries the requests. Set it for a proxy or certificate authorities of your own. The default takes the proxy from `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY`, and trusts the system's certificate authorities. |

`Boot` returns a configuration error for a negative `Timeout`.

## What every call gets

The client applies these rules to every call:

- **A timeout.** A service that hangs holds your request for `Timeout`, and no longer.
- **No redirect.** A request that carries a credential, such as an OAuth client secret, reaches the URL it names and no other.
- **A user agent.** Some APIs, GitHub's among them, refuse a request without one. A `User-Agent` the request sets is kept.
- **A span.** With a tracer, each call is a `behemoth.outbound.request` span with `method`, `host`, and `status`. It ends when the answer's body is closed. The span names no path and no query, since a query can hold a secret. See [Tracing](telemetry.md#tracing).
- **No retry.** A call that fails returns its error. Some calls work once: an authorization code can be redeemed a single time.

## Call a service from your code

`ac.HTTPClient` is the client, a plain `*http.Client`. Pass it to any library that takes one, and its calls follow the same rules:

```go
resp, err := ac.HTTPClient.Get("https://api.example.com/status")
```

The `outbound` package has helpers. The first four read an answer up to a limit, 1 MiB when you give none:

| Function | What it does |
| --- | --- |
| `GetJSON(ctx, client, url, header, into)` | GETs `url` and decodes a `2xx` answer into `into`. Another status is an error. Returns the status. |
| `PostForm(ctx, client, url, form, header)` | Posts `form` as `application/x-www-form-urlencoded`. Returns the status and the body, whatever the status. |
| `Do(client, req, limit)` | Sends `req`, and returns the status and the body read up to `limit`. |
| `ReadLimited(r, limit)` | Reads `r` to its end. |
| `CheckURL(url)` | Returns an error unless `url` is absolute `https`, or `http` on a loopback address, without credentials or a fragment. Check a URL with it before you send a credential to it or fetch keys from it. |

An answer longer than the limit returns `outbound.ErrTooLarge`, and none of it is used. The helpers' errors name the URL without its query.

```go
var health struct {
	Healthy bool `json:"healthy"`
}
status, err := outbound.GetJSON(ctx, ac.HTTPClient, "https://api.example.com/status", nil, &health)
```

## Build a client of your own

`outbound.NewClient` builds a client with the same rules and other options. Its second argument is the telemetry that receives the spans, and `nil` records none:

```go
client := outbound.NewClient(outbound.Options{Transport: testServer.Client().Transport}, ac.Telemetry)
```

`testServer` is an `*httptest.Server`. The OAuth plugin takes such a client in `oauth.Options.HTTPClient`, which replaces the shared client for its calls. See [OAuth](oauth.md). A client you build another way should follow no redirect either.
