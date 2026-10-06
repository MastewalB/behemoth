## **Rate Limiter**

This document explains how rate limiting is wired today, how the database counter in `rate_limits` works, how it behaves when many requests hit one key at once, how old counters are removed, and what is still missing before any of it limits a real request.

The code lives in:

- `types/ratelimit.go` — `Limiter`, `Limit`, the rule types, `AtomicIncrementer`, `RateLimiter`
- `types/ratelimit/ratelimiter.go` — the limiter algorithms (only `IdentityLimiter` today)
- `types/init/init.go` — `DefaultRateLimiter`, `DefaultRateLimitCatalog`, `resolveRateLimitStore`, `dbCounterStore`
- `store/rate_limits.go` — `IncrementRateLimit`, `PurgeExpiredRateLimits`
- `models/rate_limit.go` — the `rate_limits` table

---

# **Status**

`[Important]` Nothing is rate limited yet. The pieces exist but are not connected:

| Piece | State |
|---|---|
| Rule declaration and matching (`RateLimitCatalog`, `BestRouteMatch`) | works |
| `DefaultRateLimiter.evaluate`, rejection, lockout, failure mode | works, and calls `rule.Algorithm.Allow` |
| A limiter algorithm that counts | **missing**: `IdentityLimiter` allows every request |
| Database counter (`Store.IncrementRateLimit`) | works and is tested, but nothing calls it at runtime |
| Key-value counter (Redis `Increment`) | **missing** |
| Removal of old counters | the method exists, nothing schedules it |

The rest of this document describes the parts that work, then the plan for connecting them.

---

# **How a check flows**

1. A rule is declared at `Prepare` time: a `RouteRateLimitRule` (matched by method and path) or a `HookRateLimitRule` (attached to a before-phase hook point). Each carries a `Limit{Max, Window}`, an `Algorithm` (a `Limiter`), and an action.
2. At request time `DefaultRateLimiter` builds the key as `<rule name>:<KeyFunc result>`, for example `core.signin.route:1.2.3.4`.
3. `evaluate` calls `Algorithm.Allow(ctx, key, limit)`.
4. If the attempt is not allowed, it records a `ratelimit.exceeded` audit event (outcome `denied`, best effort) and returns a `rate_limited` error with a retry-after. With `ActionLockout` and a `LockoutFor`, the retry-after is the lockout duration.
5. If `Allow` itself fails, `RateLimitConfig.FailureMode` decides: `FailOpen` (the default) lets the request through and logs a warning; `FailClosed` rejects it.

Route rules and hook rules differ in one way. For a route, the single most specific matching rule applies. For a hook point, every declared rule is evaluated and all must pass.

---

# **The database counter**

### **Table**

```go
type RateLimit struct {
	Key       string    // column limit_key, primary key
	Count     int64     // column count
	ExpiresAt time.Time // column expires_at, indexed
}
```

- One row per key. `Count` is the number of attempts in the window that ends at `ExpiresAt`.
- The key column is `limit_key`, not `key`. The SQL adapters emit column names unquoted, and `KEY` is a reserved word in MySQL and SQL Server.
- The table is always declared, even when a key-value store will do the counting. See [`../models/models.md`](../models/models.md).

### **`IncrementRateLimit(ctx, key, ttl)`**

It counts one attempt and returns the count in the current window. This is a fixed window:

- The first attempt for a key creates the row with count 1 and `expires_at = now + ttl`.
- Each later attempt inside the window adds one.
- The first attempt after `expires_at` resets the count to 1 and opens a new window.

`[Decision]` It does not use a transaction, a database-specific upsert, or `count = count + 1`. The `Database` interface has none of those in a portable form. Instead it is a compare-and-swap built on the `UpdateOne` convention, which re-checks its condition in the write itself:

1. Read the row for the key.
2. No row: insert one with count 1. If the insert fails with `DuplicateKey`, another call created it first, so start again.
3. Row found, window still open: update to `count + 1` **where the count is still the value that was read**.
4. Row found, window passed: update to count 1 and a new `expires_at` **where the count is still the value that was read and `expires_at` is still in the past**.
5. If the update matched no row, another call wrote first, so start again.

The guarantee is that no two calls return the same count for one window. The contract test runs 20 concurrent calls on SQLite and Postgres, through the raw SQL, GORM and Bun adapters, and checks that the counts are exactly 1 to 20.

The extra `expires_at` condition in step 4 is what stops two calls from both resetting an expired window. The second one finds `expires_at` in the future again, fails its guard, re-reads, and increments to 2.

---

# **Behavior on contention**

Each attempt costs one read and one write, and a call that loses a race repeats both.

- **Every lost race is someone else's success.** When several calls read the same count, exactly one write matches. The others retry. The counter always moves forward; no call blocks another.
- **Retries are bounded.** `rateLimitAttempts` is 32. A call gives up only after losing 32 races in a row, which needs at least that many other calls to have incremented the same key in the meantime.
- **Giving up returns an error**, not a count. The limiter treats it as a store failure, so `FailureMode` decides what happens to the request.

`[Important]` This creates a gap under the default `FailOpen`. The situation that exhausts the retries is a flood of requests on one key, which is exactly what a limit is meant to stop. With `FailOpen`, the requests that give up are allowed through. Two mitigations:

- Use `FailClosed` for rules that protect sign-in and similar endpoints.
- Prefer a key-value store with a native atomic increment for high-traffic keys. The database counter is the fallback, and it is the slower path by design: two round trips per attempt at best.

In practice the number of calls contending for one key is limited by the database connection pool, so 32 consecutive losses needs a pool and a burst both well above that size.

Other things to know:

- **Do not call it inside a transaction.** On Postgres a `DuplicateKey` error aborts the enclosing transaction, so the retry in step 2 would fail. `dbCounterStore` uses a store of its own that is never bound to a transaction.
- **The clock is the application's**, not the database's. `expires_at` is computed from the store's clock, in UTC. Application servers with skewed clocks will disagree about when a window ends by the amount of the skew.
- **Fixed windows allow a burst across the boundary.** A client can make `Max` attempts at the end of one window and `Max` more at the start of the next.

---

# **Removing old counters**

A counter row is reused when its key is seen again: the expired window is reset in place. So a key that keeps coming back never needs cleaning up.

Rows only accumulate for keys that never return. With keys built from client IP addresses or emails, that is most of them, and the table grows without bound.

`Store.PurgeExpiredRateLimits(ctx)` deletes every row whose `expires_at` is at or before now. `expires_at` is indexed for this.

- It is safe to run at any time and from several processes. Deleting an expired row loses nothing: the next attempt for that key starts at 1 either way.
- It can race with an increment that is resetting the same expired row. The increment's update then matches no row, and it retries and inserts.

`[Not built]` Nothing calls it. `Boot` does not start a background job. Until one exists, the application has to call it on a schedule, for example from a cron job or a ticker started after `Boot`. An interval about as long as the longest configured window is enough.

---

# **`AtomicIncrementer` and what is left to build**

```go
type AtomicIncrementer interface {
	Increment(ctx context.Context, key string, ttl time.Duration) (count int64, err error)
}
```

### **Why it exists**

A fixed-window counter needs "add one and return the new count" as one atomic step. `KeyValueStorage` only has `Get`, `Set` and `Delete`, and get-then-set loses updates under concurrency. Redis provides the step natively (`INCR` with an expiry) and needs no transactions. The database provides it through the compare-and-swap above.

`AtomicIncrementer` is the seam between the two. `resolveRateLimitStore` picks the implementation at `Boot`:

- If the configured key-value store implements `AtomicIncrementer`, use it.
- Otherwise use `dbCounterStore`, which calls `Store.IncrementRateLimit`.

### **Why it does nothing today**

- **No key-value backend implements it.** The Redis adapter has no `Increment` method, so the type assertion always fails and the database path is always chosen, even with Redis configured.
- **Nothing reads the result.** `DefaultRateLimiter` keeps the chosen incrementer in its `store` field, but `evaluate` only calls `rule.Algorithm.Allow(ctx, key, limit)`. `Limiter.Allow` is not given the incrementer, and the only algorithm ignores its arguments.

### **The three pieces**

1. **`Increment` on the Redis adapter.** It must set the expiry atomically with the first increment: one Lua script, or `SET key 0 NX EX ttl` followed by `INCR`. A plain `INCR` followed by `EXPIRE` leaves a counter that never resets if the process dies between the two commands.
2. **A fixed-window `Limiter`.** It holds an `AtomicIncrementer`, calls `Increment(key, limit.Window)`, and allows the attempt when the returned count is at most `limit.Max`. For the retry-after hint it needs the time left in the window, which `Increment` does not return today; either the interface grows a second return value or the limiter reports the full window.
3. **Getting the incrementer to the limiter.** This is the open design question. Rules carry a ready-made `Algorithm` value, and they are declared during `Prepare`, before any store or key-value connection exists. Two ways to close the gap:
   - Rules name a strategy (for example `FixedWindow`) instead of holding an instance, and `Boot` builds the limiter with the resolved incrementer. This keeps `Prepare` free of live connections. It is the suggested direction.
   - `Limiter.Allow` takes the incrementer as an argument, and `evaluate` passes `rl.store`. This is the smaller change, but every algorithm is then tied to the counter shape.

### **Limit of the interface**

`Increment(key, ttl)` can only express fixed-window counting. A sliding window or a token bucket needs more state than one counter: a script on Redis, a different table shape in the database. Those should be separate optional capabilities with their own fallbacks, not extensions of this one. For throttling sign-in, sign-up and password reset, a fixed window is usually enough.
