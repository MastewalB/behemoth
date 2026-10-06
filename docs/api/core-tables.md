# Writing Behemoth's tables from a plugin

A plugin can reach the database in two ways. This page explains what each one does, so you can choose per write.

| Door | How you get it | What it is |
| --- | --- | --- |
| The store | `ac.Store`, or `hctx.Tx` inside a data hook | Typed operations for Behemoth's own tables: `CreateUser`, `UpdateAccount`, ... |
| The adapter | `ac.DB`, `ac.Store.DB()`, or `hctx.Tx.DB()` inside a data hook | The plain `behemoth.Database`: `Create`, `FindOne`, `UpdateOne`, ... for any model |

Sessions and tokens have a third door above the store: `ac.SessionManager` and `ac.TokenManager`.

## The convention

- Your own tables: use the adapter. The store has no operations for them.
- Behemoth's tables (`users`, `accounts`, `sessions`, `tokens`, `rate_limits`): use the store, and for sessions and tokens the managers.

Nothing enforces this. The adapter accepts any declared model, and a write to a core table through it succeeds. The adapter writes the row you give it and nothing else, so every step listed below becomes your job. The rest of this page lists those steps per table. If you write directly, do it knowing which ones you are taking over.

## What a direct write skips, on every core table

| Step | Done by | If you skip it |
| --- | --- | --- |
| Id | the store, on create | The row is inserted with an empty primary key unless you set one. |
| `created_at`, `updated_at` | the store, on create and update | Zero timestamps on create. `updated_at` does not move on update. |
| Column check | the store, on create and update | A misspelled or unknown column is not reported as a validation error. What happens next depends on the database: an SQL error, or on MongoDB a stray field. |
| Model returned after an update | the store reads the row back | You get nothing back and read the row yourself. |

## Users

| Step | Done by | If you skip it |
| --- | --- | --- |
| `data.user.beforeCreate`, `data.user.beforeUpdate` | the store | Other plugins' handlers don't run. A plugin that fills its own column on `users`, or rejects certain emails, is bypassed. A contributed `NOT NULL` column without a default then fails the insert. |
| `data.user.afterCreate`, `data.user.afterUpdate` | the store | Rows that other plugins add next to a user (a profile, an audit entry) are not written. |
| `data.user.created`, `data.user.updated` (after commit) | the store | Plugins that react to new or changed users (a welcome email, a stats counter) are not told. |
| The transaction around the write and its hooks | the store | Your write is a single statement. Wrap it yourself if it belongs with other writes. |
| Email normalization (trim, lowercase) | the store | A user stored as `Ada@Example.com` is not found by `FindUserByEmail`, and can sign up a second time as `ada@example.com`. `store.NormalizeEmail` is exported if you need the same form. |

## Accounts

| Step | Done by | If you skip it |
| --- | --- | --- |
| Sealing `access_token`, `refresh_token`, `id_token` on write | the store | The tokens are stored in plaintext, in the table and in its backups. Nothing reports it at write time. |
| Opening them on read | the store | A direct read returns the sealed string (`v1:<base64>`), which is not a usable token. |
| Consistency between the two | | A row you wrote in plaintext can't be read through the store afterwards: `FindAccount` returns a security error (`invalid_sealed_value`) for it. |

- `password_hash` is not sealed. It is a one-way hash and is stored as given in both paths. Hash it with `ac.Crypto.Passwords` before you store it.
- If you need to write tokens directly, there is no public function to seal them. Use `UpdateAccount` for the token columns and the adapter for the rest.

## Sessions

Use `ac.SessionManager`. It does more than the store, and a direct write skips both.

| Step | Done by | If you skip it |
| --- | --- | --- |
| Generating the raw token, storing only its lookup hash and keyed hash | the session manager | You must produce both hashes the same way, or the session can't be validated. Storing a raw token makes every session in the table usable by whoever reads it. |
| Expiry (`ExpiresIn`, `PendingExpiresIn`), `last_active_at`, `fresh_at` | the session manager | The session has whatever you wrote, not what `SessionConfig` says. |
| `MaxConcurrent` and eviction of the oldest session | the session manager | The limit is not applied to your session. |
| `CaptureIPAndAgent` | the session manager | IP address and user agent are stored even when the application turned capture off. |
| The key-value cache | the session manager | A session you revoke directly stays valid from the cache until its entry expires. A session you create directly is not cached, which only costs a lookup. |
| `auth.session.beforeCreate`, `afterCreate`, `beforeRevoke`, `afterRevoke` | the session manager | Other plugins are not told. A handler that vetoes sessions for a suspended user is bypassed. |
| Terminal state rule (a revoked session stays revoked) | the session manager | A direct update can set a revoked session back to active. |

## Tokens

Use `ac.TokenManager`.

| Step | Done by | If you skip it |
| --- | --- | --- |
| Generating the raw token, storing only its lookup hash and keyed hash | the token manager | As for sessions: the token can't be verified, or is stored in a usable form. |
| The declared kind: TTL, single use, backend | the token manager | The row ignores the kind's `TokenKindDef`. A kind whose backend is the key-value storage is not in the table at all, so a direct read misses it. |
| Consuming exactly once | the store (`ConsumeToken`), called by the manager | Two concurrent requests can both use a single-use token. The store's consume is a guarded update: of several concurrent calls one succeeds. |
| `token.beforeIssue`, `afterIssue`, `consumed`, `failed` | the token manager | Other plugins are not told. |

## Rate limits

`rate_limits` holds the rate limiter's counters. `Store.IncrementRateLimit` increments a counter atomically and starts a new window when the old one has passed. A direct write can lose increments under concurrency or leave a window that never resets.

## Audit log

`audit_log` holds the audit events. `Store.RecordAuditEvent` assigns the id that events are ordered and paged by; a row written directly with another kind of id appears out of order in `Store.QueryAuditEvents`. To record an event of your own, use `ac.Telemetry.RecordAudit`, which also fills in the request ID and redacts the metadata. See [Telemetry](telemetry.md#audit).

The table is created by the migration engine like the other core tables. While Behemoth records to it, which is the default, writes to `users` fail if it is missing.

## Reading directly

Reading a core table through the adapter is fine and is the intended way to list or search: a dashboard that lists users can call `FindMany`. Two things differ from a read through the store:

- Account tokens come back sealed.
- You get a `behemoth.Model` to type-assert, and no email normalization on the value you search for. Search for `ada@example.com`, not `Ada@Example.com`.

For sessions and tokens, prefer the managers even for reads. They know about the key-value backend and cache; the table alone may not hold the answer.

## Inside a data hook

The same choices apply, with one addition: use `hctx.Tx` and `hctx.Tx.DB()`, not `hctx.Auth.Store` and `hctx.Auth.DB`, so that your writes commit or roll back with the write that fired the hook. See [Data hooks and transactions](hooks.md#data-hooks-and-transactions).

## Choosing

Going through the store is the default because every step above is one that some other part of the system relies on. Writing directly is reasonable when you know which steps matter for your case and handle them: a migration script that backfills a column, an import that sets its own ids and timestamps, a maintenance job that must not trigger other plugins' hooks. The steps that are hard to redo by hand are sealing account tokens and hashing session and token secrets. For those, use the store and the managers.
