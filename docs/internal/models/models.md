## **Core Models**

This document explains the tables behemoth's core owns: which models exist and where they are defined, how a model, its column constants and its table declaration stay in step, how an `Account` stores credentials and encrypts OAuth tokens, what an existing database needs before `users.password_hash` is dropped, and how data hooks run inside the transaction of the write that fires them.

The code lives in:

- `models/` — one file per model, plus `schema.go` (table declarations) and `extension.go` (contributed columns)
- `store/` — the typed operations on those models; `seal.go` holds the at-rest encryption
- `types/init/init.go` — `CoreDeclareSchema`, which declares the tables, and `Boot`, which builds the store
- `types/cryptotypes/` — the crypto contracts the store uses (`Encryptor`)

The rate limiter that writes `rate_limits` is described in [`../ratelimit/rate_limiter.md`](../ratelimit/rate_limiter.md).

---

# **What exists**

| Table | Model | Definition | Declared by core | Store operations |
|---|---|---|---|---|
| `users` | `models.User` | `models/user.go` | yes | `store/users.go` |
| `accounts` | `models.Account` | `models/account.go` | yes | `store/accounts.go` |
| `sessions` | `models.Session` | `models/session.go` | yes | `store/sessions.go` |
| `tokens` | `models.Token` | `models/token.go` | yes | `store/tokens.go` |
| `rate_limits` | `models.RateLimit` | `models/rate_limit.go` | yes | `store/rate_limits.go` |
| `jwk_keypairs` | `cryptotypes.JWKKeyPair` | `types/cryptotypes/cryptotypes.go` | **no** | none (`crypto/jwks_store.go` uses the raw `Database`) |

What each one is for:

- **`users`** — who signs in: id, unique email, profile fields, `email_verified`. It holds no credential.
- **`accounts`** — how a user signs in. One row per `(provider_id, account_id)`: the `"credential"` provider carries the password hash, an OAuth provider carries its tokens.
- **`sessions`** — one row per issued session, looked up by the hash of its token.
- **`tokens`** — the verification table. It is generic by `Kind` (email verification, password reset, magic link, API key), so there is no separate `verifications` table.
- **`rate_limits`** — fixed-window counters, used only when rate limiting has no key-value store to count in.
- **`jwk_keypairs`** — asymmetric keypairs for externally verifiable JWTs. It is still outside `models` and is not declared by `CoreDeclareSchema`, so migrations do not create it yet. `types.JWKKeyPair` is an alias for it.

`sessions` and `accounts` each declare a cascading foreign key to `users`, so deleting a user removes both.

---

# **How a model is put together**

Every model in `models/` follows the same four-part shape. `models/session.go` is the reference.

1. **Column constants.** The table name and every column name are constants (`SessionTable`, `SessionUserID`, …). They are canonical names: the `SchemaResolver` maps them to physical ones.
2. **The struct, with `ToMap` and `FromMap`.** `ToMap` is the row that gets written; `FromMap` reads a row back. Both use the constants.
3. **The own-column set.** `sessionColumns`, `accountColumns`, and so on list the columns the model itself has.
4. **The table declaration.** `models/schema.go` has one function per table (`SessionTableSchema()`), built from the same constants, with indexes and foreign keys.

`[Convention, important]` These three must list exactly the same columns: the table declaration, the own-column set, and the keys `ToMap` returns. `TestDeclaredTablesMatchModels` in `models/schema_test.go` fails when they drift. A new model is added to that test's table.

### **Contributed columns**

A plugin or the application may add a column to a core table (`Registry.ExtendColumn`). A model that embeds `models.Extension` carries those values in `Extra`: `FromMap` puts every column that is not in the own-column set there, and `ToMap` merges them back. Typed access goes through `schema.Field`.

`User`, `Account`, `Session` and `Token` embed `Extension`. `RateLimit` does not: it is an internal counter, and a column contributed to it would be ignored.

### **Declaration**

`CoreDeclareSchema` declares the five tables under owner `"core"` during `Prepare`, before any plugin declares. `rate_limits` is declared whether or not a key-value store is configured, because `Prepare` runs without a live connection and cannot know. With a key-value store that counts natively, the table exists and stays empty.

### **NULL versus empty**

`Account.ToMap` writes an empty string or a nil time as `NULL` (`nullIfEmpty`, `nullIfNil`). `User` and `Session` write empty strings as empty strings. For `Account` the distinction matters: a missing token must be `NULL`, not an encrypted empty string.

---

# **Accounts**

```go
type Account struct {
	Extension
	ID         string
	UserID     string
	ProviderID string // "credential" | "google" | ...
	AccountID  string // the provider's id for the user; for "credential", the user id

	PasswordHash string // "credential" only

	AccessToken           string
	RefreshToken          string
	IDToken               string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 string

	CreatedAt time.Time
	UpdatedAt time.Time
}
```

- **Uniqueness.** The unique index `uq_accounts_provider_account` covers `(provider_id, account_id)`. Creating a second account with the same pair is a `DuplicateKey` error.
- **The credential account.** `models.ProviderCredential` is `"credential"`. Its `AccountID` is the user's own id, so the email/password plugin finds it with `Store.FindAccount(ctx, models.ProviderCredential, user.ID)`.
- **A user without a credential account** signed up through an OAuth provider only and has no password. Sign-in answers them exactly like a wrong password, runs the same dummy hash for timing, and fires the failed hook with code `noCredentialAccount`.
- **JSON.** `PasswordHash` and the three tokens are tagged `json:"-"`. Handlers return models as JSON, and these must never be in a response.

### **Secret columns**

`models.AccountSecretColumns` names the columns encrypted at rest: `access_token`, `refresh_token`, `id_token`. `password_hash` is not in the list: it is already a one-way hash.

The store is the only place that encrypts and decrypts them. The rule is:

| Where | Form of the token |
|---|---|
| An `Account` the caller passes to or gets from the store | plaintext |
| The row in the database | sealed |
| The row or model a data hook receives | sealed |

### **Seal and open**

A sealed value is a string:

```
v<key version>:<base64 ciphertext>
```

- `Store.seal` calls `Encryptor.Encrypt`, which returns the ciphertext and the version of the key it used, and writes both into that string. The base64 is `RawStdEncoding` (no padding).
- `Store.open` splits the string, parses the version, and calls `Encryptor.Decrypt(ciphertext, version)`.
- The ciphertext itself is the AES-256-GCM output of `crypto.AESGCMEncryptor`, with the nonce prepended. The key comes from the `KeyManager` under purpose `encrypt_at_rest`.
- `store.SealedKeyVersion(sealed)` reads the version without decrypting.

`[Decision]` The key version travels inside the value instead of in a `key_version` column. An account has three secrets written at different times: an access token refreshed after a key rotation sits next to a refresh token sealed under the previous key. One version column would be wrong for one of them; three columns, or re-encrypting every token on every write, would be the alternative. The cost is that key version cannot be indexed. A re-encryption sweep after a rotation selects with a starts-with match on `v<old>:` (`clause.OpStartsWith`).

`[Not built]` No such sweep exists. Old key versions must stay available to the `KeyManager` for as long as rows sealed under them exist.

### **What each store operation does**

- **`CreateAccount`** assigns the id and timestamps, seals each non-empty token, and inserts. The caller's `Account` holds the plaintext again when the call returns, whether it succeeded or failed.
- **`FindAccountByID`, `FindAccount`, `ListAccountsForUser`** open the tokens on a copy of the stored model and return the copy. The copy matters: the stored model may already have been handed to an after-hook, which must keep seeing the sealed form.
- **`UpdateAccount`** takes token columns in plaintext in the changes map. It seals them before the before-update hook runs. A value of `""` or `nil` clears the column to `NULL`. A non-string value is a validation error. The caller's map is not modified.
- **`DeleteAccount`** deletes by id.

### **The encryptor is required for tokens**

`store.WithEncryptor(e)` supplies the encryptor. `Boot` passes `Crypto.AtRest`.

`[Convention, important]` A store built without an encryptor returns a configuration error when asked to write or read a token. It never falls back to storing plaintext. Accounts with no tokens, such as credential accounts, work without one.

A stored value that is not a valid sealed string, or whose ciphertext is truncated or tampered with, is a security error from `open`. It is not a panic.

### **Limits to know**

- **Hooks do not fire for accounts today.** The store calls its hooks for every table, but `coreDataHookPoints` in `types/init/datahooks.go` only maps `users` to hook points. The "hooks see the sealed form" rule takes effect when account points are declared.
- **A hook that rewrites a token column on create is not reflected in the caller's model.** `CreateAccount` restores the caller's original plaintext after the insert.
- **Ciphertext is not bound to its row.** The `Encryptor` interface takes no associated data, so a sealed value copied from one row or column to another still decrypts. Someone with write access to the table could swap tokens between accounts.

---

# **Moving `password_hash` from `users` to `accounts`**

`users.password_hash` no longer exists in the declared schema. The hash now lives in `accounts.password_hash` on the user's credential account.

`[Important]` On a database created before this change, every existing user's hash is still in `users.password_hash`, and no credential account exists for them. Two things follow:

- Until the hashes are copied, existing users cannot sign in with a password: sign-in looks for a credential account and finds none.
- The migration planner sees `password_hash` as a live column that is no longer declared and raises a plan issue offering to drop it. Choosing "Drop column" before the copy destroys every password.

The planner never drops the column on its own. A drop is a plan issue with two options ("Drop column", "Leave as-is"), and the drop operation must be confirmed.

### **Order of operations**

1. Generate and apply the migration that creates `accounts`. Resolve the `password_hash` issue as **Leave as-is**.
2. Copy the hashes into credential accounts (below).
3. Check that the number of credential accounts equals the number of users that had a hash.
4. Deploy the code that reads the hash from accounts.
5. In a later migration, resolve the issue as **Drop column**.

Steps 2 and 4 must not be far apart. A user who signs up through the old code after the copy has a hash in `users` and no account. Either run the copy again just before step 5 (it is idempotent as written below) or stop sign-ups during the switch.

### **The copy**

`[Not built]` The migration system has no data operation. `SchemaOperation` kinds are all schema changes, and a `CustomMigration` is made of the same kinds, so the copy cannot be expressed as a behemoth migration today. It is run as SQL against the database.

The statement below was checked on SQLite only (it copies the hashes and a second run inserts nothing). Test it on a copy of the real database before running it in production:

```sql
INSERT INTO accounts (id, user_id, provider_id, account_id, password_hash, created_at, updated_at)
SELECT u.id, u.id, 'credential', u.id, u.password_hash, u.created_at, u.updated_at
FROM users u
WHERE u.password_hash IS NOT NULL
  AND u.password_hash <> ''
  AND NOT EXISTS (
    SELECT 1 FROM accounts a
    WHERE a.provider_id = 'credential' AND a.account_id = u.id
  );
```

- The account's `id` reuses the user's id. It only has to be a unique string of at most 36 characters, and this avoids a database-specific UUID function.
- `account_id` is the user id, which is what the plugin looks up.
- The names above are canonical. If the application maps physical table or column names through the resolver, use the physical ones.
- The hash string is copied unchanged. It is a self-describing Argon2id string, so it verifies the same from its new location.

---

# **Data hooks and transactions**

Behemoth has two tiers of hooks. Tier 1 data hooks (`data.user.beforeCreate`, `data.user.afterCreate`, ...) are fired by the store around a write to one table. Tier 2 flow hooks (`auth.signUp.before`, `auth.signUp.after`, ...) are fired by a plugin around a whole operation. This section covers Tier 1.

`[Convention]` A data hook is part of the write. It runs inside the write's database transaction, before and after phases alike, and it should only do work that the transaction's rollback undoes. Compare the two after hooks on sign-up:

| | `data.user.afterCreate` (Tier 1) | `auth.signUp.after` (Tier 2) |
| --- | --- | --- |
| Runs | after the insert, before commit | after the transaction has committed |
| The user | may still be rolled back | is durable |
| A handler error | fails the write and rolls it back | is logged; sign-up still succeeds |
| A later handler | does not run after a failure | runs anyway |
| Meant for | rows in other tables that belong with the user | welcome emails, webhooks, other systems |

### **How a hooked write runs**

`Store.create` and `Store.update` wrap three steps in one transaction (`Store.hooked` in `store/create.go`):

1. The before hook runs. It may rewrite the row or return an error.
2. The row is written.
3. The after hook runs. It may return an error.

An error at any step rolls the transaction back and is returned to the caller as-is. A panic in a handler is turned into an internal error and treated the same way.

If the store is already bound to a transaction (`Store.Transaction`), the write joins it instead of opening one. There is no nesting. Email/password sign-up is the example:

```go
err = ac.Store.Transaction(hctx.Ctx, func(ctx context.Context, tx *store.Store) error {
	if err := tx.CreateUser(ctx, user); err != nil {
		return err
	}
	return tx.CreateAccount(ctx, &models.Account{
		UserID: user.ID, ProviderID: models.ProviderCredential,
		AccountID: user.ID, PasswordHash: passwordHash,
	})
})
```

1. `data.user.beforeCreate` runs.
2. The user row is inserted.
3. `data.user.afterCreate` runs. The transaction is open.
4. The account row is inserted.
5. The transaction commits, or rolls back if any step failed.

If step 4 fails, the after-create hook in step 3 has already run for a user that is then rolled back. Whatever the hook wrote through the transaction is rolled back with it.

Only tables that fire hooks get a transaction. `store.Hooks.Fires(table)` answers that, and `dataHooks` answers it from `coreDataHookPoints`, which maps only `users` today. Writes to `sessions`, `tokens`, `accounts` and `rate_limits` go straight to the database as before.

### **The hook's store: `HookContext.Tx`**

The store passes itself to every `store.Hooks` method, and `dataHooks` publishes it as `HookContext.Tx`. Inside a hooked write it is the store bound to the transaction.

```go
registry.OnAfter(hooks.HookUserAfterCreate, func(hctx *types.HookContext, result any) error {
	user := result.(*models.User)
	// Commits or rolls back with the user.
	return hctx.Tx.CreateAccount(hctx.Ctx, &models.Account{UserID: user.ID /* ... */})
}, nil)
```

`[Convention]` `Tx` has two surfaces, and a handler picks by who owns the table:

- **Core tables** (users, accounts, sessions, tokens) go through the store's methods on `Tx`. They are the only place the tables' invariants are applied.
- **Any other table** (a plugin's or the application's) goes through `Tx.DB()`, the `behemoth.Database` the store itself writes through. On a transaction-bound store it is the adapter bound to that transaction.

```go
registry.OnAfter(hooks.HookUserAfterCreate, func(hctx *types.HookContext, result any) error {
	user := result.(*models.User)
	return hctx.Tx.DB().Create(hctx.Ctx, &Profile{UserID: user.ID})
}, nil)
```

`Store.DB()` returns `s.db` and nothing more. `Store.Transaction` builds the bound store with `tx.db = db`, the adapter the driver handed to the transaction callback, so `DB()` follows the store into and out of transactions without extra state.

What the adapter skips when it is used on a core table:

| Store step | Where it lives | Effect of skipping it |
| --- | --- | --- |
| Data hooks | `Store.create`, `Store.update` | no `data.user.*` handler runs; other plugins' rewrites and vetoes are bypassed |
| Token sealing | `CreateAccount`, `UpdateAccount` (`seal.go`) | OAuth tokens land in plaintext; `openAccount` then fails to open them |
| Ids and timestamps | `CreateUser`, `CreateAccount`, ... | empty primary key, zero timestamps |
| Email normalization | `CreateUser`, `UpdateUser` | the row is not found by `FindUserByEmail` |
| Column check | `checkColumns` | unknown keys are no longer a validation error at the store |
| Session cache | `DefaultSessionManager` | a revoked session stays valid from the KV cache until its TTL |

Nothing enforces the convention. The adapter accepts any declared model.

`hctx.Auth.Store` and `hctx.Auth.DB` are the root store and adapter and use a different connection. From inside a data hook:

- A write through them is not part of the transaction and stays if the transaction rolls back. A handler may want exactly that, for a record that should survive a rejected write.
- A read through them does not see the row being written. A foreign key from a row they write to the new user fails for the same reason.
- On SQLite they can wait on the write lock the transaction holds.

`HookContext.Tx` is nil on Tier 2 hooks. They do not run inside a store transaction.

How each adapter binds a transaction, and what `Transaction` does when called on a bound adapter, is described in [`../database/adapters/transactions.md`](../database/adapters/transactions.md). Three points from there matter to a handler:

- **The context carries the transaction on MongoDB.** A call on `Tx.DB()` with a context other than `hctx.Ctx` runs outside the transaction.
- **The bound adapter ends with the hook.** On the SQL adapters it wraps a `*sql.Tx` and returns `sql.ErrTxDone` afterwards.
- **A failed statement aborts a Postgres transaction.** A handler that swallows an adapter error leaves the transaction unusable, and the commit fails.

### **The dispatcher: `RunAfter` and `RunAfterTx`**

Both run the same frozen after-chain. They differ in what a handler error means.

| | `RunAfter` (Tier 2) | `RunAfterTx` (Tier 1) |
| --- | --- | --- |
| Handler returns an error | logged, chain continues | chain stops, error returned |
| Handler panics | logged as an error, chain continues | chain stops, internal error returned |
| Return value | nil, unless the point can't be dispatched | the first error |
| Audit event (`HookPointDef.Audit`) | recorded | not recorded |

All four dispatcher methods start with `DefaultDispatcher.checkPhase`. A point that was never declared, or is declared with another phase, returns a configuration error and runs no handler. For `RunAfter` and `Fail` this is the only error they return.

`Boot` runs the same check once for the points in `coreDataHookPoints` (`checkDataHookPoints`), so a table mapped to an undeclared point fails `Boot` instead of the first write.

`dataHooks.AfterCreate` and `AfterUpdate` call `RunAfterTx` and return its error to the store. Before hooks need no second entry point: `RunBefore` already stops at the first error.

### **What a rollback does not undo**

- **Key-value writes.** A hook that writes to `KeyValueStorage` (Redis, a KV-backed token) leaves that write behind. Only database writes through `HookContext.Tx` are covered.
- **Writes through `Auth.Store` or `Auth.DB`**, as described above.
- **Adapter calls made with a context other than `hctx.Ctx`** on MongoDB.
- **Outside side effects.** An email or a webhook call sent from a data hook can't be recalled. These belong in Tier 2.
- **Rate-limit counters.** `RunBefore` checks a point's rate limit before the handlers run, through a store that is never bound to a transaction. An attempt that is later rolled back still counts. This is intended: the limit is on attempts.
- **The caller's model.** `Store.create` reads the before hook's rewrite back into the model and the caller's `CreateUser` has already set its id and timestamps. After a failed create the model keeps those values for a row that does not exist.
- **`HookContext.Values`** and any other in-memory state a handler changed.

### **Limits to know**

- `[Not built]` **There is no after-commit hook.** A handler that wants to write to the database without being able to fail the main write has no Tier 1 place to do it. Until one exists, that work goes in the Tier 2 after hook of the operation (`auth.signUp.after`).
- `[Not built]` **Data points are not audited.** `RunAfterTx` skips the audit record even when the point declares `Audit`, because the row can still be rolled back and the audit log would describe a write that never happened. The `data.user.*` points declare no `Audit` today. Auditing them is deferred to the after-commit hook.
- **A hook can run more than once on MongoDB.** The Mongo adapter uses `session.WithTransaction`, which runs its callback again on a transient error. A hooked write and its hooks are inside that callback. Writes through `HookContext.Tx` and `Tx.DB()` are rolled back between attempts, so they are unaffected. Anything else a hook does is repeated.
- **Hooked writes need transaction support.** A write to a table that fires hooks always opens a transaction. MongoDB only supports transactions on a replica set or sharded cluster, so the MongoDB adapter requires one. `Boot` fails on a standalone server (`behemoth.TransactionChecker`, see [`../database/adapters/transactions.md`](../database/adapters/transactions.md)).
- **Hooks hold the transaction open.** A slow handler keeps locks for as long as it runs. On SQLite that blocks every other writer.
- **Hooks fire only for `users`.** The transaction rules apply to any table that gains hook points in `coreDataHookPoints`. The `auth.session.*` and `token.*` points are not data points: the session and token managers fire them as Tier 2 points, so `sessions` and `tokens` have no entry there. The managers build a `HookContext` per dispatch (`hookContext` in `transport/session.go`) with the point, the phase, fresh `Values`, the request and the `AuthContext` that `Boot` passes to their constructors. `Tx` is nil.

### Data hooks run inside the write's transaction
**Context:** `data.user.afterCreate` ran at the point of the insert. Inside sign-up's transaction it could act on a user that the account insert then rolled back, it could not reach the transaction to write related rows, and its error was logged and ignored. The after hook was neither a reliable "the row is committed" signal nor a usable part of the write.
**Options considered:**
- *After hooks fire after commit.* Gives a reliable "committed" signal. A handler can no longer fail the write or add rows atomically, and the store has to queue hooks until the outermost transaction commits.
- *After hooks stay as they were, with a documented warning.* No code change. Handlers still can't write in the transaction or abort, so the only safe handler is one that does nothing durable.
- *Before and after hooks both run inside the transaction, and an after-hook error rolls back.* A handler can add related rows atomically and veto the write. Handlers must avoid work a rollback can't undo, and the dispatcher needs an after-dispatch that returns errors.
**Decision:** The third option. It matches what a data hook is for, plugins adding their own rows and columns to a write, and it gives after hooks a contract that is the same inside and outside a caller's transaction. Irreversible side effects already have a home in Tier 2, which fires after commit. Tier 2 after hooks keep the log-and-continue behaviour.
**Revisit if:** handlers need to write to the database after a write without being able to fail it. That calls for an after-commit hook next to these, not for changing them.

### An undeclared hook point is a configuration error, not a panic
**Context:** `checkPhase` panicked when a point was dispatched without being declared, or in the wrong phase. Core fired the `auth.*`, `auth.session.*` and `token.*` points without declaring them, so sign-in, session creation and token issue panicked under a real `Boot`. Every other setup mistake (a duplicate declaration, a handler on an unknown point, a reserved owner name) is returned as a `ConfigurationError`.
**Options considered:**
- *Keep the panic.* Loud, and the signatures of `RunAfter` and `Fail` stay without a return value. A missing declaration in one flow takes the whole process down at request time, unless the HTTP layer recovers.
- *Return the error from `RunBefore` and `RunAfterTx`, log it in `RunAfter` and `Fail`.* No interface change. A flow with an undeclared after or failed point then looks healthy while its handlers and audit events never run.
- *Return a `ConfigurationError` from all four methods.* The mistake reaches the caller as an error on every path. `RunAfter` and `Fail` gain an error return that every caller has to check, and a flow can fail after its work is done (the session row exists, the after point is undeclared).
**Decision:** The third option. `RunAfter` and `Fail` return only this error; handler errors are still logged. Core now declares every point it fires (`CoreDeclareHookPoints`), with the session points split into `beforeCreate`/`afterCreate` and `beforeRevoke`/`afterRevoke` because a point has one phase.
**Revisit if:** the set of dispatched points can be known at boot (for example flows registering the points they fire). The check could then move to `Boot` entirely and `RunAfter` and `Fail` could drop the return value.

### Plugins write their own tables through the adapter
**Context:** A data hook runs inside the write's transaction, but `Store` only had typed operations for core tables. A plugin that owns a table could not write it inside the transaction, so the convention above could not be followed for the tables plugins care most about. Plugins such as a dashboard or an audit log also need to read every table.
**Options considered:**
- *Generic `Create`/`Update`/`Find` on `Store` for any declared model.* Keeps one door to the database. It re-implements the adapter interface one level up, and the generic methods would have to decide per table whether hooks, sealing and normalization apply.
- *Expose the adapter: `Store.DB()`.* One accessor, no new API to maintain, and plugins get the full `behemoth.Database` they already have as `AuthContext.DB`. The store is no longer the only path to core tables, so their invariants rest on a convention.
**Decision:** Expose the adapter. `AuthContext.DB` was already public, so the store was never an enforced boundary; what was missing was the transaction-bound adapter. The store stays the owner of core tables' rules, and the convention (core tables through the store, own tables through the adapter) is documented in the package doc, on `Store.DB` and in the API docs.
**Revisit if:** plugins writing core tables through the adapter becomes a recurring source of bugs. A wrapper adapter that rejects writes to core tables would then enforce the convention.
