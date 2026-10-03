## **Core Models**

This document explains the tables behemoth's core owns: which models exist and where they are defined, how a model, its column constants and its table declaration stay in step, how an `Account` stores credentials and encrypts OAuth tokens, what an existing database needs before `users.password_hash` is dropped, and how data hooks behave inside a store transaction.

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

# **Hooks inside a store transaction**

`Store.Transaction(ctx, fn)` runs `fn` with a store bound to one database transaction. Called on a store that is already in a transaction, it runs `fn` in that same transaction: there is no nesting.

`[Important]` Data hooks fire at the point of the write, not at commit. The comment on `store.Hooks.AfterCreate` says it "runs once the row is committed", and that is only true for a write made outside a transaction. Inside `Transaction`, `AfterCreate` and `AfterUpdate` run while the transaction is still open.

Email/password sign-up is the first place this matters. It creates the user and the credential account together:

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

The sequence is:

1. `data.user.beforeCreate` runs.
2. The user row is inserted.
3. `data.user.afterCreate` runs. The transaction is open.
4. The account row is inserted.
5. The transaction commits, or rolls back if step 4 failed.

If step 4 fails, the after-create hook in step 3 has already run for a user that no longer exists.

What this means for a hook handler on `data.user.afterCreate`:

- It must not treat the user as durable. Sending a welcome email, calling a webhook, or writing to another system from there can act on a user that is rolled back.
- A read through `AuthContext.Store` from inside the handler goes through a different connection than the transaction. Depending on the database's isolation level it will not see the new row, and on SQLite it may wait on the write lock.

`[Not built]` There is no after-commit hook. Side effects that must only happen for committed users belong at the operation level instead: `auth.signUp.after` is fired by the plugin after the transaction has returned.
