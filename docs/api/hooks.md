# Hooks

Hooks let your code run at fixed points in Behemoth's work: before a user row is inserted, after a sign-up has finished, when a sign-in is rejected. A hook handler can inspect what is happening, change the data on its way in, stop the operation, or react once it is done.

This page covers the whole hook system: the two tiers of hooks, the three phases, how handlers are registered and ordered, what each kind of handler may do, and which hook points exist.

## Concepts

| Term | Meaning |
| --- | --- |
| Hook point | A named place where handlers run, such as `data.user.beforeCreate`. The type is `types.HookPoint`. The constants live in `types/hooks`. |
| Phase | When the point fires relative to its operation: `before`, `after` or `failed`. A point has exactly one phase. |
| Handler | Your function. Its signature depends on the phase. |
| Chain | All handlers registered on one point, in their resolved order. |
| Tier | Which layer fires the point. Tier 1 points are fired by the data layer, Tier 2 points by a flow such as sign-up. |

## The two tiers

The tier decides what a handler may safely do, so pick the point by the tier first.

| | Tier 1: data hooks | Tier 2: flow hooks |
| --- | --- | --- |
| Example | `data.user.afterCreate` | `auth.signUp.after` |
| Fired by | the store, around a write to one table | a flow, around a whole operation |
| Fires when | every time the row is written, whatever caused it | only when that flow runs |
| Runs | inside the write's database transaction | outside any store transaction |
| After-handler error | fails the write and rolls it back | is logged; the operation still succeeds |
| Use it for | data that belongs with the row: extra columns, rows in other tables | everything else: emails, webhooks, calls to other systems |

A short way to choose: if a rollback of the database transaction would undo everything your handler did, it fits Tier 1. If not, it belongs in Tier 2.

For example, creating a profile row for each new user fits `data.user.afterCreate`, because the profile is rolled back if the user is. Sending a welcome email does not fit there, because the user can still be rolled back after your handler returns. Send it from `auth.signUp.after`, which fires once the user is committed.

## Phases and handler signatures

```go
// before: validate or rewrite the payload, or stop the operation.
type BeforeHookFunc func(hctx *HookContext, payload behemoth.M) (behemoth.M, error)

// after: react to the result.
type AfterHookFunc func(hctx *HookContext, result any) error

// failed: be told that the operation was rejected.
type FailedHookFunc func(hctx *HookContext, reason FailureReason) error
```

### Before handlers

A before handler receives the payload as a `behemoth.M` and returns the payload to continue with.

- Return `(payload, nil)` to continue. Return the full payload even when you changed nothing. A nil map is not read as "no change".
- Return `(nil, err)` to stop the operation. No later handler runs and the operation does not happen. The caller receives your error unchanged, so return one of the `errors` package's types (a validation error, for example) to get a sensible HTTP status.
- Each handler receives what the previous one returned.
- A panic is caught, logged, and treated as an error that stops the operation.

```go
func requireCompanyEmail(hctx *types.HookContext, payload behemoth.M) (behemoth.M, error) {
	email, _ := payload[models.UserEmail].(string)
	if !strings.HasSuffix(email, "@example.com") {
		return nil, behemotherr.NewValidationError("requireCompanyEmail", "users",
			errors.New("only example.com addresses may register"))
	}
	return payload, nil
}
```

### After handlers

An after handler receives the result of the operation. What its error does depends on the tier.

| | Tier 1 after handler | Tier 2 after handler |
| --- | --- | --- |
| The result | written, not yet committed | committed |
| Returning an error | fails the write, rolls the transaction back, is returned to the caller | is logged; the caller still gets a success |
| Later handlers after an error | do not run | still run |
| A panic | same as an error | logged; later handlers still run |

### Failed handlers

A failed handler is a notification. It fires when a flow rejects an operation for a business reason: wrong password, email already registered, a before handler said no.

```go
type FailureReason struct {
	Code  string // "invalidCredentials", "userExists", "rejectedByHook", ...
	Cause error  // the underlying error, or nil
}
```

- It can't change the outcome. Its error is logged and later handlers still run.
- It does not fire for system errors such as a database timeout. Those are returned to the caller as ordinary errors.
- When a before handler stops a flow, the flow's failed point fires with code `rejectedByHook` and your error as `Cause`.
- Tier 1 has no failed points.

## HookContext

Every handler receives a `*types.HookContext`.

| Field | Contents |
| --- | --- |
| `Ctx` | The `context.Context` of the operation. Pass it to anything that does I/O. |
| `Point`, `Phase` | The point being dispatched and its phase. |
| `Auth` | The `*types.AuthContext`: store, session manager, token manager, crypto, telemetry. |
| `Tx` | Tier 1 only: the store bound to the write's transaction. `Tx.DB()` is the database adapter bound to the same transaction, for your own tables. Nil on Tier 2 hooks. See [Data hooks and transactions](#data-hooks-and-transactions). |
| `Values` | A scratch map shared by the handlers of one chain. One handler can leave a note for a later one. It is fresh for each dispatch and is not the payload. |
| `Request` | The HTTP request being handled, or nil when the operation was started outside a request (a CLI, a background job). Most handlers don't need it. |

Some points publish well-known entries in `Values` or in the payload. The keys are constants in `types/hooks` (`HookValueUserID`, `HookValueSessionID`, `HookValueIPAddress`, ...). Use the constants so that handlers from different authors agree on the names.

## Registering handlers

Handlers are registered on a `types.HookRegistry`:

```go
type HookRegistry interface {
	OnBefore(point HookPoint, fn BeforeHookFunc, opts *HookOptions) error
	OnAfter(point HookPoint, fn AfterHookFunc, opts *HookOptions) error
	OnFailed(point HookPoint, fn FailedHookFunc, opts *HookOptions) error
}
```

There are two places to get one, and both run during `Boot`.

An application registers its handlers with `BootConfig.Hooks`. No plugin is needed:

```go
ac, err := binit.Boot(ctx, app, db, binit.BootConfig{
	Crypto: cryptoCfg,
	Hooks: func(reg types.HookRegistry) error {
		return reg.OnBefore(hooks.HookUserBeforeCreate, requireCompanyEmail, nil)
	},
})
```

A plugin registers its handlers in its `Register` method:

```go
func (p *LegacyPlugin) Register(reg types.HookRegistry) error {
	return reg.OnAfter(hooks.HookUserAfterCreate, p.linkLegacyAccount, nil)
}
```

Both use the same registry and the same points, and their handlers share one chain per point.

Each handler is recorded under an owner name. For a plugin it is the plugin's name. For the application it is `PrepareConfig.AppName`, which defaults to `app`:

```go
app, err := binit.Prepare(plugins, binit.PrepareConfig{AppName: "shop"})
```

The owner name is what ordering constraints and error messages use. `Prepare` rejects an `AppName` of `core`, and a plugin named `core` or named like the application.

Registration is checked, and a failed check is a boot error:

- The point must have been declared. Registering on an unknown point fails.
- The method must match the point's phase. `OnAfter` on a before point fails.
- An owner may register one handler per point. A second registration on the same point by the same plugin, or by the application, fails, whatever its priority. Put both steps in one function.
- Registration closes when `Boot` freezes the chains. Handlers can't be added or removed at runtime.

## Handler order

Handlers on one point run in an order resolved once, at boot.

```go
type HookOptions struct {
	Priority HookPriority // default: PriorityNormal
	Before   []string     // owner names this handler runs before, on this point
	After    []string     // owner names this handler runs after, on this point
}
```

1. **Priority first.** Lower values run earlier.

   | Constant | Value | Meant for |
   | --- | --- | --- |
   | `PriorityHighest` | -100 | gatekeepers that should see the raw input: validation, security checks |
   | `PriorityHigh` | -50 | |
   | `PriorityNormal` | 0 | the default |
   | `PriorityLow` | 50 | |
   | `PriorityLowest` | 100 | observers that should see the final state: logging, analytics |

2. **Then `Before` and `After`**, among handlers of the same priority. They name owners, not functions: `After: []string{"geoip"}` means "after the `geoip` plugin's handler on this point", and the application's name (`"app"` by default) names the application's handler.
3. **Then boot order**, for handlers with no constraint between them. Plugins boot in dependency order and the application comes last, so its handlers run after the plugins' unless a priority or constraint says otherwise.

Rules to know:

- A constraint that names an owner with no handler on this point is ignored.
- A constraint that contradicts priority is a boot error. A `PriorityLow` handler can't ask to run before a `PriorityHigh` one.
- A cycle (`a` before `b`, `b` before `a`) is a boot error.
- One handler per owner per point is what makes these rules work: a constraint names an owner, so it always means exactly one handler.

```go
// Run the domain check before every other handler on the point.
reg.OnBefore(hooks.HookUserBeforeCreate, requireCompanyEmail,
	&types.HookOptions{Priority: types.PriorityHighest})
```

## Data hooks and transactions

A Tier 1 hook is part of the write. The store runs these steps in one database transaction:

1. The before chain runs. It may rewrite the row or stop the write.
2. The row is written.
3. The after chain runs. It may fail the write.

An error at any step rolls the transaction back and is returned to the caller unchanged. If the caller already opened a transaction with `Store.Transaction`, the write and its hooks join that transaction.

### Write through `hctx.Tx`

`hctx.Tx` is the store bound to the transaction. Everything a data hook reads or writes should go through it. Which part of it you use depends on whose table you are touching.

| Table | Use | Why |
| --- | --- | --- |
| Behemoth's own: users, accounts, sessions, tokens | the store's methods: `hctx.Tx.CreateAccount`, `hctx.Tx.UpdateUser`, ... | they apply Behemoth's rules for those tables |
| Your plugin's or application's own | the adapter: `hctx.Tx.DB()` | the store has no operations for tables it doesn't own |

A core table, through the store:

```go
func (p *LegacyPlugin) linkLegacyAccount(hctx *types.HookContext, result any) error {
	user := result.(*models.User)
	// Committed or rolled back together with the user.
	return hctx.Tx.CreateAccount(hctx.Ctx, &models.Account{
		UserID: user.ID, ProviderID: "legacy", AccountID: p.legacyID(user.Email),
	})
}
```

Your own table, through the adapter:

```go
func (p *ProfilePlugin) createProfile(hctx *types.HookContext, result any) error {
	user := result.(*models.User)
	// Profile is the plugin's own model, declared in Declare.
	return hctx.Tx.DB().Create(hctx.Ctx, &Profile{UserID: user.ID, Theme: "light"})
}
```

In both cases, return the error. It is what rolls the user back when your row can't be written.

`hctx.Tx.DB()` is a `behemoth.Database`, the same interface as `hctx.Auth.DB`, bound to the open transaction. It has the full adapter API: `Create`, `FindOne`, `FindMany`, `UpdateOne`, `DeleteOne`, `Count`, ...

### Rules for the adapter

**Don't write Behemoth's tables through it.** The adapter writes the row and nothing else. The store's methods add all of this, and the adapter skips it:

| Skipped | What goes wrong |
| --- | --- |
| Data hooks | Updating a user through the adapter runs no `data.user.*` handler, so other plugins' checks and columns are bypassed. |
| Sealing of account tokens | OAuth tokens are stored in plaintext. Reads through the adapter return the sealed form. |
| Ids and timestamps | The row has none unless you set them. |
| Email normalization | A user stored with `Ada@Example.com` is not found by `FindUserByEmail`. |
| The column check | A misspelled column in an update is not caught by the store. |
| Session cache | A session revoked through the adapter stays valid from the key-value cache until its entry expires. Revoke through the session manager. |

Reading Behemoth's tables through the adapter is fine. A dashboard that lists users can use `FindMany` directly.

**Pass `hctx.Ctx` to every call.** On MongoDB the transaction travels in the context, not in the adapter: a call made with another context is written outside the transaction and stays after a rollback. On the SQL adapters it is the adapter that carries the transaction. Using `hctx.Tx.DB()` together with `hctx.Ctx` is correct on every database.

**Don't keep the adapter.** It is valid until your handler returns. After that its transaction is committed or rolled back. Later calls on it fail on the SQL adapters and run outside any transaction on MongoDB. Don't store it on the plugin, and don't use it from a goroutine that outlives the handler.

**`Transaction` on it joins the open transaction.** You may call `hctx.Tx.DB().Transaction(...)`, for example from a helper that also runs outside hooks. Inside a hook it starts nothing new: your function runs in the transaction that is already open, and nothing is committed until the outer write commits. If your function returns an error, return that error from the handler too. Catching it and carrying on has different results per adapter: on the plain SQL adapters and MongoDB the inner writes stay in the transaction, while GORM and bun undo them through a savepoint.

**On Postgres, a failed statement ends the transaction.** After any statement fails, Postgres rejects every later statement in the same transaction. A handler can't try an insert, catch a duplicate-key error and continue: the user's write is lost as well. Check first with a `FindOne`, or let the error fail the write.

**Writing outside the transaction is a choice you can make.** `hctx.Auth.DB` and `hctx.Auth.Store` use a different connection. What you write through them stays when the transaction rolls back, which is what a record of a rejected attempt needs. From inside a data hook they have limits:

- They can't see the row being written, so a foreign key from your row to the new user fails.
- On SQLite they can block on the lock the transaction holds.

### The row may still be rolled back

An after handler runs before commit. The row it receives can be rolled back after the handler returns, by a later handler's error or by a later write in the caller's transaction. Sign-up is the example: it creates the user and then the user's credential account in one transaction. `data.user.afterCreate` fires between the two, and if the account insert fails the user is rolled back.

So a data hook should only do work that the rollback undoes. A rollback does not undo:

- **Key-value writes.** Anything written to `KeyValueStorage`, such as Redis, stays.
- **Writes through `hctx.Auth.Store` or `hctx.Auth.DB`.**
- **Adapter calls made with a context other than `hctx.Ctx`**, on MongoDB.
- **Outside side effects.** Emails, webhooks and calls to other systems can't be recalled.
- **Rate-limit counters.** A rate limit attached to a before point counts the attempt even when the write is rolled back.
- **In-memory state.** `hctx.Values`, and the model the caller passed in, keep what was set on them.

### Other things to know

- **A handler can run more than once on MongoDB.** The MongoDB driver retries a transaction on a transient error, and the hooks are inside it. Writes through `hctx.Tx` and `hctx.Tx.DB()` are rolled back between attempts. Anything else the handler does is repeated.
- **MongoDB needs a replica set.** A hooked write always opens a transaction, and a standalone MongoDB server has none.
- **A slow handler holds the transaction open.** It keeps its locks for as long as it runs. On SQLite that blocks every other writer.
- **Not built: there is no after-commit data hook.** If you need to react to a committed row, use the Tier 2 after point of the flow that wrote it.
- **Not built: data points record no audit events.** See [Audit](#audit).

## What each data point carries

Data points exist for the `users` table.

| Point | Phase | Payload or result | `Values` |
| --- | --- | --- | --- |
| `data.user.beforeCreate` | before | the full row, keyed by column name (`models.UserEmail`, ...) | |
| `data.user.afterCreate` | after | the stored `*models.User` | |
| `data.user.beforeUpdate` | before | only the columns being changed | `HookValueUserID`: the row's id |
| `data.user.afterUpdate` | after | the stored row, read back after the update | `HookValueUserID`: the row's id |

Rules for rewriting the payload:

- **Setting a column.** A before handler may set any column the table has, including columns contributed by other plugins. This is how a plugin fills its own column on create.
- **Unknown columns.** A key that is not a column of the table is a validation error and stops the write. It is not silently ignored.
- **Primary key.** `beforeUpdate` can't change the primary key, and the id is not in the payload.
- **Email normalization.** On update, the store lowercases and trims an email after the handlers run, so a handler's value is normalized too. On create it normalizes before the handlers run, so an email set by a `beforeCreate` handler is stored as given.
- **Timestamps.** On update, `updated_at` is set by the store after the handlers and can't be overridden.

## Rate limits on hook points

A rate-limit rule can be attached to a before point with `HookRateLimitRule`. The dispatcher checks it before the first handler runs.

- Every rule declared on the point is checked, and all must pass.
- A rejected attempt returns a `rate_limited` error with a retry-after. No handler runs, and the caller can't tell it apart from a before handler stopping the operation.
- Rules can only be attached to before points.

## Audit

A point can be declared with an `AuditSpec`. The dispatcher then records an audit event each time the point is dispatched, after its handlers have run. The event type defaults to the point's name.

- This applies to Tier 2 after points and to failed points.
- Tier 1 after points record nothing, even when declared with an `AuditSpec`. Their row may still be rolled back, and the audit log would describe a write that never happened.

## Declaring and firing your own points

A plugin can add points of its own for other code to hook into.

Declare the point in `Declare`:

```go
const HookInviteAccepted types.HookPoint = "invite.accepted"

func (p *InvitePlugin) Declare(ic *types.PluginInitContext) error {
	return ic.Hooks.Declare(types.HookPointDef{
		Point: HookInviteAccepted,
		Phase: types.AfterHookPhase,
	})
}
```

- The owner is filled in with your plugin's name.
- A point can be declared once. Declaring a name that already exists is an error naming both owners.
- A point has one phase. An operation with a before, an after and a failed side declares three points.
- Declaration closes when `Prepare` returns.

Fire it through the dispatcher on the `AuthContext`:

```go
hctx := &types.HookContext{Ctx: ctx, Point: HookInviteAccepted, Phase: types.AfterHookPhase,
	Auth: ac, Values: behemoth.M{}, Request: types.RequestFrom(ctx)}
if err := ac.Dispatcher.RunAfter(hctx, HookInviteAccepted, invite); err != nil {
	return err // the point is not declared, or not as an after point
}
```

| Method | Use |
| --- | --- |
| `RunBefore(hctx, point, payload)` | runs the before chain; returns the rewritten payload or the first error |
| `RunAfter(hctx, point, result)` | runs a Tier 2 after chain; handler errors are logged, not returned |
| `Fail(hctx, point, reason)` | runs the failed chain; handler errors are logged, not returned. Does nothing when `point` is empty |
| `RunAfterTx(hctx, point, result)` | runs a Tier 1 after chain and returns the first error; used by the store |

Dispatching a point that was never declared, or with the wrong phase, returns a configuration error from all four methods and runs no handler. That is a mistake in the code that fires the point, not something a handler can cause, so return the error to your caller. For `RunAfter` and `Fail` it is the only error they return.

`types.WithLifecycle` wraps a function with all three points of a flow:

```go
signUp := types.WithLifecycle(ac.Dispatcher,
	hooks.HookSignUpBefore, hooks.HookSignUpAfter, hooks.HookSignUpFailed,
	signUpBody)
```

It runs the before chain on the input, calls the function with the rewritten input, and runs the after chain on the output. If a before handler stops it, it fires the failed point with `rejectedByHook`. If the function itself returns an error, no after chain runs; the function is expected to have fired the failed point for its own business rejections.

## Hook point reference

### Data points (Tier 1)

Fired by the store. See [What each data point carries](#what-each-data-point-carries).

| Point | Phase |
| --- | --- |
| `data.user.beforeCreate` | before |
| `data.user.afterCreate` | after |
| `data.user.beforeUpdate` | before |
| `data.user.afterUpdate` | after |

### Flow points (Tier 2)

Core declares these, so a handler can be registered on any of them.

| Point | Phase | Fired by | Payload, result or reason |
| --- | --- | --- | --- |
| `auth.signUp.before` | before | email/password sign-up | the sign-up fields from the request, including `email` and the plaintext `password` |
| `auth.signUp.after` | after | email/password sign-up | the created `*models.User` |
| `auth.signUp.failed` | failed | email/password sign-up | codes `userExists`, `rejectedByHook` |
| `auth.signIn.before` | before | email/password sign-in | `email`, `password` |
| `auth.signIn.credentialsVerified` | before | sign-in, after the password check | `HookValueUserID`. A second-factor plugin stops the sign-in here. |
| `auth.signIn.after` | after | email/password sign-in | the sign-in result |
| `auth.signIn.failed` | failed | email/password sign-in | codes `userNotFound`, `noCredentialAccount`, `invalidCredentials`, `secondFactorRejected`, `rejectedByHook`. Audited. |
| `auth.signOut.before` | before | sign-out | `sessionID` |
| `auth.signOut.after` | after | sign-out | nil |
| `auth.session.beforeCreate` | before | session manager | user id, state, IP address, user agent |
| `auth.session.afterCreate` | after | session manager | the created `*models.Session` |
| `auth.session.beforeRevoke` | before | session manager | session id, reason |
| `auth.session.afterRevoke` | after | session manager | the revoked `*models.Session` |
| `token.beforeIssue` | before | token manager | token kind and subject |
| `token.afterIssue` | after | token manager | the issued token |
| `token.consumed` | after | token manager | the consumed token |
| `token.failed` | failed | token manager | the classified error code, with the error as `Cause` |

The session and token points are Tier 2 even though they sit next to a table write: the managers fire them outside any store transaction, `hctx.Tx` is nil, and an after handler's error is logged.

The `auth.signUp.*`, `auth.signIn.*` and `auth.signOut.*` points are fired by the email/password plugin, which can't be booted through `Prepare` and `Boot` yet.
