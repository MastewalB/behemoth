## **Hooks**

This folder explains how hooks work inside Behemoth: how a hook point is declared, how a handler is registered on it, how the handlers of a point are put in order, and how the dispatcher runs them when the point is fired.

For how to use hooks from a plugin or an application, read [`../../api/hooks.md`](../../api/hooks.md). These documents describe the code behind that API.

| Document | Covers |
| --- | --- |
| [1. Purpose and Components](<1. Purpose and Components.md>) | why hooks exist, every type involved and where it lives, the import rules between the packages |
| [2. Hook Taxonomy](<2. Hook Taxonomy.md>) | the two tiers, the three phases, point names, every point core declares and who fires it |
| [3. Hook Context](<3. Hook Context.md>) | `HookContext`, the three handler signatures, who builds the context at each firing site |
| [4. Hook Declaration and Priority](<4. Hook Declaration and Priority.md>) | `HookCatalog`, `HookRegistry`, owner scoping, the order resolution that produces the frozen chains |
| [5. Hook Dispatching](<5. Hook Dispatching.md>) | `Dispatcher`, `DefaultDispatcher`, rate limits and audit at dispatch, `WithLifecycle`, the firing sites |
| [6. Data Hooks](<6. Data Hooks.md>) | `store.Hooks`, `dataHooks`, how a table write becomes a dispatch, the after-commit points |

The transaction rules of data hooks (what `HookContext.Tx` is bound to, what a rollback undoes, the commit queue) are described in full in [`../models/models.md`](../models/models.md#data-hooks-and-transactions). Document 6 covers the bridge between the store and the dispatcher and links there for the rest.

The code lives in:

- `types/plugins.go`: the public types (`HookPoint`, `HookPhase`, `HookPointDef`, `HookCatalog`, `HookRegistry`, `HookOptions`, `HookContext`, the handler function types, `Dispatcher`, `WithLifecycle`, `KahnSort`)
- `types/hooks/hooks.go`: the names of the points core declares and the shared payload keys
- `types/init/init.go`: the implementations (`DefaultHookCatalog`, `DefaultHookRegistry`, the scoped wrappers, `freezeAllHookChains`, `DefaultDispatcher`) and `Prepare` and `Boot`, which run them
- `types/init/datahooks.go`: `dataHooks`, the adapter between the store and the dispatcher
- `store/store.go` and `store/create.go`: `store.Hooks` and the write paths that call it

---

# **From declaration to execution**

A hook goes through four stages. The first three happen once, at startup. The fourth happens on every request.

| Stage | When | What happens | Result |
| --- | --- | --- | --- |
| Declare | `Prepare` | core and each plugin add `HookPointDef`s to the `HookCatalog` | a frozen catalog: the set of points that exist, each with one phase and one owner |
| Register | `Boot` | each plugin, then the application, attach handlers through a `HookRegistry` | an unordered list of handlers per point |
| Freeze | `Boot` | `freezeAllHookChains` orders each point's handlers | `frozenChains`: one ordered slice per declared point |
| Dispatch | request time | firing code calls a `Dispatcher` method with a point | the point's chain runs |

Nothing is added or reordered after the freeze. A dispatch reads the catalog and the frozen chains and writes neither.

### **One sign-up, end to end**

The example follows `POST /sign-up/email` from the email/password plugin with one extra plugin, `profile`, that adds a row of its own for every new user and sends a welcome email.

**At `Prepare`:**

1. `CoreDeclareHookPoints` declares 23 points under owner `core`, among them `auth.signUp.before`, `auth.signUp.after`, `auth.signUp.failed`, `data.user.beforeCreate`, `data.user.afterCreate` and `data.user.created`.
2. Each plugin's `Declare` runs in dependency order. Neither plugin declares a point of its own here.
3. The catalog is frozen.

**At `Boot`:**

4. A `DefaultHookRegistry` is created over the catalog.
5. Each plugin's `Register` runs with a registry scoped to the plugin's name. `profile` calls `OnAfter(data.user.afterCreate, ...)` and `OnAfter(auth.signUp.after, ...)`. The registry checks that each point exists and is an after point.
6. `freezeAllHookChains` builds the chain of every declared point. `data.user.afterCreate` and `auth.signUp.after` get a chain of one handler. The other 21 get an empty chain.
7. The `DefaultDispatcher` is built from the catalog and the chains and put on the `AuthContext`.
8. The store is built with `dataHooks` as its `store.Hooks`.
9. The email/password plugin's `Init` wraps `signUpBody` with `WithLifecycle` and the three sign-up points.

**At the request:**

| Step | Code | Dispatch |
| --- | --- | --- |
| 1 | the router puts the `RequestContext` on the context (`ContextWithRequest`) | |
| 2 | `handleSignUp` builds a `HookContext` and calls the wrapped flow | |
| 3 | `WithLifecycle` | `RunBefore(auth.signUp.before)` with the request fields as payload |
| 4 | `signUpBody` validates, hashes the password, opens `Store.Transaction` | |
| 5 | `tx.CreateUser` → `Store.create` → `dataHooks.BeforeCreate` | `RunBefore(data.user.beforeCreate)` with the user row |
| 6 | the user row is inserted | |
| 7 | `dataHooks.AfterCreate` | `RunAfterTx(data.user.afterCreate)`: `profile` writes its row through `hctx.Tx` |
| 8 | `tx.CreateAccount` inserts the credential account | none: `accounts` fires no hooks |
| 9 | the transaction commits | |
| 10 | the commit queue runs `dataHooks.CreateCommitted` | `RunAfter(data.user.created)` |
| 11 | `signUpBody` returns the user to `WithLifecycle` | `RunAfter(auth.signUp.after)`: `profile` sends the email |

The two tiers show in this trace. Steps 5 to 10 are Tier 1: the store fires them, and steps 5 and 7 run inside the transaction. Steps 3 and 11 are Tier 2: the flow fires them, outside the transaction.

What a failure does depends on where it happens:

- A handler error in step 3 stops the sign-up before anything is written. `WithLifecycle` fires `auth.signUp.failed` with code `rejectedByHook`.
- A handler error in step 5 or 7, or a failed insert in step 8, rolls the transaction back. Step 10 never runs. A handler's typed rejection is returned to the caller as it is, and `signUpBody` fires `auth.signUp.failed` with code `rejectedByHook` for it. A system failure fires no failed point.
- A handler error in step 10 or 11 is logged. The user exists and the sign-up succeeds.

---

# **Terms**

| Term | Meaning |
| --- | --- |
| Hook point | a named place in the code where handlers can run, for example `auth.signIn.before`. A `types.HookPoint` string. |
| Phase | what kind of point it is: before, after or failed. A point has one phase. |
| Tier | who fires the point. Tier 1 points are fired by the store around a table write. Tier 2 points are fired by a flow or a manager around an operation. |
| Owner | the name a declaration or a handler is attributed to: `core`, a plugin's name, or the application's name (`app` by default). |
| Handler | a function registered on a point. Its type follows the point's phase. |
| Chain | the ordered handlers of one point. |
| Fire, dispatch | to run a point's chain through the `Dispatcher`. |
| Firing site | the code that dispatches a point: the store bridge, a manager, a plugin flow. |
