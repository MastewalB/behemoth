# 0006. Require a declared permission in every self-service flow and admin operation

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** MastewalB
- **Affects:** `types` (`Access`, `PermissionCatalog`, `PluginInitContext`), `identity` (the grant), `engine` (`Boot`), every plugin with a self-service flow or an admin operation, and plugins written outside this repository

## Context and problem

[`../plans/caller.md`](../plans/caller.md) gives a flow `Access`, through which it requires what it needs of its caller: a user, a fresh session, or a privileged caller. Today every caller that gets past "is there a user" holds all of that user's rights, because a session is the only credential.

That will change. A personal API key, or an agent that acts for a user with an OAuth access token, holds part of a user's rights. On that day each self-service flow has to answer whether this caller may run it, and each admin operation has to answer whether this principal may.

Plugins are written against `Access` from its first release, including plugins outside this repository. Whatever a require call says when it is written is what that plugin says when partial grants arrive.

## Decision drivers

In priority order:

1. A flow written before partial grants exist is safe when they arrive.
2. Partial grants arrive without a change to any flow or plugin.
3. A typo, or a permission that nobody declared, is caught at once, not when the first partial grant meets it.
4. A grant on one's own account never reaches another user's account.
5. Each name has one owner and a description, and the names can be listed for documentation and consent screens.
6. The cost today is small.

## Options considered

### Option A: require a user only, and add permissions later

`RequireUser(ctx)` takes no permission. Permissions are added when the first partial grant exists.

- **Pros:** Nothing to name or declare today.
- **Cons:** The helper's signature changes later for every plugin. A plugin not updated by then grants a delegated caller everything its flows do.
- **Fails when:** an agent with a read-only grant calls a flow of a plugin written before permissions existed. The flow runs in full.

### Option B: a permission string on the require call, undeclared

`RequireUser(ctx, "email:change")`, with any string accepted.

- **Pros:** Drivers 1 and 2 hold. No catalog.
- **Cons:** Nothing checks the strings, so a typo passes. Two plugins can pick the same name for different actions. Nothing lists the names.
- **Fails when:** a flow requires `"email:chnage"`. Every caller passes it today, and the first grant that should cover it doesn't. The mistake surfaces as a refusal in production.

### Option C: a declared permission with a kind, required in every self-service flow and admin operation

A plugin declares each permission in `Declare`, with a name, a kind (self or admin), and a description. `RequireUser`, `RequireFreshUser`, and `OptionalUser` take a self permission, and `RequireAdmin` takes an admin permission. An undeclared permission is a configuration error.

- **Pros:** Drivers 1 to 5 hold. It matches how hook points, token kinds, and rate-limit rules are declared already.
- **Cons:** A constant and a declaration per flow. The names become a public contract before anything grants them partially.
- **Fails when:** a flow needs a permission that depends on its input, such as access to one organization out of several. A fixed name can't express that.

### Option D: the flow's hook point is its permission

A grant lists hook points, such as `auth.emailChange.beforeRequest`.

- **Pros:** No new catalog. Each point has an owner already.
- **Cons:** A hook point names a phase of an implementation, not an action a user grants. Renaming a point would change stored grants.
- **Fails when:** two flows should share one grant, as sending and verifying a new phone number do, or a flow has no before point.

## Decision

We chose Option C, with these parts:

- **A name is `resource:action` in lowercase snake case,** such as `email:change` or `session_token:issue`. That is the usual form of an OAuth scope, so a name can become a scope without a translation.
- **One name stands for one action that a user would grant on its own.** A scope that a user consents to can later bundle several names.
- **Self and admin permissions are separate sets,** and each require method accepts one kind only.
- **The zero grant holds nothing.** The authenticator gives a session every self permission, and a system caller holds every permission.
- **Freshness is required at the call site,** with `RequireFreshUser`, and not in the declaration.

## Rationale

Driver 1 rules out Option A, and driver 3 rules out Option B. Option D ties stored grants to the names of hook points, which name phases of an implementation and change with it, and it can't give two flows one grant.

Option C costs a declaration per flow, which driver 6 accepts, and the commitment of naming early. That commitment is the reason to name now. Once partial grants exist, grants store the names, so the names are cheapest to choose while there are few of them and nothing stores them.

Separate sets for self and admin permissions meet driver 4 by construction. Without them, an agent granted `email:change` on its user's account could pass an admin operation that also required `email:change`, and change any user's email.

Freshness stays at the call site so that a reader of the flow sees it. Policy in the declaration, such as "never grantable to a delegate", can be added later as a field whose zero value is the safe one.

## Consequences

- **Gains:**
  - A plugin written today is safe when partial grants arrive, without a change.
  - A missing declaration fails the first test that runs the flow.
  - The catalog lists every permission with its owner and description, for documentation and consent screens.
- **Costs and risks we accepted:**
  - Each self-service flow and admin operation declares a permission, and plugin authors learn one more catalog.
  - A name, once shipped, is a public contract.
  - Until partial grants exist, every caller that gets past "is there a user" holds every self permission, so the check refuses nobody yet.
- **Follow-up work:** steps 2 and 5 of [`../plans/caller.md`](../plans/caller.md), which also lists the first names.

## Invariants

- **Every self-service flow requires a declared self permission, and every admin operation a declared admin permission.** A flow that skips the requirement grants a delegated caller everything once partial grants exist.
- **A self permission never satisfies `RequireAdmin`, and an admin permission never satisfies `RequireUser`.** If one does, a grant on one's own account reaches every account.
- **The zero grant holds nothing.** If it holds anything, a caller that nobody set up holds it.
- **A shipped name doesn't change.** Grants store names, so a renamed permission silently revokes what was granted under the old name.

## Revisit when

- A flow needs a permission that depends on its input, such as one organization out of several. The catalog would then need permissions with a resource.
- An application wants delegated grants to cover its own routes. The catalog would then take the application's declarations too.
- The names outgrow what a consent screen can show. Scopes that bundle names would then be designed.

## References

- [`../plans/caller.md`](../plans/caller.md): `Access`, the catalog, and the first names
- [ADR-0005](0005-treating-a-missing-caller-as-anonymous.md): the zero caller, and why a missing caller holds nothing
- `types/plugins.go`: `HookCatalog` and `PluginInitContext`, the pattern the catalog follows
- [RFC 6749, section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3): the syntax of a scope
- [RFC 6750, section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1): the `insufficient_scope` error
