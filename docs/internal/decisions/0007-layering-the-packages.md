# 0007. Lay out the packages in layers, with the plugin contracts in `core`

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** MastewalB
- **Affects:** `types` (becomes `core`), `types/init` (becomes `engine`), `types/cryptotypes`, `types/hooks`, `types/schema`, `types/ratelimit`, `crypto`, `errors` (becomes `errs`), `transport` (becomes `auth`), `migration/core` (becomes `migration`), every plugin, the framework and storage adapters, the examples, and the tests

## Context and problem

`types` started as the place for Behemoth's core type definitions. It now holds the plugin contracts, implementations such as `Router` and `OriginCheck`, the HTTP types, and aliases: 22 type aliases and 8 constants of `types/cryptotypes`, and three aliases of `models` types. [`../plans/package_layout.md`](../plans/package_layout.md) lists the contents in full.

The aliases come from the import graph. `types` imports `store`, because `AuthContext.Store` and `HookContext.Tx` are a `*store.Store`, so `store` can't import `types`. The crypto contracts that the store needs moved below `types` and came back as aliases. `store.Hooks` is the store's own interface for the data hooks, for the same reason.

Three package names need an import alias wherever Behemoth imports them:

- `types/init` declares `package types`, and its importers rename it `bmth`.
- `errors` has the name of a standard library package, and its 124 importers rename it `behemotherr`.
- `migration/core` would share its name with the contracts package if the contracts package became `core`.

Two forces shape any layout:

- **The plugin contracts form a hub.** `AuthContext` holds every service: the store, the managers, the dispatcher, the rate limiter, and the mailer. `HookContext` holds the `AuthContext` and the store's transaction. Hook rate-limit rules take a `HookContext`. Whatever package holds `AuthContext` refers to every service contract, and sits above `store`.
- **The store sits below the contracts.** `HookContext.Tx` is a `*store.Store`, so in any layout the store can't import the package that holds `HookContext`. What the store needs from a contract either lives below the store, or is an interface the store declares itself.

The caller plan adds a third: the caller's types must sit below `telemetry` ([`../plans/caller.md`](../plans/caller.md)).

## Decision drivers

In priority order:

1. Each concept has one home and one name: no aliases, and no duplicated types.
2. No package imports a package above it, so no contract is moved or redeclared to break a cycle.
3. A plugin author imports one package for the plugin API, and no Behemoth package needs an import alias in Behemoth's own code.
4. Implementations live apart from contracts, so that each can be read, tested, and replaced on its own.
5. A test can keep HTTP out of flows, as [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md) plans.
6. The move leaves behavior unchanged, and lands in steps.

## Options considered

### Option A: keep `types`, and remove only the aliases and the duplicates

Callers import `types/cryptotypes` and `models` by their own names.

- **Pros:** A small change.
- **Cons:** It leaves the cause. `types` still sits above the store, so a second contracts package (`types/cryptotypes`) stays, under a name that says nothing. The implementations, the HTTP types, and the names that need an alias stay.
- **Fails when:** the next contract that a low package needs, such as the caller, has to go below `types` too. Where a contract lives then depends on who imports it, not on what it is.

### Option B: contracts split by domain

Packages such as `hook`, `session`, `token`, `mail`, and `ratelimit`, each with its contracts.

- **Pros:** Small packages, each named for what it holds.
- **Cons:** The hub cuts across the domains. `HookContext` needs `AuthContext`, `AuthContext` needs every service contract, and a hook rate-limit rule takes a `HookContext`.
- **Fails when:** two domains refer to each other, which they do from the start: `hook` needs `AuthContext`, which needs `RateLimiter`, which needs `HookContext`.

### Option C: contracts where they are consumed

Each consumer declares the interfaces it needs, and no central contracts package exists.

- **Pros:** It follows the Go convention to the letter. The store does this already with `store.Hooks`.
- **Cons:** Plugins share `AuthContext`, `HookContext`, and the dispatcher. Each plugin would redeclare the interfaces it uses, and `AuthContext` has to name its field types somewhere.
- **Fails when:** two plugins have to agree on a type, such as `SignInResult`, which every sign-in plugin returns and every handler on `auth.signIn.after` receives.

### Option D: the plugin contracts in the root package

`behemoth.AuthContext`, `behemoth.Plugin`.

- **Pros:** The shortest import path for plugin authors.
- **Cons:** The root package holds `M`, `Model`, and `Database`, which `models` and `store` import.
- **Fails when:** the root package refers to `*store.Store`, which imports the root package. That is a cycle.

### Option E: one contracts package, in layers

The hub stays together in one package, `core`, above the store. What the store and the lower packages need sits below it, each in a package with a name of its own: `identity`, `schema`, and the crypto contracts in `crypto`. Implementations get packages of their own (`auth`, `dispatch`, `ratelimit`, `messaging`), and the composition root becomes `engine`. The HTTP types move to a package of their own once the caller plan has removed the contracts' references to them.

- **Pros:** Drivers 1 to 6 hold. Each step of the move is mechanical.
- **Cons:** Every plugin, adapter, example, and test changes its imports. `core` stays a large package, and holds the HTTP types until they can move.
- **Fails when:** a contract that the store needs also needs the hub. It then has to be split, as `store.Hooks` splits off the part of the dispatcher's contract that the store uses.

## Decision

We chose Option E, with these names:

- **`types` becomes `core`.** In Behemoth, "core" already means Behemoth itself as opposed to a plugin, as in the owner `core` of hook points and rate-limit rules, and the core tables.
- **`types/init` becomes `engine`.**
- **`errors` becomes `errs`,** which needs no import alias. Its `Is` becomes `IsCategory`, because `errs.Is` next to `errors.Is` reads as the standard function.
- **`transport` becomes `auth`,** because the caller plan uses "transport" for HTTP or another protocol.
- **`migration/core` becomes `migration`,** so that two packages aren't both named `core`.
- **`types/cryptotypes` merges into `crypto`, and `types/schema` becomes `schema`.**
- **The caller's types go in `identity`.**

## Rationale

Option A treats a symptom: the aliases follow from where `types` sits, and removing them leaves a second contracts package in their place. Option B fails on the hub, and Option D on the cycle with the store. Option C works for one interface the store consumes, and fails for a plugin system, whose plugins must agree on shared types.

Option E keeps the hub whole, which is the only shape the hub allows, and moves out of it everything that isn't part of the hub. `store.Hooks` stays, because it is Option C used where Option C fits.

The names follow driver 3. None of them needs an import alias in Behemoth's code, and `core`, `engine`, and `auth` tell a reader what is inside.

## Consequences

- **Gains:**
  - No aliases, no duplicated types, and no import aliases for Behemoth's own packages.
  - `crypto`, `schema`, and `identity` sit below the store, so the store uses them directly.
  - A test checks the layering from the end of part 1, and the HTTP rule from the end of part 2.
- **Costs and risks we accepted:**
  - Every import of a moved package changes, in this repository and in any application built on it. The move happens before a tagged release.
  - `core` holds the HTTP types and their implementations until part 2.
  - The docs change with each step: about 360 references to the old names, in 63 files.
- **Follow-up work:** the steps of [`../plans/package_layout.md`](../plans/package_layout.md).

## Invariants

- **A package imports only packages in earlier rows of the layout.** If one imports a later row, a contract has to move or be redeclared to break the cycle, which is how the aliases started.
- **After part 2, `core` holds contracts and the helpers plugins call over them, and no implementation.** If an implementation moves in, its dependencies reach every plugin.
- **A plugin imports no implementation package (`auth`, `dispatch`, `ratelimit`, `messaging`).** If one does, an application can't replace that implementation without breaking the plugin.
- **A Behemoth package has a name that Behemoth's own code imports without an alias.** If one doesn't, the alias spreads to every importer, as `behemotherr` and `bmth` did.

## Revisit when

- `core` grows past what a reader can hold, and a group of its contracts turns out to be referred to by nothing in the hub. That group can then leave, as `identity` does.
- A second protocol's package appears beside `web`, and the two share code that belongs in neither.
- An application needs to replace an implementation that `AuthContext` names as a concrete type, such as `*store.Store`.

## References

- [`../plans/package_layout.md`](../plans/package_layout.md): the layout, where each identifier goes, and the steps
- [`../plans/caller.md`](../plans/caller.md): `identity`, and the steps that free the HTTP types
- [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md): the import rule
- `store/store.go`: the package comment on why `store` doesn't import `types`, and `store.Hooks`
- `types/crypto.go`: the aliases
- [Package names](https://go.dev/blog/package-names), on the Go blog: names that need no alias, and names that say what a package holds
