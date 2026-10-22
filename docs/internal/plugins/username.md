# Username plugin

This document explains how `plugins/username` adds usernames on top of the email/password plugin: where the column lives, where the rules are applied, and how sign-in by username reuses the email sign-in.

## What the plugin contributes

| `core.Plugin` method | Result | Why |
| --- | --- | --- |
| `Meta` | name `username`, a dependency on `emailpassword`, no mount path | `emailpassword` is initialized first, and the route sits next to `/sign-in/email` |
| `Declare` | the `username` and `display_username` columns on `users`, and a route rate-limit rule per route | the column is the plugin's; core's sign-in rule is bound to `/sign-in/email` |
| `Register` | handlers on `auth.signUp.before`, `data.user.beforeCreate` and `data.user.beforeUpdate` | the rules hold for every write of a user |
| `Middlewares` | nothing | |
| `Init` | checks the options and that an email/password plugin was given | |
| `Routes` | `POST /sign-in/username`, and `POST /username/available` with `Options.AvailabilityRoute` | sign-up uses the email/password plugin's route |

Compare with the other two sign-in plugins. The magic link plugin has a flow of its own and fires `auth.signIn.*` itself, because nothing in its sign-in is shared with a password sign-in. This plugin has no sign-in body: everything after "which user" is the email/password plugin's, so it calls into it. It is also the first plugin that uses `PluginMeta.Dependencies`.

## The column

`username.Column` is a `schema.Field[string]` on `users`, declared unique, nullable, public and 64 characters long (`MaxColumnLength`). `Options.MaxLength` can't exceed the column, so changing the option plans no migration.

The value lives in `User.Extra`, like any contributed column:

| Case | In `Extra` | In the database |
| --- | --- | --- |
| a user with a username | `"username": "ada"` | `ada` |
| a user created without one | no key | `NULL`: the insert leaves the column out |
| a username removed by an update | `"username": nil` after the read back | `NULL` |

The handlers never store an empty string. `onUserCreate` deletes the key and `onUserUpdate` writes nil. This is what lets the unique constraint allow any number of users without a username. `TestUsernameRulesAtSignUp` reads the column with SQL to check it.

A user read from the database has the key with a nil value, and one fresh from `CreateUser` without a username has no key. `Column.Get` reports both as "no value". `PublicView` passes them on as they are, so a response has `"username": null` or no `username` key.

`username.DisplayColumn` (`display_username`) is the second column: nullable, public, not unique, the same length. It holds the username as it was typed. The handlers write the two columns together, so it is `NULL` exactly when `username` is.

## Where the rules are applied

`Plugin.Validate` is the one place the rules are written: normalize (`Normalize`: trim, lowercase), length, the character set, the reserved names. Three handlers call it.

| Handler | Point | What it does |
| --- | --- | --- |
| `onSignUp` | `auth.signUp.before` | validates the sign-up's `username` and `display_username`, applies `RequireAtSignUp`, and leaves both in `Values` under `username.signUp` and `username.signUpDisplay` |
| `onUserCreate` | `data.user.beforeCreate` | takes the two from the row, or else from `Values`; validates them, checks the username is free, and writes both to the row |
| `onUserUpdate` | `data.user.beforeUpdate` | the same for an update that names `username`; the row's own id is not a conflict. An update that names only `display_username` goes to `respell` |

- **The data handlers are the enforcement.** They run for a sign-up, for `Store.UpdateUser` and `Store.CreateUser` called by the application, and for any later plugin that writes users. The email verification plugin covers address changes the same way.
- **The sign-up handler exists for two reasons.** The email/password plugin copies only its own profile fields from the sign-up input to the user, so the username has to travel another way: the user's create is an operation nested in the sign-up, and starts with a copy of the sign-up's `Values`. The handler also refuses a bad username before the password is hashed.
- **The taken check runs in the write's transaction** (`hctx.Tx.FindUserBy`). It gives the typed `username_taken` in the usual case. Two writes racing for one name can both pass it, and the unique constraint refuses the second. The store answers that with the column's code, `username_taken` too, since the column is declared unique ([`../database/adapters/unique_keys.md`](../database/adapters/unique_keys.md)). Only the message differs: "username is already taken".
- **`onSignUp` clears its note first.** A sign-up started inside another sign-up's operation would otherwise inherit the outer one's username.
- **`resolve` pairs the two values.** It takes the username and the display form as they arrive and returns both in the form to store. Without a display form it uses the username as typed, trimmed. With one it requires `Normalize(display) == name`.
- **`respell` does not validate the username again.** It reads the user's username in the write's transaction and compares. A username accepted under older limits can still be respelled, as it can still sign in.
- **`RequireAtSignUp` is about sign-up only.** A user created by `Store.CreateUser` or by another sign-in plugin needs no username.

## Sign-in

`Plugin.SignIn` is a call of `emailpassword.Plugin.SignInWith`:

```go
return p.passwords.SignInWith(ctx, emailpassword.IdentifierCredentials{
	Key: HookValueUsername, Value: Normalize(creds.Username),
	Password: creds.Password, Extra: creds.Extra, Method: PluginName,
	Find: func(ctx context.Context, s *store.Store, value string) (*models.User, error) {
		return s.FindUserBy(ctx, Column.Name, Normalize(value))
	},
})
```

[`emailpassword.md`](emailpassword.md) describes `SignInWith` under *Sign-in by another identifier*. What follows from it here:

- The username is normalized before the call, because `SignInWith` publishes `Value` in `Values` as it is, and a rule per username should count `Ada` and `ada` together. It is normalized again in `Find`, because a before handler may have rewritten it.
- `Find` does not apply the rules. A username stored under older limits still signs in, and a string that could never be stored finds no user. An empty username finds none either, since no row holds an empty string.
- An unknown username, a user without a credential account and a wrong password get the email sign-in's `invalid_credentials`, and the password is hashed for an unknown username as it is for an unknown email.
- An email address in the username field finds no user. The two routes do not accept each other's identifier, so a client plugin for usernames and one for email and password each have one route to call.

`Plugin.SetUsername` is `Store.UpdateUser` with the one column, for the application's code. It is an admin operation: `Access.RequireAdmin` with `user:set_username` (`PermissionSetUsername`). The update handler does the work, and sets the display form from the value passed.

## Availability

`Plugin.Available(ctx, username)` answers whether a username can be taken:

| Username | Answer |
| --- | --- |
| breaks a rule of length or characters | a validation error, `username_invalid_input` |
| reserved | `false` |
| held by a user | `false` |
| otherwise | `true` |

`Validate` is split for this. `wellFormed` has the rules about shape, and `Validate` adds the reserved names. A reserved name is a refusal when someone tries to store it, and "not available" when someone asks.

The lookup uses `AuthContext.Store`, outside any transaction, and nothing is reserved by a `true`. The flow fires no points and has no hook rule: it reads one row and changes nothing.

`handleAvailable` is mounted by `Routes` only with `Options.AvailabilityRoute`, and `Declare` adds `RuleAvailableRoute` (30 a minute per address) under the same condition. The flow itself does not look at the option.

## Tests

| Test | File | Covers |
| --- | --- | --- |
| `TestUsernameSignUpAndSignIn` | `tests/plugins/username_test.go` | the stored form, sign-in in any casing, the before payload and `Values`, `Method`, email sign-in still working, the five refusals with one answer and their failure codes |
| `TestUsernameRulesAtSignUp` | same | each rule's code, `auth.signUp.failed`, no user created, users without a username and the `NULL` they store |
| `TestUsernameRequiredAtSignUp` | same | the option, and that it does not apply to other creates |
| `TestUsernameRulesOnDirectWrites` | same | `SetUsername`, `Store.UpdateUser` and `Store.CreateUser`, the row's own name, removing a name and reusing it |
| `TestUsernameIsUniqueUnderConcurrentSignUps` | same | one winner among racing sign-ups, the losers refused with `username_taken` |
| `TestSignUpThatLosesTheRaceForAUsername`, `TestSetUsernameThatLosesTheRace` | `tests/plugins/signup_race_test.go` | a value taken after the check: the database's refusal answered with `username_taken` |
| `TestUsernameRoutes` | same | the bodies and statuses of sign-up and sign-in |
| `TestUsernameSignInPassesTheSecondFactorCheckpoint` | same | a pending session |
| `TestUsernameSignInsCanBeLimitedPerUsername` | same | an application's hook rule keyed on `HookValueUsername` |
| `TestUsernameOptionsAndWiring` | same | the dependency, the configuration errors, `SignInWith`'s input checks |
| `TestDisplayUsername` | same | the display form at sign-up, on a create and in updates, alone and with the username; the refusals; `NULL` without a username |
| `TestUsernameAvailability` | same | the flow's four answers, the route's bodies and statuses, the route being off by default |

The tests run on SQLite, with `_txlock=immediate`: the data handlers read in the write's transaction before the row is written, and SQLite refuses a second such transaction with "database is locked" unless the write lock is taken at the start. `docs/ongoing.md` has the entry. The other adapters are covered for contributed columns in general by the store contract (`tests/store/extensions_test.go`), not for this plugin.

## Limits to know

These limits apply:

- `[Not built]` A route to change the caller's username or its spelling. `SetUsername` is the flow such a route would call.
- `[Limit]` The availability route's limit is a route rule, so `Available` called from code has none: the flow fires no hook point for a hook rule to sit on. A sign-in by username is counted by core's `core.signin.address` under the method `username`, which `SignIn` passes to `emailpassword.SignInWith`.
- `[Limit]` A released username is free at once. `docs/ongoing.md` has the entry.
- The validation messages are sent to the client, unlike `emailpassword`'s `invalid email`: they are the plugin's own text and say which rule was broken.

## Design decisions

### The username column belongs to the plugin, not to core

**Context:** `users.username` was a core column: nullable, not unique, written by sign-up as the client sent it. An empty one was stored as `""`. Signing in by it needs it unique and normalized.

**Options considered:**

- *A unique index on the core column.* One column. `User.ToMap` writes an empty string for an empty field, so a unique index would allow one user without a username; core would have to write `NULL` for this one field. The typed casing would be lost, and every application would keep a column that only this plugin gives a meaning.
- *Keep the core column for display and add a unique lookup column.* No change to core, and the casing is kept. Two columns have to stay in step, and the core one still has no rules without the plugin.
- *Remove the column from core and let the plugin contribute it.* One column with one owner. A contributed column that is not set is left out of the insert, so "no username" is `NULL` without special handling. It changes `models.User`, which no application depended on yet.

**Decision:** The third. `models.User` lost `Username`, `GetUsername`, and `UserUsername`, sign-up stopped copying the field, and `FromUserInfo` (removed later with the OAuth provider code) stopped setting it to the email.

**Revisit if:** core needs a username without the email/password plugin, for a sign-in plugin that has no passwords.

### Sign-in goes through the email/password plugin

**Context:** `signInBody` looked the user up by email and was private. A sign-in by username differs from it in that one step.

**Options considered:**

- *A flow of its own, as in the magic link plugin, with `emailpassword` exporting a password check.* The plugin would repeat the hash for an unknown user, the three refusals with one answer, the `credentialsVerified` checkpoint and the session create. A later fix to one copy would not reach the other.
- *A before handler on `auth.signIn.before` that turns a username into an email.* No new code in `emailpassword`. Clients would post a username to `/sign-in/email`, an unknown username would need a made-up email, and the published email would be empty.
- *One sign-in body with the lookup as a parameter (`SignInWith`).* `emailpassword` keeps everything that is about the password, and this plugin supplies `Find`.

**Decision:** The third.

**Revisit if:** an identifier needs a different check after the lookup, not only a different lookup.

### The plugin is given the email/password plugin at construction

**Context:** `SignIn` has to call a method on the application's `emailpassword.Plugin`. `AuthContext` has no way to look a plugin up.

**Options considered:**

- *`username.New(passwords, opts)`.* The dependency is in the signature. A configuration file can't carry a pointer, so the standalone service's plugin factories will have to resolve it by name.
- *A plugin lookup on `AuthContext`, used in `Init`.* The constructor takes data only. It adds a registry of plugins to core, and a type assertion that fails at `Boot` instead of a compile error.

**Decision:** The first. `PluginMeta.Dependencies` names `emailpassword` as well, which orders the two and fails `Prepare` when it is missing.

**Revisit if:** several plugins need another plugin's value. A lookup on `AuthContext` would then be worth its cost.

### One stored form, lowercase

**Context:** Users expect `Ada` and `ada` to be the same account, and some expect to see `Ada`.

**Options considered:**

- *Store as typed and compare case-insensitively.* Needs a case-insensitive unique index, which each database and MongoDB do differently.
- *Store the lowercase form only.* A plain unique constraint works everywhere. The typed form is lost.
- *Two columns: the lowercase form and the typed one.* Both needs are met, at the cost of a second column on every user.

**Decision:** The second at first, then the third: `display_username` was added next to `username` without changing it. See *The display username spells the username*.

### The display username spells the username

**Context:** `display_username` is public and is what an application shows. It needs a rule for what it may hold.

**Options considered:**

- *Any text, like a profile name.* The most freedom. A user with the username `mallory` could show `ada`, and uniqueness would protect nothing a person reads. `firstname` and `lastname` already exist for a free name.
- *Derived only: always the username as typed, with no input of its own.* Nothing to validate. A user who signed up as `ada_l` can't become `Ada_L` without a username change.
- *An optional input that has to normalize to the username.* The spelling can be given or changed alone, and it can never read as another username.

**Decision:** The third. The value is checked wherever it is written, by the same data handlers as the username.

**Revisit if:** applications want a free-form handle shown next to the username. That would be another column, not a looser rule on this one.

### The availability route is opt-in

**Context:** A sign-up form wants to tell the user that a name is taken before they submit. Any answer to that question also tells a stranger which usernames exist.

**Options considered:**

- *No route; let applications call `Available` from their own.* Nothing exposed by default. Every application with a sign-up form writes the same route.
- *Always mounted.* Works out of the box. An application that treats usernames as private can't turn it off, and sign-in's single answer for unknown usernames would be undone by default.
- *Mounted when `Options.AvailabilityRoute` is set, with a rule per address.* The application decides, and the flow is the same either way.

**Decision:** The third. The route is a `POST` with the username in the body, so usernames stay out of URLs and access logs, and every route of the plugin is a JSON call. A reserved name answers `false` and not an error, so the response does not show which names are reserved for the application and which are users.

**Revisit if:** the answer should be hidden behind a session or a captcha. A handler can't veto it today, because the flow fires no point.

### Usernames are ASCII and never contain `@`

**Context:** The character set decides whether two usernames can look alike, and whether a username can be an email address.

**Options considered:**

- *Any Unicode letter.* Friendlier in many languages. It needs Unicode normalization and a policy for look-alike characters, or two users can hold names that render the same.
- *`a` to `z`, digits, `_`, and `.`, starting with a letter or a digit.* No look-alikes within the set and nothing to normalize beyond case. A username can't be mistaken for an address, so the two identifiers never overlap.

**Decision:** The second. The set is fixed in `Validate`; the lengths and the reserved names are options, all of them data.

**Revisit if:** applications need other characters. An option would then choose among named sets, so that it stays data.

### No limit per username by default

**Context:** A sign-in by username publishes no email, so an application's rule per email does not count it.

**Options considered:**

- *Declare a rule per username in the plugin.* Covered without the application doing anything. Core has no rule per email for a reason that applies here too: anyone can keep a user out by failing on purpose.
- *Publish the username and leave the rule to the application.* It matches core's sign-in, which is limited per address only.

**Decision:** The second. The username is published under `HookValueUsername`, the route has a rule per address, and `docs/api/username.md` shows the rule to add next to one per email.
