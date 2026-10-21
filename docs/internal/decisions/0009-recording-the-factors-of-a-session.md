# 0009. Record on each session the factors that authenticated it

- **Status:** Accepted
- **Date:** 2026-10-22
- **Deciders:** MastewalB
- **Affects:** `core` (`SessionMeta`, `SessionManager.Promote`, the factor names), `core/hooks` (the checkpoint payload), `models` (`Session` and the `sessions` table), `identity` (`SessionRef`), `auth`, the email/password, magic link, phone number, OAuth, and two-factor plugins, and sign-in plugins written outside this repository

## Context and problem

The two-factor plugin must not accept a second factor that repeats the first factor's channel. An email code after a magic link proves control of the same mailbox twice, and an attacker who holds the mailbox passes both. An SMS code after a sign-in by phone code proves the same phone number twice.

The plugin applies the rule at two moments. At the sign-in checkpoint, the sign-in flow can name its factor in the payload. In the later requests of the challenge, the plugin knows only the pending session, and nothing records how that session's first factor was proved. `HookValueMethod` names the plugin that ran a sign-in, and the phone number plugin runs two kinds of sign-in: by code and by password.

## Decision drivers

In priority order:

1. A second factor never repeats the first factor's channel, whichever plugin checked the first.
2. What the challenge reads survives between requests and across replicas.
3. A session never exists without the record, so no gap between two writes leaves the rule without it.
4. Any flow can read the record, not only the two-factor plugin.
5. The change to core stays small.

## Options considered

### Option A: a table of the two-factor plugin, keyed by session

A handler on `auth.signIn.after` stores the session's id and the factor that the checkpoint saw.

- **Pros:** No change to core's tables.
- **Cons:** Driver 3 fails: an after handler's error is logged, and the sign-in succeeds without the record. Driver 4 fails. The table needs a cleanup of its own.
- **Fails when:** the write fails after the session was created. The pending session can't be completed, and the user signs in again.

### Option B: the sign-in method on the session

Record `HookValueMethod`: `emailpassword`, `magiclink`, `phonenumber`, or `oauth`.

- **Pros:** The value exists already.
- **Cons:** A method names a plugin, not what was proved. Driver 1 fails for the phone number plugin.
- **Fails when:** a user whose method is SMS signs in with a phone number and a password. The rule can't tell that sign-in from one by code, so it refuses SMS for both or for neither.

### Option C: the session records its factors

Every sign-in flow names the factor it checked: `password`, `email`, `sms`, or `oauth`. It passes the name in the checkpoint payload, under `factor`, and in `SessionMeta.Factor`. The session stores the name in a new nullable column, `sessions.factors`. `Promote` appends the second factor: `totp`, `email`, `sms`, or `recovery_code`. `identity.SessionRef.Factors` carries the list to flows.

- **Pros:** Drivers 1 to 4 hold. The record is written in the same insert as the session. It is the fact that OpenID Connect calls `amr` (RFC 8176), which a list of the user's sessions, a step-up policy, or a token for other services can use later.
- **Cons:** A new column on a core table, and a field that every sign-in plugin sets.
- **Fails when:** a sign-in plugin passes no factor. Its sessions record none, and the rule can't exclude a channel for them.

### Option D: no rule

Accept any second factor after any first factor.

- **Pros:** Nothing to build.
- **Cons:** Driver 1 fails.
- **Fails when:** a user's mailbox is taken over and their method is an email code. The magic link and the code both arrive in the attacker's mailbox.

## Decision

We chose Option C. Factor names are plain strings in lowercase snake case. `core` names the six that Behemoth's plugins record, and another plugin may record a name of its own. The column holds the names separated by spaces, in the order they were proved.

## Rationale

Option D gives up the property that a second factor exists for. Option B can't express the phone number plugin's two kinds of sign-in. Option A serves the two-factor plugin alone, and leaves a gap between the session's insert and its record. Option C costs a column and a field per sign-in plugin, and the fact it records belongs to the session.

## Consequences

- **Gains:**
  - The channel rule compares names that the caller already carries, without a read.
  - A session says how it was authenticated, for a list of the user's sessions, for the audit log, and later for an `amr` claim.
- **Costs and risks we accepted:**
  - The column is new on a core table, and the new version writes it, so an application migrates before it deploys. M9 in `docs/ongoing.md` describes the same order for a new table.
  - Every sign-in plugin passes its factor, plugins outside this repository included. One that doesn't records no factor.
  - The names become a contract once shipped: stored sessions and an application's checks hold them.
- **Follow-up work:** step 2 of [`../plans/two_factor.md`](../plans/two_factor.md).

## Invariants

- **Every sign-in flow passes the factor it checked, in the checkpoint payload and in `SessionMeta`.** A flow that skips it lets a second factor repeat its channel.
- **A factor name means one channel, whichever plugin records it.** `email` is control of a mailbox, and `sms` is control of a phone number by text message. If two plugins used one name for two channels, the rule would exclude the wrong method.
- **Factors are appended, never removed or rewritten.** A session's list is the history of its proofs.

## Revisit when

- A token for other services carries `amr`. The names then map to RFC 8176's values, such as `pwd` and `otp`.
- One credential proves two factors at once, such as a passkey with user verification. `SessionMeta.Factor` would become a list.
- The rule needs more than the channel, for example so that an email code to a second mailbox counts after a magic link.

## References

- [`../plans/two_factor.md`](../plans/two_factor.md): the channel rule, and the factor each sign-in records
- [ADR-0008](0008-renewing-the-session-token-on-promotion.md): `Promote`, which appends the second factor
- `core/hooks/hooks.go`: the checkpoint's point and the payload keys
- [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176): Authentication Method Reference values
