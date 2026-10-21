# 0008. Renew the session token when a pending session becomes active

- **Status:** Accepted
- **Date:** 2026-10-22
- **Deciders:** MastewalB
- **Affects:** `core` (`SessionManager.Promote`), `auth` (`DefaultSessionManager`), the two-factor plugin, and any plugin that promotes a session

## Context and problem

A sign-in that needs a second factor creates a pending session and hands its token to the client. The client presents that token together with the second factor. `SessionManager.Promote` then makes the session active: it resets `FreshAt` and the expiry, and keeps the token.

Keeping the token causes two problems:

- **The client's copy falls out of step.** Under the cookie deliveries the cookie was set to expire with the pending session, 10 minutes after the sign-in. A browser drops it then, although the session now lasts days. Setting the cookie again needs the raw token. The flow that verifies the second factor never sees it: the flow learns the session from the caller (`identity.SessionRef`), which holds no secret. Only the HTTP handler could read the token from the request, so the fix would live in the wrapper, which [`../guidelines/transport_neutral_flows.md`](../guidelines/transport_neutral_flows.md) asks to avoid.
- **The token outlives a change of privilege.** A pending token is handed out before the user is fully authenticated, and it passes through places an active token avoids: a script that read a body delivery, a log of the challenge requests. The OWASP Session Management Cheat Sheet asks for a new session id after any change of privilege level. With the token kept, whoever copied the pending token holds the active session as soon as the user passes the second factor.

## Decision drivers

In priority order:

1. A token copied before the second factor never authenticates the active session.
2. The flow that verifies the second factor returns everything a transport needs to deliver the session, as a sign-in flow does.
3. One sign-in keeps one session row, so that its id and its audit trail don't split.
4. The change to the session manager's contract stays small.

## Options considered

### Option A: keep the token

The HTTP handler reads the token from the request and sets the cookie again with `TokenCarrier.Extend`.

- **Pros:** No change to `SessionManager`.
- **Cons:** Driver 1 fails. Driver 2 fails too: the flow can't return the token, so each transport repeats the handler's step.
- **Fails when:** a script reads a pending token from a body delivery before the user enters the code. The script holds a signed-in session afterwards.

### Option B: a new token on the same session

`Promote(ctx, sessionID, factor)` generates a new raw token. It replaces the lookup hash and the keyed hash in the same guarded write that sets the state, and returns the token.

- **Pros:** Drivers 1 to 3 hold. The verify flow returns a `core.SignInResult` with the raw token, and its route answers with `WriteSignIn` like any sign-in. Under the cookie deliveries the new cookie replaces the old one and expires with the active session.
- **Cons:** `Promote`'s signature changes. The client must replace its token, which a client of the body or header delivery does from the answer.
- **Fails when:** a transport can't hand the client a new credential in its answer to the second factor.

### Option C: a new session, with the pending one revoked

The verify flow calls `Create` for an active session and revokes the pending one.

- **Pros:** No new method. `Create` supplies the new token.
- **Cons:** Driver 3 fails: one sign-in becomes two sessions, with two creates and a revoke in the audit log, and handlers on `auth.session.beforeCreate` see the user a second time.
- **Fails when:** a handler on `auth.signIn.after` keeps the session's id, for a list of the user's devices for example. The second factor revokes the session it kept, and the user goes on with a session whose id the handler never saw.

## Decision

We chose Option B. `Promote` also records the second factor ([ADR-0009](0009-recording-the-factors-of-a-session.md)), and its write is guarded on the pending state, so of two promotions of one session, one succeeds.

## Rationale

Option A leaves open the window that driver 1 is about, and puts part of the operation in the HTTP handler. Option C closes the window at the cost of a split trail, and of an id that changes between the two steps of one sign-in. Option B changes a few more columns of a row that the promotion writes anyway.

## Consequences

- **Gains:**
  - A pending token stops working when its session becomes active.
  - The verify flow's result is a sign-in result, so every transport delivers it the way it delivers a sign-in.
- **Costs and risks we accepted:**
  - `Promote` returns a raw token, and its callers change. Today they are tests only.
  - A client takes the token from the answer to the second factor, as it takes one from a sign-in. A client that keeps the pending token gets `session_invalid`.
  - The session cache drops the entry under the old lookup hash, and stores the session under the new one.
- **Follow-up work:** step 3 of [`../plans/two_factor.md`](../plans/two_factor.md).

## Invariants

- **A session's token changes when the session becomes active.** If it doesn't, a pending token copied before the second factor authenticates the active session.
- **The new token and the new state are written together, in one guarded write.** If they were two writes, a request between them would find an active session under the old token.

## Revisit when

- A transport can't hand the client a new credential in its answer to the second factor.
- Sessions gain another change of privilege, such as an impersonation that starts on an existing session. It would renew the token in the same way.

## References

- [`../plans/two_factor.md`](../plans/two_factor.md): the flow that promotes a session
- [`../sessions/token_delivery.md`](../sessions/token_delivery.md): how a token travels, a pending one included
- `auth/session.go`: `DefaultSessionManager.Promote` and `create`
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew the session id after any privilege level change
