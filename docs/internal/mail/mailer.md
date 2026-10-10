## **Mailer**

This document explains how plugins send messages: the `Mailer` on the `AuthContext`, the application's `MailSender` behind it, and the background pool that `SendAsync` uses.

The code lives in:

- `types/mail.go`: `MailMessage`, `MailKind`, `MailSender`, `MailConfig`, the `Mailer` interface
- `types/init/mailer.go`: `DefaultMailer`
- `types/init/init.go`: `Boot` builds it from `BootConfig.Mail`

---

# **Two layers**

| Layer | Who writes it | What it does |
| --- | --- | --- |
| `MailSender` | the application | delivers one message: SMTP, a provider's API, its own queue |
| `Mailer` | core (`DefaultMailer`) | what plugins call. It adds the choice between waiting and not waiting, a metric, and the log line of a background failure |

A plugin never sees the sender. It builds a `MailMessage` and calls `ac.Mailer.Send` or `ac.Mailer.SendAsync`. This is the same split as hooks: plugins call the dispatcher and never see the handlers behind it.

`Boot` always sets `AuthContext.Mailer`, with or without a sender. `Configured()` says which, and a plugin that can't work without one returns a configuration error from `Init`.

# **`Send` and `SendAsync`**

```go
err := ac.Mailer.Send(ctx, msg)      // calls the sender, returns its error
err  = ac.Mailer.SendAsync(ctx, msg) // queues, returns; the error means "not queued"
```

The plugin chooses per operation, by what a failed send costs:

| Plugin | Call | Why |
| --- | --- | --- |
| `magiclink`, default | `SendAsync` | the sender's speed then does not show in the response time, which would tell a known email from an unknown one. A lost message costs a retry |
| `magiclink`, with `WaitForSend` | `Send` | a link that was not sent is revoked and the failed point fires with `sendFailed` |
| `emailverification`, its links | `SendAsync` | the send is triggered by a sign-up or a profile update, which should not wait for a mail provider. A lost message costs a retry, and a repeated send is harmless |
| `emailpassword`, a password reset link, default | `SendAsync` | as for a magic link |
| `emailpassword`, the notice that a password was reset | `SendAsync` | the password is already set, so there is nothing to undo when the notice fails |
| `emailpassword`, with `Reset.WaitForSend` | `Send` | a link that was not sent is revoked and the failed point fires with `sendFailed` |
| `emailverification`, the notice of an email change | `Send` | the notice is what lets the owner stop a change. If it can't be handed over, the request fails and no confirmation link is issued |

### **What `SendAsync` does**

1. Returns a configuration error when there is no sender, and `ErrMailerClosed` after `Close`.
2. Puts `{context.WithoutCancel(ctx), msg}` on a buffered channel. If the channel is full it counts `dropped` and returns `ErrMailQueueFull` without blocking.
3. On the first call, starts `Workers` goroutines that read the channel.

A worker runs `sender.Send` under `context.WithTimeout(q.ctx, SendTimeout)`. It recovers a panic of the sender and treats it as an error. An error is logged at Error under the `mail` component with the message's kind, and counted. The address is left out of the log line.

- **The context keeps its values and loses its cancellation.** The request is usually over by the time the worker runs, and its context is canceled then. The values stay so that the log line carries the request ID.
- **The lock is held across the channel send.** `SendAsync` and `Close` take the same mutex, and the send is non-blocking, so a message can't be written to a closed channel.
- **`Close` closes the channel and waits for the workers,** or for its context. Messages already queued are sent.

### **What it is not**

The pool is a convenience for an application without a queue. It has no retry, no backoff and no persistence: a failed message is logged and gone, and queued messages are lost when the process dies. An application that needs more gives a `MailSender` that enqueues onto its own queue. `Send` and `SendAsync` then both return in the time an enqueue takes.

# **Metrics**

`behemoth.mail.sent{kind, result}`: `sent` and `error` are counted where the sender returns, in both modes. `dropped` is counted in `SendAsync` when the queue is full.

# **Tests**

| Test | File | Covers |
| --- | --- | --- |
| `TestMailerSendWaits` | `types/init/mailer_test.go` | no sender, the sender's error returned, the metric |
| `TestMailerSendAsync` | same | the send outlives the caller's canceled context, a failure and a panic are logged, a full queue refuses, `Close` drains and then refuses |
| `TestMagicLinkSendsInBackground` | `tests/plugins/magiclink_test.go` | the request returns while the sender is blocked, and a failed send leaves the link valid |
| `TestPasswordResetSendsInBackground` | `tests/plugins/passwordreset_test.go` | the same for a reset link |
| `TestEmailVerificationAfterSignUp` | `tests/plugins/emailverification_test.go` | a sign-up returns while the sender is blocked |

# **Design decisions**

### One sender for every plugin
**Context:** The magic link plugin took a `SendLink` callback in its own options. Email verification needed to send too, and so did password reset later.
**Options considered:**
- *A callback per plugin.* No shared surface. Every plugin adds an option to wire, and each defines its own message type.
- *A mailer interface in core with SMTP and provider adapters.* Works out of the box. A large surface that every application replaces with its own provider and templates.
- *One sender the application provides, behind a `Mailer` on the `AuthContext`.* Wired once. Core composes no message: it passes a kind, an address, a link and metadata.
**Decision:** The third. `MailKind` tells the sender which template to use, and a plugin can define its own kind.
**Revisit if:** a plugin needs a channel other than email (SMS codes). `MailMessage` is shaped for a link sent to an address.

### The sender is synchronous; not waiting is the plugin's choice
**Context:** A sender that calls SMTP or a provider's API directly takes hundreds of milliseconds. Called inside a request, it holds the request for that long.
**Options considered:**
- *Synchronous only; tell the application to enqueue.* The simplest contract. The simplest sender is a direct SMTP call, so the common case is the slow one.
- *Always in the background.* No request waits. A failure can't be returned, so the magic link plugin could not revoke a link that was not sent, and an application with a real queue gets a weaker in-memory queue in front of it.
- *A synchronous sender contract, with `Send` and `SendAsync` on the mailer.* The plugin decides per operation whether a failure is worth waiting for.
**Decision:** The third. Whether to wait depends on the operation and not on the application: an idempotent send whose failure costs a retry (email verification) does not wait, and one whose failure the plugin acts on (a magic link by default) does. The magic link plugin exposes the choice as an option because both answers are reasonable there.
**Revisit if:** applications need retries from the built-in pool. That is a job queue, and should be a separate component with storage.
