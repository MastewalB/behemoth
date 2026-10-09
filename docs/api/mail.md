# Mail

Some plugins have to send a message: a sign-in link, a link that confirms an address. Behemoth sends nothing itself and knows no templates. You give it one sender at `Boot`, and every plugin that sends goes through it.

## Setup

```go
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	Mail: types.MailConfig{
		Sender: types.MailSenderFunc(func(ctx context.Context, msg types.MailMessage) error {
			return mailQueue.Enqueue(ctx, msg.To, subjectFor(msg.Kind), msg.URL)
		}),
	},
	// ...
})
defer ac.Mailer.Close(context.Background())
```

`Sender` is a `types.MailSender`, an interface with one method, `Send(ctx, msg) error`. `types.MailSenderFunc` turns a function into one. Return an error when the message was not delivered or handed off.

A plugin that needs a sender (`magiclink`, `emailverification`) makes `Boot` fail with a configuration error when none is set. Without such a plugin, `Mail` can stay empty.

## The message

| Field | Content |
| --- | --- |
| `Kind` | what the message is for: `types.MailMagicLink`, `types.MailEmailVerification`, `types.MailEmailChange`, `types.MailEmailChangeNotice`. Pick the subject and template by it. |
| `To` | the address, trimmed and lowercased |
| `URL` | the link to put in the message, with the token in it |
| `Token` | the raw token, if you build the URL yourself. It is a credential: don't log it. |
| `ExpiresAt` | when the link stops working |
| `User` | the `*models.User` the message is about |
| `Data` | what the plugin adds for the text beyond the link. The two email change messages carry the old and the new address here; the other kinds leave it empty. |
| `Metadata` | whatever the request carried under `metadata`: a locale, a template name |

```go
func send(ctx context.Context, msg types.MailMessage) error {
	locale, _ := msg.Metadata["locale"].(string)
	switch msg.Kind {
	case types.MailMagicLink:
		return mailQueue.Enqueue(ctx, msg.To, templates.SignIn(locale), msg.URL)
	case types.MailEmailVerification:
		return mailQueue.Enqueue(ctx, msg.To, templates.Verify(locale), msg.URL)
	}
	return fmt.Errorf("no template for mail kind %q", msg.Kind)
}
```

`Metadata` is passed through by the plugins without being read or stored. When the message started at a route, it is what the client sent. Check a value before using it in a template or a query. `Data` is different: the plugin fills it, and each kind documents its keys.

## Waiting and background sends

A plugin hands a message to your sender in one of two ways, and each plugin picks the one that fits the operation.

| | The request waits | In the background |
| --- | --- | --- |
| The request returns | after your sender does | once the message is queued |
| A failed send | is returned to the plugin, which can act on it | is logged at Error under the `mail` component and counted; nobody is told |
| Used by | `magiclink`, by default: a failed send revokes the link. The notice of an email change: without it the change does not start | `emailverification`, for its links; `magiclink` with `SendInBackground` |

Email verification sends in the background because nothing is lost when a send fails: the user asks for another link, and asking twice does no harm. A sign-up should not wait for a mail provider.

Background sends run on a small pool inside Behemoth:

| `MailConfig` field | Default | Meaning |
| --- | --- | --- |
| `Workers` | 4 | sends that run at once |
| `QueueSize` | 256 | messages that may wait. When it is full, a new message is refused and the plugin treats that as a failed send. |
| `SendTimeout` | 30 seconds | how long one background send may take |

- **The queue is in memory and does not retry.** A message that fails is gone, and messages still waiting are lost if the process stops without `Close`. If you need retries or durability, give a sender that puts the message on your own queue; it then returns quickly in both modes.
- **Call `ac.Mailer.Close(ctx)` at shutdown.** It stops accepting messages and waits for the queued ones, or for `ctx` to end.
- **A background send does not see the request's cancellation.** It keeps the context's values, such as the request ID in its log lines, and runs under `SendTimeout`.
- **The workers start with the first background send.** A process that never sends starts none.

## Metrics

`behemoth.mail.sent` counts messages by `kind` and `result`: `sent`, `error` when your sender returned an error, and `dropped` when the background queue was full.

## Sending from your own plugin

A plugin takes the mailer from the `AuthContext`:

```go
func (p *Plugin) Init(ac *types.AuthContext) error {
	if !ac.Mailer.Configured() {
		return behemotherr.NewConfigurationError("myplugin.Init", "no mail sender is configured", nil)
	}
	// ...
}

err := ac.Mailer.Send(ctx, types.MailMessage{Kind: "myplugin.invite", To: email, URL: link})      // waits
err = ac.Mailer.SendAsync(ctx, types.MailMessage{Kind: "myplugin.invite", To: email, URL: link})  // does not
```

Define your own `types.MailKind` for a message of your own, and document it so the application can add a template. Use `Send` when your code does something about a failure. Use `SendAsync` when a failed send costs the user a retry and nothing else. The error `SendAsync` returns means the message was not queued.
