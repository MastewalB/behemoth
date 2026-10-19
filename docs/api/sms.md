# SMS and one-time codes

Plugins that send text messages hand them to an SMS sender you give Behemoth at `Boot`. Behemoth writes no message text and talks to no provider. The [phone number](phonenumber.md) plugin uses it.

It works like the [mail sender](mail.md), with a code where a mail has a link.

## The sender

```go
ac, err := bmth.Boot(ctx, app, db, bmth.BootConfig{
	SMS: types.SMSConfig{
		Sender: types.SMSSenderFunc(func(ctx context.Context, msg types.SMSMessage) error {
			return provider.Send(ctx, msg.To, textFor(msg.Kind, msg.Code))
		}),
	},
})
defer ac.SMS.Close(context.Background())
```

| `SMSMessage` field | Content |
| --- | --- |
| `Kind` | what the message is for: `types.SMSPhoneVerification`, `types.SMSSignIn`, `types.SMSPasswordReset` |
| `To` | the number, in E.164 form |
| `Code` | the one-time code. It is a credential: do not log it. |
| `ExpiresAt` | when the code stops working |
| `User` | the account the message is about |
| `Metadata` | what the request carried for you, such as a locale. It is client input. |

| `SMSConfig` field | Default | Meaning |
| --- | --- | --- |
| `Sender` | none | Your sender. Without one, a plugin that sends fails `Boot`. |
| `Workers` | 4 | Background sends running at once. |
| `QueueSize` | 256 | Background sends that may wait. |
| `SendTimeout` | 30 seconds | How long one background send may take. |

The sender and the queue behave as follows:

- Your provider's API key belongs to your sender. It is not part of `SMSConfig`.
- A plugin either waits for your sender or queues the message. The phone number plugin queues by default (`WaitForSend`).
- The queue is in memory and does not retry, like the mailer's. If you need retries, use a sender that puts the message on your own queue.
- Call `ac.SMS.Close(ctx)` at shutdown. Mail and SMS have separate queues.
- Messages are counted in `behemoth.sms.sent`, by kind and result (`sent`, `error`, `dropped`).

## One-time codes

`ac.Codes` issues and checks the short numeric codes a text message carries. A plugin of yours can use it:

```go
code, issued, err := ac.Codes.Issue(ctx, "myplugin.confirm", userID, types.CodeOptions{})
// send code ...
consumed, err := ac.Codes.Consume(ctx, "myplugin.confirm", userID, typed)
if errs.IsCodeRejection(err) {
	// wrong, expired, used, or out of attempts
}
```

| `CodeOptions` field | Default | Meaning |
| --- | --- | --- |
| `Length` | 6 | Digits, 4 to 12. |
| `TTL` | 5 minutes | How long the code works. |
| `MaxAttempts` | 5 | Tries, the right one included. |
| `Metadata` | none | Stored with the code and returned by `Consume`. |

Codes behave as follows:

- There is one live code per kind and subject. Issuing another replaces it.
- Only a keyed hash is stored, in the core `verification_codes` table. The table is new in core. Generate and apply a migration before you deploy a version that has it, whether or not you use codes, because deleting a user clears the user's codes from it.
- `Consume` gives one error for every refusal, with the code `code_invalid`.
- Use a user id as the subject when the code belongs to a user: `Store.DeleteUser` removes the codes whose subject is the user's id.
- Expired codes that were never used stay until `ac.Store.PurgeExpiredVerificationCodes(ctx)` runs. Nothing schedules it, so call it from a job, next to the other purges.

A code is not a token. Use `ac.TokenManager` for a long secret that travels in a link, and a code for a short one a person types.
