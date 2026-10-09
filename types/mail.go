package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// MailKind says what a message is for, so that the application's sender can
// pick a subject and a template. A plugin that sends a message of its own
// defines its own kind.
type MailKind string

const (
	MailMagicLink         MailKind = "magic_link"         // a sign-in link (plugins/magiclink)
	MailEmailVerification MailKind = "email_verification" // a link that confirms an address (plugins/emailverification)
	// MailEmailChange goes to the new address of a requested email change,
	// with the link that confirms it. MailEmailChangeNotice goes to the
	// current address, with a link that undoes the change. Both carry the
	// two addresses in Data (plugins/emailverification).
	MailEmailChange       MailKind = "email_change"
	MailEmailChangeNotice MailKind = "email_change_notice"
)

// MailMessage is one message a plugin wants delivered: everything the
// application's sender needs to write it. Behemoth composes no text and
// knows no template.
type MailMessage struct {
	Kind MailKind
	// To is the address to send to, normalized.
	To string
	// URL is the link to put in the message, with the token in it.
	URL string
	// Token is the raw token, for an application that builds its own URL.
	// It is a credential: do not log it.
	Token string
	// ExpiresAt is when the link stops working.
	ExpiresAt time.Time
	// User is the account the message is about.
	User *models.User
	// Data is what the plugin adds for the message's text beyond the link:
	// the old and the new address of an email change, for example. Each
	// kind documents its keys. Unlike Metadata it does not come from the
	// client.
	Data behemoth.M
	// Metadata is whatever the request carried for the sender: a locale, a
	// template name. Plugins pass it through without reading or storing it.
	// From a route it is client input, so treat it as untrusted.
	Metadata behemoth.M
}

// MailSender delivers a message: by SMTP, through a provider's API, onto
// the application's own queue. The application implements it and passes it
// in MailConfig; behemoth sends nothing itself. Send returns once the
// message is delivered or handed off, and an error when it was not.
type MailSender interface {
	Send(ctx context.Context, msg MailMessage) error
}

// MailSenderFunc adapts a function to a MailSender.
type MailSenderFunc func(ctx context.Context, msg MailMessage) error

// Send implements [MailSender].
func (f MailSenderFunc) Send(ctx context.Context, msg MailMessage) error { return f(ctx, msg) }

// MailConfig configures AuthContext.Mailer.
type MailConfig struct {
	// Sender delivers the messages. nil = no sender: Mailer.Configured
	// reports false, and a plugin that has to send fails Boot.
	Sender MailSender

	// Workers and QueueSize bound the background sends (Mailer.SendAsync):
	// how many run at once, and how many may wait. Zero means 4 and 256.
	// The workers start with the first background send.
	Workers   int
	QueueSize int

	// SendTimeout is how long one background send may take. Zero means 30
	// seconds. A send the caller waits for (Mailer.Send) runs under the
	// caller's context instead.
	SendTimeout time.Duration
}

// Mailer is how a plugin sends a message. It is the application's
// MailSender behind two ways of calling it, and the plugin picks one per
// operation:
//
//   - Send waits for the sender and returns its error. Use it when the
//     caller acts on a failure, as a magic link request does by revoking
//     the link that was not sent.
//   - SendAsync returns at once and sends in the background. Use it when a
//     failed send costs nothing but a retry by the user, as an email
//     verification does: the request is not held up by the mail provider.
//
// AuthContext.Mailer is never nil on an AuthContext Boot returns.
type Mailer interface {
	// Configured reports whether a sender was given. A plugin that can't
	// work without one checks it in Init.
	Configured() bool

	// Send calls the sender and waits for it.
	Send(ctx context.Context, msg MailMessage) error

	// SendAsync queues msg and returns. The send runs on a background
	// worker, detached from ctx's cancellation: the request may be over by
	// then. A failed send is logged and counted, and nobody is told. The
	// returned error says the message was not queued: no sender, a full
	// queue, or a mailer that was closed.
	//
	// The queue is in memory. A message waiting in it is lost when the
	// process stops without Close.
	SendAsync(ctx context.Context, msg MailMessage) error

	// Close stops accepting background sends and waits for the queued ones
	// to finish, or for ctx to end. The application calls it at shutdown.
	Close(ctx context.Context) error
}
