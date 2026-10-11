package types

import (
	"context"
	"time"

	"github.com/MastewalB/behemoth"
	"github.com/MastewalB/behemoth/models"
)

// SMSKind says what a text message is for, so that the application's sender
// can pick its wording. A plugin that sends a message of its own defines its
// own kind.
type SMSKind string

const (
	// SMSPhoneVerification carries the code that confirms a number a user
	// is adding to their account (plugins/phonenumber).
	SMSPhoneVerification SMSKind = "phone_verification"
	// SMSSignIn carries the code that signs a user in (plugins/phonenumber).
	SMSSignIn SMSKind = "sign_in"
	// SMSPasswordReset carries the code that lets a user set a new password
	// (plugins/phonenumber).
	SMSPasswordReset SMSKind = "password_reset"
)

// SMSMessage is one text message a plugin wants delivered: everything the
// application's sender needs to write it. Behemoth composes no text. It is
// to SMSSender what MailMessage is to MailSender, with a code where a mail
// has a link.
type SMSMessage struct {
	Kind SMSKind
	// To is the number to send to, in E.164 form ("+14155550123").
	To string
	// Code is the one-time code to put in the message. It is a credential:
	// do not log it.
	Code string
	// ExpiresAt is when the code stops working.
	ExpiresAt time.Time
	// User is the account the message is about.
	User *models.User
	// Metadata is whatever the request carried for the sender: a locale.
	// Plugins pass it through without reading or storing it. From a route
	// it is client input, so treat it as untrusted.
	Metadata behemoth.M
}

// SMSSender delivers a text message: through a provider's API, onto the
// application's own queue. The application implements it and passes it in
// SMSConfig; behemoth sends nothing itself. The provider's credentials are
// the sender's own and are not part of SMSConfig. Send returns once the
// message is delivered or handed off, and an error when it was not.
type SMSSender interface {
	Send(ctx context.Context, msg SMSMessage) error
}

// SMSSenderFunc adapts a function to an SMSSender.
type SMSSenderFunc func(ctx context.Context, msg SMSMessage) error

// Send implements [SMSSender].
func (f SMSSenderFunc) Send(ctx context.Context, msg SMSMessage) error { return f(ctx, msg) }

// SMSConfig configures AuthContext.SMS. Its fields mean what MailConfig's
// do.
type SMSConfig struct {
	// Sender delivers the messages. nil = no sender: SMS.Configured reports
	// false, and a plugin that has to send fails Boot.
	Sender SMSSender

	// Workers and QueueSize bound the background sends (SMS.SendAsync).
	// Zero means 4 and 256.
	Workers   int
	QueueSize int

	// SendTimeout is how long one background send may take. Zero means 30
	// seconds.
	SendTimeout time.Duration
}

// SMS is how a plugin sends a text message. Like Mailer it is the
// application's sender behind two ways of calling it: Send waits and returns
// the sender's error, SendAsync queues the message and returns. A plugin
// that must not show the provider's latency in its response time uses
// SendAsync.
//
// AuthContext.SMS is never nil on an AuthContext Boot returns.
type SMS interface {
	// Configured reports whether a sender was given.
	Configured() bool
	// Send calls the sender and waits for it.
	Send(ctx context.Context, msg SMSMessage) error
	// SendAsync queues msg and returns. A failed send is logged and counted.
	// The returned error says the message was not queued. The queue is in
	// memory, as the mailer's is.
	SendAsync(ctx context.Context, msg SMSMessage) error
	// Close stops accepting background sends and waits for the queued ones
	// to finish, or for ctx to end. The application calls it at shutdown.
	Close(ctx context.Context) error
}
