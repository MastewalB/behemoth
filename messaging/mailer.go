// Package messaging sends the messages plugins produce: mail through the
// application's MailSender, and text messages through its SMSSender, each
// with a background queue for the sends a flow doesn't wait for.
package messaging

import (
	"errors"

	"github.com/MastewalB/behemoth/errs"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
)

// ErrMailQueueFull is returned by Mailer.SendAsync when MailConfig.QueueSize
// messages are already waiting. The message was not queued.
var ErrMailQueueFull = errors.New("mailer: the background queue is full")

// ErrMailerClosed is returned by Mailer.SendAsync after Close.
var ErrMailerClosed = errors.New("mailer: closed")

// DefaultMailer is the types.Mailer Boot puts on the AuthContext: the
// application's MailSender, called directly by Send and from a bounded
// worker pool by SendAsync. It is to messages what the dispatcher is to
// hooks: plugins call it and never see the sender behind it.
//
// Its methods are sendQueue's, which DefaultSMS shares.
type DefaultMailer struct {
	*sendQueue[types.MailMessage]
}

// NewMailer returns the mailer for cfg. tel may be nil.
func NewMailer(cfg types.MailConfig, tel *telemetry.Telemetry) *DefaultMailer {
	q := &sendQueue[types.MailMessage]{
		channel: "mail",
		kind:    func(msg types.MailMessage) string { return string(msg.Kind) },
		metric:  telemetry.MetricMailSent,
		errNoSender: func(op string) error {
			return errs.NewConfigurationError("Mailer."+op, "no mail sender is configured; set BootConfig.Mail.Sender", nil)
		},
		errFull:   ErrMailQueueFull,
		errClosed: ErrMailerClosed,
		tel:       telemetry.OrDefault(tel).Named("mail"),
	}
	if cfg.Sender != nil {
		q.send = cfg.Sender.Send
	}
	q.init(cfg.Workers, cfg.QueueSize, cfg.SendTimeout)
	return &DefaultMailer{q}
}

var _ types.Mailer = (*DefaultMailer)(nil)
