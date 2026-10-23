package messaging

import (
	"errors"

	"github.com/go-behemoth/behemoth/core"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/telemetry"
)

// ErrSMSQueueFull is returned by SMS.SendAsync when SMSConfig.QueueSize
// messages are already waiting. The message was not queued.
var ErrSMSQueueFull = errors.New("sms: the background queue is full")

// ErrSMSClosed is returned by SMS.SendAsync after Close.
var ErrSMSClosed = errors.New("sms: closed")

// DefaultSMS is the core.SMS Boot puts on the AuthContext: the
// application's SMSSender behind Send and SendAsync. It is DefaultMailer for
// text messages, and shares its queue and workers code (sendQueue). The two
// have separate queues: a slow mail provider does not hold up a code.
type DefaultSMS struct {
	*sendQueue[core.SMSMessage]
}

// NewSMS returns the SMS sender for cfg. tel may be nil.
func NewSMS(cfg core.SMSConfig, tel *telemetry.Telemetry) *DefaultSMS {
	q := &sendQueue[core.SMSMessage]{
		channel: "SMS",
		kind:    func(msg core.SMSMessage) string { return string(msg.Kind) },
		metric:  telemetry.MetricSMSSent,
		errNoSender: func(op string) error {
			return errs.NewConfigurationError("SMS."+op, "no SMS sender is configured; set BootConfig.SMS.Sender", nil)
		},
		errFull:   ErrSMSQueueFull,
		errClosed: ErrSMSClosed,
		tel:       telemetry.OrDefault(tel).Named("sms"),
	}
	if cfg.Sender != nil {
		q.send = cfg.Sender.Send
	}
	q.init(cfg.Workers, cfg.QueueSize, cfg.SendTimeout)
	return &DefaultSMS{q}
}

var _ core.SMS = (*DefaultSMS)(nil)
