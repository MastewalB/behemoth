package types

import (
	"errors"

	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
)

// ErrSMSQueueFull is returned by SMS.SendAsync when SMSConfig.QueueSize
// messages are already waiting. The message was not queued.
var ErrSMSQueueFull = errors.New("sms: the background queue is full")

// ErrSMSClosed is returned by SMS.SendAsync after Close.
var ErrSMSClosed = errors.New("sms: closed")

// DefaultSMS is the types.SMS Boot puts on the AuthContext: the
// application's SMSSender behind Send and SendAsync. It is DefaultMailer for
// text messages, and shares its queue and workers code (sendQueue). The two
// have separate queues: a slow mail provider does not hold up a code.
type DefaultSMS struct {
	*sendQueue[types.SMSMessage]
}

// NewSMS returns the SMS sender for cfg. tel may be nil.
func NewSMS(cfg types.SMSConfig, tel *telemetry.Telemetry) *DefaultSMS {
	q := &sendQueue[types.SMSMessage]{
		channel: "SMS",
		kind:    func(msg types.SMSMessage) string { return string(msg.Kind) },
		metric:  telemetry.MetricSMSSent,
		errNoSender: func(op string) error {
			return behemotherr.NewConfigurationError("SMS."+op, "no SMS sender is configured; set BootConfig.SMS.Sender", nil)
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

var _ types.SMS = (*DefaultSMS)(nil)
