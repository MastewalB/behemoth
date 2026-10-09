package types

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/MastewalB/behemoth"
	behemotherr "github.com/MastewalB/behemoth/errors"
	"github.com/MastewalB/behemoth/telemetry"
	"github.com/MastewalB/behemoth/types"
)

// Defaults of types.MailConfig.
const (
	defaultMailWorkers     = 4
	defaultMailQueueSize   = 256
	defaultMailSendTimeout = 30 * time.Second
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
// The pool is a convenience, not a job queue. It has no retry and its queue
// is in memory. An application with a queue of its own gives a sender that
// enqueues, and both Send and SendAsync then return quickly.
type DefaultMailer struct {
	sender  types.MailSender
	tel     *telemetry.Telemetry
	workers int
	timeout time.Duration

	mu      sync.Mutex
	queue   chan queuedMail
	started bool
	closed  bool
	wg      sync.WaitGroup
}

type queuedMail struct {
	ctx context.Context
	msg types.MailMessage
}

// NewMailer returns the mailer for cfg. tel may be nil.
func NewMailer(cfg types.MailConfig, tel *telemetry.Telemetry) *DefaultMailer {
	if cfg.Workers <= 0 {
		cfg.Workers = defaultMailWorkers
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultMailQueueSize
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = defaultMailSendTimeout
	}
	return &DefaultMailer{
		sender:  cfg.Sender,
		tel:     telemetry.OrDefault(tel).Named("mail"),
		workers: cfg.Workers,
		timeout: cfg.SendTimeout,
		queue:   make(chan queuedMail, cfg.QueueSize),
	}
}

// Configured implements [types.Mailer].
func (m *DefaultMailer) Configured() bool { return m.sender != nil }

// Send implements [types.Mailer].
func (m *DefaultMailer) Send(ctx context.Context, msg types.MailMessage) error {
	if m.sender == nil {
		return errNoMailSender("Mailer.Send")
	}
	err := m.sender.Send(ctx, msg)
	m.count(ctx, msg.Kind, err)
	return err
}

// SendAsync implements [types.Mailer].
func (m *DefaultMailer) SendAsync(ctx context.Context, msg types.MailMessage) error {
	if m.sender == nil {
		return errNoMailSender("Mailer.SendAsync")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrMailerClosed
	}
	// The send outlives the request, so it keeps the context's values (the
	// request ID its log lines carry) and drops its cancellation.
	select {
	case m.queue <- queuedMail{ctx: context.WithoutCancel(ctx), msg: msg}:
	default:
		m.countResult(ctx, msg.Kind, "dropped")
		return ErrMailQueueFull
	}
	if !m.started {
		m.started = true
		m.wg.Add(m.workers)
		for range m.workers {
			go m.work()
		}
	}
	return nil
}

func (m *DefaultMailer) work() {
	defer m.wg.Done()
	for q := range m.queue {
		m.sendQueued(q)
	}
}

// sendQueued runs one background send. Its failure, or its panic, is logged
// here because no caller is left to return it to.
func (m *DefaultMailer) sendQueued(q queuedMail) {
	ctx, cancel := context.WithTimeout(q.ctx, m.timeout)
	defer cancel()
	var err error
	defer func() {
		if r := recover(); r != nil {
			err = behemotherr.NewInternalError("Mailer.SendAsync", errors.New("the mail sender panicked"))
		}
		m.count(ctx, q.msg.Kind, err)
		if err != nil {
			// The address is left out: it is personal data, and the kind
			// and the error are what an operator needs.
			m.tel.Logger.Error(ctx, "background mail was not sent", telemetry.ErrorFields(err, behemoth.M{"kind": string(q.msg.Kind)}))
		}
	}()
	err = m.sender.Send(ctx, q.msg)
}

// Close implements [types.Mailer].
func (m *DefaultMailer) Close(ctx context.Context) error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.queue)
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *DefaultMailer) count(ctx context.Context, kind types.MailKind, err error) {
	result := "sent"
	if err != nil {
		result = "error"
	}
	m.countResult(ctx, kind, result)
}

// countResult counts one message: "sent", "error" when the sender failed,
// or "dropped" when the background queue was full.
func (m *DefaultMailer) countResult(ctx context.Context, kind types.MailKind, result string) {
	if m.tel.MetricsEnabled() {
		m.tel.Count(ctx, telemetry.MetricMailSent, behemoth.M{telemetry.AttrKind: string(kind), telemetry.AttrResult: result})
	}
}

func errNoMailSender(op string) error {
	return behemotherr.NewConfigurationError(op, "no mail sender is configured; set BootConfig.Mail.Sender", nil)
}

var _ types.Mailer = (*DefaultMailer)(nil)
