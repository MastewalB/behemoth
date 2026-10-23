package messaging

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-behemoth/behemoth"
	"github.com/go-behemoth/behemoth/errs"
	"github.com/go-behemoth/behemoth/telemetry"
)

// Defaults of the background sends, for mail and for SMS.
const (
	defaultSendWorkers   = 4
	defaultSendQueueSize = 256
	defaultSendTimeout   = 30 * time.Second
)

// sendQueue is what DefaultMailer and DefaultSMS share: the application's
// sender for messages of type M, called directly by Send and from a bounded
// worker pool by SendAsync.
//
// The pool is a convenience, not a job queue. It has no retry and its queue
// is in memory. An application with a queue of its own gives a sender that
// enqueues, and both Send and SendAsync then return quickly.
type sendQueue[M any] struct {
	// channel names what is sent, for messages and errors: "mail", "SMS".
	channel string
	// send is the application's sender, or nil when none was given.
	send func(ctx context.Context, msg M) error
	// kind labels a message in metrics and logs. The address is never used:
	// it is personal data.
	kind   func(msg M) string
	metric string
	// errNoSender, errFull and errClosed are the channel's errors.
	errNoSender        func(op string) error
	errFull, errClosed error

	tel     *telemetry.Telemetry
	workers int
	timeout time.Duration

	mu      sync.Mutex
	queue   chan queuedMessage[M]
	started bool
	closed  bool
	wg      sync.WaitGroup
}

type queuedMessage[M any] struct {
	ctx context.Context
	msg M
}

// init sets the pool's bounds, with the defaults for values left at zero.
func (q *sendQueue[M]) init(workers, queueSize int, timeout time.Duration) {
	if workers <= 0 {
		workers = defaultSendWorkers
	}
	if queueSize <= 0 {
		queueSize = defaultSendQueueSize
	}
	if timeout <= 0 {
		timeout = defaultSendTimeout
	}
	q.workers, q.timeout = workers, timeout
	q.queue = make(chan queuedMessage[M], queueSize)
}

// Configured reports whether a sender was given.
func (q *sendQueue[M]) Configured() bool { return q.send != nil }

// Send calls the sender and waits for it.
func (q *sendQueue[M]) Send(ctx context.Context, msg M) error {
	if q.send == nil {
		return q.errNoSender("Send")
	}
	err := q.send(ctx, msg)
	q.count(ctx, msg, err)
	return err
}

// SendAsync queues msg and returns. The workers start with the first call.
func (q *sendQueue[M]) SendAsync(ctx context.Context, msg M) error {
	if q.send == nil {
		return q.errNoSender("SendAsync")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return q.errClosed
	}
	// The send outlives the request, so it keeps the context's values (the
	// request ID its log lines carry) and drops its cancellation.
	select {
	case q.queue <- queuedMessage[M]{ctx: context.WithoutCancel(ctx), msg: msg}:
	default:
		q.countResult(ctx, msg, "dropped")
		return q.errFull
	}
	if !q.started {
		q.started = true
		q.wg.Add(q.workers)
		for range q.workers {
			go q.work()
		}
	}
	return nil
}

func (q *sendQueue[M]) work() {
	defer q.wg.Done()
	for queued := range q.queue {
		q.sendQueued(queued)
	}
}

// sendQueued runs one background send. Its failure, or its panic, is logged
// here because no caller is left to return it to.
func (q *sendQueue[M]) sendQueued(queued queuedMessage[M]) {
	ctx, cancel := context.WithTimeout(queued.ctx, q.timeout)
	defer cancel()
	var err error
	defer func() {
		if r := recover(); r != nil {
			err = errs.NewInternalError("SendAsync", errors.New("the "+q.channel+" sender panicked"))
		}
		q.count(ctx, queued.msg, err)
		if err != nil {
			// The address is left out: it is personal data, and the kind
			// and the error are what an operator needs.
			q.tel.Logger.Error(ctx, "background "+q.channel+" was not sent", telemetry.ErrorFields(err, behemoth.M{"kind": q.kind(queued.msg)}))
		}
	}()
	err = q.send(ctx, queued.msg)
}

// Close stops accepting background sends and waits for the queued ones to
// finish, or for ctx to end.
func (q *sendQueue[M]) Close(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.queue)
	}
	q.mu.Unlock()

	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *sendQueue[M]) count(ctx context.Context, msg M, err error) {
	result := "sent"
	if err != nil {
		result = "error"
	}
	q.countResult(ctx, msg, result)
}

// countResult counts one message: "sent", "error" when the sender failed,
// or "dropped" when the background queue was full.
func (q *sendQueue[M]) countResult(ctx context.Context, msg M, result string) {
	if q.tel.MetricsEnabled() {
		q.tel.Count(ctx, q.metric, behemoth.M{telemetry.AttrKind: q.kind(msg), telemetry.AttrResult: result})
	}
}
