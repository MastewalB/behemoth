package telemetry

import (
	"context"

	"github.com/MastewalB/behemoth"
)

// Logger is the logging interface behemoth and its plugins write to. It is
// small so that any logging library can stand behind it; NewSlogLogger
// adapts log/slog, and through slog handlers, zap and zerolog.
//
// fields may be nil. Keys shared across components are the Field constants.
//
//	logger.Warn(ctx, "session cache write failed", telemetry.ErrorFields(err))
type Logger interface {
	Debug(ctx context.Context, msg string, fields behemoth.M)
	Info(ctx context.Context, msg string, fields behemoth.M)
	Warn(ctx context.Context, msg string, fields behemoth.M)
	Error(ctx context.Context, msg string, fields behemoth.M)
}

// NoOpLogger discards every line. New uses it when no logger is given.
type NoOpLogger struct{}

func (NoOpLogger) Debug(context.Context, string, behemoth.M) {}
func (NoOpLogger) Info(context.Context, string, behemoth.M)  {}
func (NoOpLogger) Warn(context.Context, string, behemoth.M)  {}
func (NoOpLogger) Error(context.Context, string, behemoth.M) {}

// Named returns a Logger that adds FieldComponent to every line, so a
// deployment's logs can be filtered down to one component:
//
//	log := telemetry.Named(tel.Logger, "session")
//
// A line that sets FieldComponent itself keeps its own value.
func Named(logger Logger, component string) Logger {
	switch logger.(type) {
	case nil, NoOpLogger:
		return NoOpLogger{}
	}
	return &namedLogger{inner: logger, component: component}
}

type namedLogger struct {
	inner     Logger
	component string
}

func (l *namedLogger) with(fields behemoth.M) behemoth.M {
	out := make(behemoth.M, len(fields)+1)
	out[FieldComponent] = l.component
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func (l *namedLogger) Debug(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Debug(ctx, msg, l.with(fields))
}
func (l *namedLogger) Info(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Info(ctx, msg, l.with(fields))
}
func (l *namedLogger) Warn(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Warn(ctx, msg, l.with(fields))
}
func (l *namedLogger) Error(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Error(ctx, msg, l.with(fields))
}

// guardedLogger is the wrapper New puts around the application's logger. It
// is the one place redaction and request correlation happen, so a backend
// never sees an unredacted field and no call site adds the request ID.
type guardedLogger struct {
	inner    Logger
	redactor redactor
}

// guard wraps logger once. A nil or no-op logger stays a no-op.
func guard(logger Logger, r redactor) Logger {
	switch l := logger.(type) {
	case nil, NoOpLogger:
		return NoOpLogger{}
	case *guardedLogger:
		return l
	case *namedLogger:
		// A named logger over a guarded one (Telemetry.Named) is guarded
		// already.
		if _, ok := l.inner.(*guardedLogger); ok {
			return l
		}
	}
	return &guardedLogger{inner: logger, redactor: r}
}

// prepare returns the fields the backend receives: a redacted copy, plus the
// context's request ID unless the line already has one.
func (l *guardedLogger) prepare(ctx context.Context, fields behemoth.M) behemoth.M {
	out := l.redactor.redact(fields)
	if id := RequestIDFrom(ctx); id != "" {
		if out == nil {
			out = behemoth.M{}
		}
		if _, set := out[FieldRequestID]; !set {
			out[FieldRequestID] = id
		}
	}
	return out
}

func (l *guardedLogger) Debug(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Debug(ctx, msg, l.prepare(ctx, fields))
}
func (l *guardedLogger) Info(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Info(ctx, msg, l.prepare(ctx, fields))
}
func (l *guardedLogger) Warn(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Warn(ctx, msg, l.prepare(ctx, fields))
}
func (l *guardedLogger) Error(ctx context.Context, msg string, fields behemoth.M) {
	l.inner.Error(ctx, msg, l.prepare(ctx, fields))
}
